//! 同步引擎 —— 把服务器上的信搬进本地库
//!
//! 这一层回答「什么时候同步、同步哪些、写进哪个表」。协议原语在
//! [`crate::imap`]，解析在 [`crate::mime`]，落盘在 [`crate::store`]。
//!
//! 四条硬规矩：
//!
//! 1. **UIDVALIDITY 一变就整箱重建。**RFC 3501 规定 UID 只在同一个
//!    UIDVALIDITY 下唯一，继续用旧的本地映射会张冠李戴。这不是优化问题，
//!    是正确性问题。
//! 2. **取原文用 `BODY.PEEK[]`。**收信不该顺手把信标成已读 ——「收到」和
//!    「读了」是两件事，已读由 UI 决定。
//! 3. **一封坏信不能卡住整个文件夹。**解析失败的照样入库占位，原文也留着，
//!    好让以后修好解析器能重新算一遍。
//! 4. **`n:*` 会把最后一封也带回来。**RFC 3501：`n:*` 总包含信箱里最后一封，
//!    哪怕 `n` 比最大 UID 还大。所以拿到之后必须再按 uid 过一遍，否则每次
//!    同步都会把最后一封重算一次。

use chrono::Utc;

use crate::error::Result;
use crate::imap::{Conn, FetchedFull, RemoteFolder};
use crate::mime;
use crate::rules::{self, MailText, Rule};
use crate::sanitize;
use crate::store::{NewFolder, NewMessage, Store};
use crate::types::{Flags, Folder, FolderKind};

// ================================================================= 结果

/// 一次文件夹同步的结果。给 UI 显示「收信收了几封」用。
#[derive(Debug, Clone, Default)]
pub struct FolderSync {
    pub folder_id: i64,
    pub imap_name: String,
    /// UIDVALIDITY 变了，本地数据被清空重建过
    pub rebuilt: bool,
    /// 新入库的信
    pub fetched: u32,
    /// 解析失败但仍然占位入库的信
    pub broken: u32,
    /// 被来信分类挪去别的文件夹的信（不在本箱，也不在 `fetched` 里）
    pub moved: u32,
    /// 本次顺带刷新了标志的信
    pub flags_changed: u32,
    /// 同步后服务器上的信总数
    pub total: u32,
}

// ================================================================= 引擎

/// 同步引擎。`store` 是它唯一的落库出口。
pub struct SyncEngine<'s> {
    store: &'s Store,
}

impl<'s> SyncEngine<'s> {
    pub fn new(store: &'s Store) -> Self {
        SyncEngine { store }
    }

    /// 同步一个文件夹：收新信 + 刷标志。
    ///
    /// 只拉**新增 UID** 的全文，不重拉整箱 —— 一封带 20 MB 附件的信不该
    /// 每次同步都重下一遍。已有邮件的标志用 [`Self::refresh_flags`] 单独刷。
    ///
    /// `folder` 只用来认是哪个文件夹（`id` / `imap_name`）；**同步状态一律
    /// 从库里重新读**。调用方手里那份 `Folder` 多半是早就拿到的快照，拿它的
    /// `last_synced_uid` 算增量会把已经收过的信再收一遍 —— 这个坑踩过一次。
    pub fn sync_folder(
        &self,
        conn: &mut Conn,
        account_id: i64,
        folder: &Folder,
    ) -> Result<FolderSync> {
        let folder = self.store.get_folder(folder.id)?.ok_or_else(|| {
            crate::error::Error::Other(anyhow::anyhow!("文件夹 {} 已不在库里", folder.id))
        })?;

        let status = conn.select(&folder.imap_name)?;

        // ---- 1. UIDVALIDITY -------------------------------------------
        let rebuilt = match folder.uid_validity {
            Some(old) if old != status.uid_validity => {
                tracing::warn!(
                    folder = %folder.imap_name,
                    old,
                    new = status.uid_validity,
                    "UIDVALIDITY 变了，清空本地重建（RFC 3501 硬约束）"
                );
                self.store.purge_folder_messages(folder.id)?;
                true
            }
            _ => false,
        };

        let after = if rebuilt { 0 } else { folder.last_synced_uid.unwrap_or(0) };
        let mut out = FolderSync {
            folder_id: folder.id,
            imap_name: folder.imap_name.clone(),
            rebuilt,
            total: status.total,
            ..FolderSync::default()
        };

        // ---- 2. 新信 ---------------------------------------------------
        // 见模块头第 4 条：`after+1:*` 会把最后一封也带回来，下面按 uid 过滤。
        //
        // 来信分类的规则**只在收件箱上跑**（理由见 `rules` 模块的头注释）：
        // 别的箱子是服务器或用户已经分好的，再分一遍只会搅乱。
        let rules: Vec<Rule> = if folder.kind == FolderKind::Inbox {
            self.store.list_rules(account_id)?
        } else {
            Vec::new()
        };
        let full = conn.uid_fetch_full(&format!("{}:*", after + 1))?;
        let mut max_uid = after;
        let mut moved_targets: Vec<i64> = Vec::new();
        for f in &full {
            if f.uid <= after {
                // `n:*` 会把信箱里最大的那封再发一遍（RFC 3501 §6.4.8），
                // 哪怕它的 uid 在水位线之下。本地有**同一封信**（按
                // Message-ID 认）的只刷标志；本地没有、或者 uid 一样信却不
                // 一样（服务器丢了状态又没换 UIDVALIDITY —— 假服务器重启就是
                // 这个样子）的都当新信落库。规则挪进箱子的信就落在这个缝里，
                // 跳过它「挪走的信」就永远接不回来。
                if let Some(existing) = self.store.get_message_by_uid(folder.id, f.uid)? {
                    let same_mail = match mime::parse_message(&f.raw) {
                        Ok(p) => existing.summary.message_id == p.message_id.unwrap_or_default(),
                        // 认不出就当是同一封 —— 坏信的占位行别每轮重落一遍
                        Err(_) => true,
                    };
                    if same_mail {
                        if existing.summary.flags != f.flags {
                            self.store.set_message_flags(existing.summary.id, &f.flags)?;
                            out.flags_changed += 1;
                        }
                        continue;
                    }
                }
            }
            match self.ingest(conn, account_id, &folder, f, &rules)? {
                Ingested::Ok => out.fetched += 1,
                Ingested::Broken => {
                    out.broken += 1;
                    out.fetched += 1;
                }
                Ingested::Moved { target } => {
                    out.moved += 1;
                    moved_targets.push(target);
                }
            }
            max_uid = max_uid.max(f.uid);
        }

        // ---- 3. 记同步状态 ---------------------------------------------
        self.store.record_folder_sync_state(
            folder.id,
            status.uid_validity,
            Some(status.uid_next),
            Some(max_uid).filter(|u| *u > 0),
        )?;

        // ---- 4. 分类挪走的信去目标箱子接回来 ---------------------------
        // MOVE 之后信在目标信箱里，本地还没有 —— 立刻把目标箱子同步一遍，
        // 「老板的信自动进『老板』箱」当场就看得见，不用等下一轮。
        // 目标箱子不会是收件箱（ingest 拒绝往 INBOX 挪），所以这层递归
        // 不会再跑规则，不会转圈。
        moved_targets.sort_unstable();
        moved_targets.dedup();
        for tid in moved_targets {
            match self.store.get_folder(tid)? {
                Some(target) => {
                    // 接不回来别把整次同步打成失败 —— 收件箱那头已经是对的
                    if let Err(e) = self.sync_folder(conn, account_id, &target) {
                        tracing::warn!(folder_id = tid, "挪过去的信暂时收不回来: {}", e.user_message());
                    }
                }
                None => {
                    tracing::warn!(folder_id = tid, "规则挪去的文件夹已不在库里，信在服务器上");
                }
            }
        }

        Ok(out)
    }

    /// 刷新一个文件夹里已有邮件的标志（**不取正文**）。
    ///
    /// 「在手机上标了已读、电脑上看还是未读」就靠这个。全文拉一遍只为改个
    /// 标志是几百 KB 的浪费，所以走 `UID FLAGS`。
    ///
    /// 不记录 `last_synced_uid` —— 这只是刷标志，没收到新信。
    pub fn refresh_flags(&self, conn: &mut Conn, folder: &Folder) -> Result<u32> {
        conn.select(&folder.imap_name)?;
        let mut changed = 0;
        for (uid, flags) in conn.uid_fetch_flags("1:*")? {
            if self.store_has_different_flags(folder.id, uid, &flags)? {
                changed += 1;
            }
        }
        Ok(changed)
    }

    /// 同步一个账号下所有**可选**的文件夹。
    ///
    /// `\NoSelect` 的跳过 —— 那是层级容器，SELECT 会被服务器拒绝。
    /// 本地没有的文件夹先建出来，所以「服务器上新建了文件夹」会自动出现在侧栏。
    pub fn sync_account(&self, conn: &mut Conn, account_id: i64) -> Result<Vec<FolderSync>> {
        // 第一趟：LIST 把文件夹行**全部建齐** —— 目录树立刻就是全的。
        // Gmail 一个箱几千封，逐箱「建了就同步」会让剩下的目录迟到半小时。
        let mut folders = Vec::new();
        for remote in conn.list_folders()? {
            if remote.noselect() {
                continue;
            }
            folders.push(self.ensure_folder(account_id, &remote)?);
        }
        // 第二趟：逐箱收信。
        let mut out = Vec::new();
        for folder in folders {
            out.push(self.sync_folder(conn, account_id, &folder)?);
        }
        Ok(out)
    }

    /// 只对齐文件夹清单，不收信。建/改名/删文件夹之后拿它把本地清单对上。
    ///
    /// **只增改，不删**：服务器上少了的文件夹这里不动 ——「少了」有两种可能
    /// （我们刚删的、别人在别处删的），前者由 [`crate::store::Store::delete_folder`]
    /// 收尾，后者的发现是同步的事，不该藏在一个「刷清单」的函数里悄悄干掉
    /// 一箱子缓存信。`\NoSelect` 跳过的理由同 [`Self::sync_account`]。
    /// 同步一个 POP3 账号：只收收件箱，按 **UIDL** 增量去重。
    ///
    /// POP3 没有服务器端文件夹和标志，所以没有「刷标志」那半边；来信分类
    /// 挪箱是**本地**的（信直接落到目标箱），不碰服务器（也没有可碰的）。
    /// 只拉不删：`RETR` 过的信保留在服务器上。
    pub fn sync_pop3(
        &self,
        pop: &mut crate::pop3::Conn,
        account_id: i64,
    ) -> Result<FolderSync> {
        let folder = self.store.ensure_inbox_folder(account_id)?;
        let (total, _octets) = pop.stat()?;
        let mut out = FolderSync {
            folder_id: folder.id,
            imap_name: folder.imap_name.clone(),
            total,
            ..FolderSync::default()
        };
        let rules: Vec<Rule> = self.store.list_rules(account_id)?;
        for (seq, uidl) in pop.uidl_all()? {
            // UIDL 去重（账号范围）：收过的信不再下正文 —— 被规则/用户挪到
            // 别的箱的信也算收过，不能下两遍。
            if self
                .store
                .get_message_uidl_account(account_id, &uidl)?
                .is_some()
            {
                continue;
            }
            match pop.retrieve(seq) {
                Ok(raw) => match self.ingest_pop3(account_id, &folder, &uidl, &raw, &rules)? {
                    Ingested::Ok => out.fetched += 1,
                    Ingested::Broken => {
                        out.broken += 1;
                        out.fetched += 1;
                    }
                    Ingested::Moved { .. } => {
                        // 信确实下载了（落在目标箱），收信数和挪箱数都得算
                        out.fetched += 1;
                        out.moved += 1;
                    }
                },
                Err(e) => {
                    // 一封取不下不该让整次同步失败 —— 下轮再试
                    tracing::warn!(seq, uidl = %uidl, "RETR 失败，跳过: {e}");
                    out.broken += 1;
                }
            }
        }
        pop.quit().ok();
        Ok(out)
    }

    pub fn refresh_folders(&self, conn: &mut Conn, account_id: i64) -> Result<Vec<Folder>> {
        let mut out = Vec::new();
        for remote in conn.list_folders()? {
            if remote.noselect() {
                continue;
            }
            out.push(self.ensure_folder(account_id, &remote)?);
        }
        Ok(out)
    }

    /// 建文件夹。名字是人看的（`Conn` 负责编 modified UTF-7）。
    ///
    /// 落库靠 LIST 回读而不是 CREATE 的响应 —— 那个响应里只有一个 OK，
    /// 分隔符、属性这些得 LIST 才有。返回**本地那一行**，前端拿它的 id
    /// 直接切过去。
    pub fn create_folder(&self, conn: &mut Conn, account_id: i64, name: &str) -> Result<Folder> {
        conn.create_folder(name)?;
        self.refresh_folders(conn, account_id)?
            .into_iter()
            .find(|f| f.display_name == name)
            .ok_or_else(|| {
                crate::error::Error::Other(anyhow::anyhow!(
                    "服务器说 {name:?} 建好了，LIST 里却找不到它"
                ))
            })
    }

    /// 改文件夹名。**先服务器、后本地**：反过来断在中间，下趟 LIST 会把
    /// 新名当新箱子插一行，旧的那行还指着旧名，一个箱子裂成两个。
    /// 本地 `messages` 不用动 —— 换的是箱子名，箱子 id 没变。
    pub fn rename_folder(
        &self,
        conn: &mut Conn,
        folder: &Folder,
        new_name: &str,
    ) -> Result<()> {
        conn.rename_folder(&folder.display_name, new_name)?;
        self.store
            .rename_folder(folder.id, &crate::imap::utf7::encode(new_name), new_name)
    }

    /// 删文件夹。先服务器、后本地，理由同 [`Self::rename_folder`]。
    /// 本地是级联删（`messages.folder_id` 是 `ON DELETE CASCADE`）——
    /// 服务器上箱子没了，缓存的信留着也只是幽灵。
    pub fn delete_folder(&self, conn: &mut Conn, folder: &Folder) -> Result<()> {
        conn.delete_folder(&folder.display_name)?;
        self.store.delete_folder(folder.id)
    }

    /// 把本地标志推回服务器。UI 改了已读/星标之后调用。
    ///
    /// 只推**差异**：`old` 是改之前的状态，`new` 是改之后的。传错了最坏是
    /// 多发几个 FLAGS 命令，不会把状态改错。
    ///
    /// 会先 SELECT 一次 `folder` —— UID 只在**当前选中的箱子**里有意义，
    /// 跳过这一步就是把标志写到别的文件夹去。代价是多一个来回，值得。
    pub fn push_flags(
        &self,
        conn: &mut Conn,
        folder: &Folder,
        uid: u32,
        old: &Flags,
        new: &Flags,
    ) -> Result<()> {
        conn.select(&folder.imap_name)?;

        let mut add: Vec<&str> = Vec::new();
        let mut remove: Vec<&str> = Vec::new();

        // 系统标志。(名字, 改成了什么, 改之前是什么)。顺序无所谓，服务端按集合处理。
        for (name, now_set, was_set) in [
            ("\\Seen", new.seen, old.seen),
            ("\\Answered", new.answered, old.answered),
            ("\\Flagged", new.flagged, old.flagged),
            ("\\Draft", new.draft, old.draft),
            ("\\Deleted", new.deleted, old.deleted),
        ] {
            if now_set == was_set {
                continue;
            }
            if now_set {
                add.push(name);
            } else {
                remove.push(name);
            }
        }

        // 自定义关键词。M1 只做「整体替换」的近似：新增的加、删掉的减。
        for k in new.keywords.iter().filter(|k| !old.keywords.contains(k)) {
            add.push(k.as_str());
        }
        for k in old.keywords.iter().filter(|k| !new.keywords.contains(k)) {
            remove.push(k.as_str());
        }

        if add.is_empty() && remove.is_empty() {
            return Ok(());
        }
        conn.uid_store_flags(&uid.to_string(), &add, &remove)
    }

    /// 一批信一次推成已读（「全标已读」）。
    ///
    /// 和 [`Self::push_flags`] 的分工：那个按封推差异，界面上单封点的；这个
    /// 一条 `UID STORE` 推一串 uid，一个来回的事，别按封循环。
    pub fn push_seen(&self, conn: &mut Conn, folder: &Folder, uids: &[u32]) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        conn.select(&folder.imap_name)?;
        let set = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        conn.uid_store_flags(&set, &["\\Seen"], &[])
    }

    /// 用户从界面上把一封信挪到别的信箱（「删除」= 挪进废纸篓）。
    ///
    /// 和来信分类的挪箱（[`Self::ingest`] 里的 `uid_move`）是同一个原语，
    /// 区别在触发时机：那个跑在收信里、箱子已经选好了；这个是用户随时点
    /// 的，所以自己先 SELECT 源箱 —— UID 只在**当前选中的箱子**里有意义。
    ///
    /// 只管服务器那半边。本地行怎么处理、目标箱什么时候追平，归调用方
    /// （commands 的 `delete_message`）。
    pub fn move_message(
        &self,
        conn: &mut Conn,
        from: &Folder,
        uid: u32,
        to: &Folder,
    ) -> Result<()> {
        conn.select(&from.imap_name)?;
        conn.uid_move(uid, &to.imap_name)
    }

    /// 彻底删除：打 `\Deleted` 再 EXPUNGE（见 [`Conn::uid_expunge`] 的
    /// UIDPLUS 退化）。同样只管服务器那半边。
    pub fn delete_message(&self, conn: &mut Conn, folder: &Folder, uid: u32) -> Result<()> {
        conn.select(&folder.imap_name)?;
        conn.uid_store_flags(&uid.to_string(), &["\\Deleted"], &[])?;
        conn.uid_expunge(&uid.to_string())
    }

    // ------------------------------------------------------------ 内部

    /// 本地这封信的标志和服务器一致吗？不一致就写回去，返回 true。
    fn store_has_different_flags(
        &self,
        folder_id: i64,
        uid: u32,
        flags: &Flags,
    ) -> Result<bool> {
        let Some(existing) = self.store.get_message_by_uid(folder_id, uid)? else {
            return Ok(false); // 本地没有，是新信，由 sync_folder 处理
        };
        if existing.summary.flags == *flags {
            return Ok(false);
        }
        self.store.set_message_flags(existing.summary.id, flags)?;
        Ok(true)
    }

    /// 把一封信落库。返回它怎么处理的 —— 见 [`Ingested`]。
    ///
    /// 来信分类（`rules`）在这里跑：匹配、挪箱、改标志、贴标签。挪箱需要
    /// 连接（IMAP `UID MOVE`），所以 `ingest` 带着 `conn` —— 调用方
    /// （[`Self::sync_folder`] 的收信循环）保证进来时**源信箱还是选中的**。
    fn ingest(
        &self,
        conn: &mut Conn,
        account_id: i64,
        folder: &Folder,
        f: &FetchedFull,
        rules: &[Rule],
    ) -> Result<Ingested> {
        let received_at = f
            .internal_date
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let size = f.size.or(Some(f.raw.len() as u64));

        let parsed = match mime::parse_message(&f.raw) {
            Ok(p) => p,
            Err(e) => {
                // 一封坏信不该让整个文件夹同步失败
                tracing::warn!(uid = f.uid, "解析失败，占位入库: {e}");
                // 原文也留着 —— 将来修好解析器能重算（硬规矩 3）
                let raw_path = self.store.write_raw(account_id, folder.id, f.uid, &f.raw)?;
                self.store.upsert_message(&NewMessage {
                    account_id,
                    folder_id: folder.id,
                    uid: f.uid,
                    message_id: "",
                    subject: "（无法解析的邮件）",
                    from: vec![],
                    to: vec![],
                    date: None,
                    size,
                    flags: f.flags.clone(),
                    has_attachments: false,
                    preview: "",
                    // None = 还没建索引。解析坏了不算「没正文」—— 留着让
                    // reindex_bodies 下趟启动再试，别把搜索这条路堵死。
                    body_text: None,
                    received_at,
                    raw_path: Some(&raw_path),
                })?;
                return Ok(Ingested::Broken);
            }
        };

        let text = parsed.body_text.clone().unwrap_or_default();
        let preview = sanitize::build_preview(&text);

        // ---- 来信分类 -------------------------------------------------
        let from_text = rules::addrs_text(&parsed.from);
        let to_text = rules::addrs_text(&parsed.to);
        let mail_text = MailText {
            from: &from_text,
            to: &to_text,
            subject: &parsed.subject,
            body: &text,
        };
        let applied = rules::apply_all(rules, &mail_text);

        // 规则要改的标志在**入库那一刻**就带上，再推回服务器。只改本地的话，
        // 下一轮 refresh_flags 就把服务器的旧值刷回来 —— 白改。
        let mut flags = f.flags.clone();
        if applied.mark_read {
            flags.seen = true;
        }
        if applied.mark_flagged {
            flags.flagged = true;
        }

        if let Some(target_id) = applied.move_to {
            // 目标得还在库里，而且不能是收件箱/自己：往「来信」里挪没意义，
            // 更要紧的是第 4 步递归同步目标箱子时会再跑一遍规则 —— 那就转圈了。
            let target = self
                .store
                .get_folder(target_id)?
                .filter(|t| t.id != folder.id && t.kind != FolderKind::Inbox);
            if let Some(t) = target {
                // 标志得赶在挪箱**之前**推：MOVE 把服务器上的标志一起带去新
                // 箱子，目标箱子同步时按那个值入库。挪完这个 uid 就没了，
                // 再推找不着人。
                if flags != f.flags {
                    let (add, remove) = flag_delta(&f.flags, &flags);
                    if let Err(e) = conn.uid_store_flags(&f.uid.to_string(), &add, &remove) {
                        tracing::warn!(uid = f.uid, "规则改的标志推不回服务器（信照挪）: {e}");
                    }
                }
                match conn.uid_move(f.uid, &t.imap_name) {
                    Ok(()) => {
                        tracing::info!(uid = f.uid, to = %t.display_name, "来信分类：挪箱");
                        if !applied.labels.is_empty() {
                            // 标签是本地概念，而这封的本地行要等目标箱子同步
                            // 才落地 —— 这里没处贴。丢掉、记一笔（M3 记录有载）。
                            tracing::warn!(
                                uid = f.uid,
                                "挪走的信贴不上本地标签（行还没落地）: {:?}",
                                applied.labels
                            );
                        }
                        // 不落本地行 —— 信不在这箱了。原文也不落：等目标箱子
                        // 同步时按那边的 uid 落（路径按 (箱, uid) 组织）。
                        return Ok(Ingested::Moved { target: t.id });
                    }
                    Err(e) => {
                        // 老服务器不认 RFC 6851 的 MOVE：信留在原箱照常入库，
                        // 什么都不丢，只是这条规则的移动动作没做成
                        tracing::warn!(uid = f.uid, "来信分类挪箱失败，信留在原箱: {e}");
                    }
                }
            } else {
                tracing::warn!(
                    uid = f.uid,
                    folder_id = target_id,
                    "规则指向的文件夹不可用（不存在 / 是收件箱 / 是自己），跳过移动"
                );
            }
        }

        // 原文落盘。挪走的那封在上面就返回了，不会走到这儿 —— 路径按
        // (箱, uid) 组织，落了也是别的箱的名下。
        let raw_path = self.store.write_raw(account_id, folder.id, f.uid, &f.raw)?;

        let id = self.store.upsert_message(&NewMessage {
            account_id,
            folder_id: folder.id,
            uid: f.uid,
            message_id: parsed.message_id.as_deref().unwrap_or(""),
            subject: &parsed.subject,
            from: parsed.from.clone(),
            to: parsed.to.clone(),
            date: parsed.date,
            size,
            flags: flags.clone(),
            has_attachments: parsed.has_attachments(),
            preview: &preview,
            // 正文进搜索索引。preview 是它截断的影子，搜正文得用全份。
            body_text: Some(&text),
            received_at,
            raw_path: Some(&raw_path),
        })?;

        if flags != f.flags {
            let (add, remove) = flag_delta(&f.flags, &flags);
            if let Err(e) = conn.uid_store_flags(&f.uid.to_string(), &add, &remove) {
                // 本地已经是对的；推不回去就等下一轮对齐（和 set_message_flags
                // 那条路一个态度）
                tracing::warn!(uid = f.uid, "规则改的标志推不回服务器: {e}");
            }
        }

        if !applied.labels.is_empty() {
            // 标签纯本地，没有「推回去」那半边（见 rules::Action::AddLabels）
            self.store.set_message_labels(id, &applied.labels)?;
        }

        Ok(Ingested::Ok)
    }

    /// POP3 版入库：解析 + 来信分类 + 落库。和 [`Self::ingest`] 的差别：
    ///
    /// - 没有 `conn` —— 规则挪箱只改本地 `folder_id`（信直接落目标箱），
    ///   不推服务器（POP3 也没有服务器标志/文件夹可推）；
    /// - 标志从空开始（新信未读），规则的标记动作叠上去；
    /// - 身份是 **UIDL**：落库后记到行上，下轮增量去重靠它。
    fn ingest_pop3(
        &self,
        account_id: i64,
        folder: &Folder,
        uidl: &str,
        raw: &[u8],
        rules: &[Rule],
    ) -> Result<Ingested> {
        let received_at = Utc::now();
        let size = Some(raw.len() as u64);

        let parsed = match mime::parse_message(raw) {
            Ok(p) => p,
            Err(e) => {
                // 一封坏信不该让整次同步失败（同 ingest 的态度）
                tracing::warn!(uidl = %uidl, "解析失败，占位入库: {e}");
                let uid = self.store.next_message_uid(folder.id)?;
                let raw_path = self.store.write_raw(account_id, folder.id, uid, raw)?;
                let id = self.store.upsert_message(&NewMessage {
                    account_id,
                    folder_id: folder.id,
                    uid,
                    message_id: "",
                    subject: "（无法解析的邮件）",
                    from: vec![],
                    to: vec![],
                    date: None,
                    size,
                    flags: Flags::default(),
                    has_attachments: false,
                    preview: "",
                    body_text: None,
                    received_at,
                    raw_path: Some(&raw_path),
                })?;
                self.store.set_message_uidl(id, uidl)?;
                return Ok(Ingested::Broken);
            }
        };

        let text = parsed.body_text.clone().unwrap_or_default();
        let preview = sanitize::build_preview(&text);

        // ---- 来信分类（本地） --------------------------------------------
        let from_text = rules::addrs_text(&parsed.from);
        let to_text = rules::addrs_text(&parsed.to);
        let mail_text = MailText {
            from: &from_text,
            to: &to_text,
            subject: &parsed.subject,
            body: &text,
        };
        let applied = rules::apply_all(rules, &mail_text);

        let mut flags = Flags::default();
        if applied.mark_read {
            flags.seen = true;
        }
        if applied.mark_flagged {
            flags.flagged = true;
        }

        // 挪箱 = 选好落脚点再建行（(folder_id, uid) 唯一，uid 按目标箱分配）。
        // 目标不能是收件箱/自己 —— 和 ingest 同一条规矩。
        let mut target = folder.clone();
        if let Some(target_id) = applied.move_to {
            if let Some(t) = self
                .store
                .get_folder(target_id)?
                .filter(|t| t.id != folder.id && t.kind != FolderKind::Inbox)
            {
                tracing::info!(uidl = %uidl, to = %t.display_name, "来信分类：本地挪箱");
                target = t;
            } else {
                tracing::warn!(uidl = %uidl, folder_id = target_id, "规则指向的文件夹不可用，落在收件箱");
            }
        }
        let uid = self.store.next_message_uid(target.id)?;
        let raw_path = self.store.write_raw(account_id, target.id, uid, raw)?;

        let id = self.store.upsert_message(&NewMessage {
            account_id,
            folder_id: target.id,
            uid,
            message_id: parsed.message_id.as_deref().unwrap_or(""),
            subject: &parsed.subject,
            from: parsed.from.clone(),
            to: parsed.to.clone(),
            date: parsed.date,
            size,
            flags: flags.clone(),
            has_attachments: parsed.has_attachments(),
            preview: &preview,
            body_text: Some(&text),
            received_at,
            raw_path: Some(&raw_path),
        })?;
        self.store.set_message_uidl(id, uidl)?;
        if !applied.labels.is_empty() {
            self.store.set_message_labels(id, &applied.labels)?;
        }

        if target.id != folder.id {
            Ok(Ingested::Moved { target: target.id })
        } else {
            Ok(Ingested::Ok)
        }
    }

    /// 本地有就取出来，没有就按 LIST 的响应建一个。
    fn ensure_folder(&self, account_id: i64, remote: &RemoteFolder) -> Result<Folder> {
        let kind = guess_folder_kind(&remote.imap_name, &remote.display_name);
        let id = self.store.upsert_folder(&NewFolder {
            account_id,
            imap_name: &remote.imap_name,
            display_name: &pretty_folder_name(&remote.display_name),
            kind,
            parent_id: None,
            delimiter: remote.delimiter,
            subscribed: true,
        })?;
        self.store.get_folder(id)?.ok_or_else(|| {
            crate::error::Error::Other(anyhow::anyhow!(
                "upsert_folder 刚写进去的文件夹(id={id})又查不到了"
            ))
        })
    }
}

/// 一封信入库的结局。见 [`SyncEngine::ingest`]。
enum Ingested {
    /// 正常入库
    Ok,
    /// 解析坏了，占位入库（原文留着，等解析器修好重算）
    Broken,
    /// 被来信分类挪去了别的文件夹 —— **没有**本地行，等目标箱子同步收
    Moved { target: i64 },
}

/// 本地标志相对服务器标志的增减，拼成 `UID STORE` 的两个名单。
/// 只列**变了**的那几项 —— 没变的推过去也是空转一个来回。
fn flag_delta(server: &Flags, local: &Flags) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut add = Vec::new();
    let mut remove = Vec::new();
    let pairs: [(bool, bool, &'static str); 5] = [
        (local.seen, server.seen, "\\Seen"),
        (local.answered, server.answered, "\\Answered"),
        (local.flagged, server.flagged, "\\Flagged"),
        (local.draft, server.draft, "\\Draft"),
        (local.deleted, server.deleted, "\\Deleted"),
    ];
    for (want, have, name) in pairs {
        if want && !have {
            add.push(name);
        } else if !want && have {
            remove.push(name);
        }
    }
    (add, remove)
}

// ================================================================= 语义猜测

/// 从名字猜文件夹的语义。**是猜，不是解析** —— 各家命名不一
/// （`INBOX` / `[Gmail]/已发送` / `Sent Messages` / `Sent Items`…），
/// 只能按关键词匹配。猜错了用户还能自己改，所以规则宁可宽一点。
///
/// 用 `display_name` 匹配（一般是 imap_name 的最后一段），没有就退回
/// `imap_name` —— LIST 只给一个名字是常见的。
///
/// 代价是会误伤：一个叫 `Consent` 的文件夹会被认成「已发送」（contains
/// `sent`）。可接受，错了只影响侧栏排序和默认文件夹，不影响数据。
/// 显示名美化：Gmail 的 `[Gmail]/All Mail` 们翻成中文（对齐网易邮箱大师），
/// 用户标签原样保留。163 等的中文名（utf7 解码后的 `已发送`）不受影响。
///
/// 只改**显示名**，`imap_name`（wire 名）原样存 —— SELECT/APPEND 都用它。
pub fn pretty_folder_name(display_name: &str) -> String {
    let name = display_name.trim();
    let inner = name
        .strip_prefix("[Gmail]/")
        .or_else(|| name.strip_prefix("[Google Mail]/"))
        .unwrap_or(name);
    match inner.to_ascii_lowercase().as_str() {
        "all mail" => "所有邮件".into(),
        "sent mail" => "已发送".into(),
        "drafts" => "草稿箱".into(),
        "spam" => "垃圾邮件".into(),
        "trash" | "bin" => "已删除".into(),
        "important" => "重要".into(),
        "starred" => "标星邮件".into(),
        "unread" => "未读邮件".into(),
        _ => inner.to_string(),
    }
}

pub fn guess_folder_kind(imap_name: &str, display_name: &str) -> FolderKind {
    // 用 display_name 兜底：imap_name 可能是 modified UTF-7，没法直接匹配
    let name = if display_name.is_empty() {
        imap_name.to_lowercase()
    } else {
        display_name.to_lowercase()
    };

    const RULES: &[(&[&str], FolderKind)] = &[
        (&["inbox", "收件箱", "收信"], FolderKind::Inbox),
        (&["sent", "已发送", "发件箱", "已發送"], FolderKind::Sent),
        (&["draft", "草稿", "草稿箱"], FolderKind::Drafts),
        (&["trash", "deleted", "垃圾箱", "已删除", "废纸篓"], FolderKind::Trash),
        (&["junk", "spam", "垃圾邮件", "垃圾郵件"], FolderKind::Junk),
        // Gmail 的「所有邮件」就是归档语义（含全部信）
        (&["archive", "归档", "歸檔", "all mail", "所有邮件"], FolderKind::Archive),
    ];

    for (keys, kind) in RULES {
        if keys.iter().any(|k| name.contains(k)) {
            return *kind;
        }
    }
    FolderKind::Normal
}

/// 把还没建正文索引的信补一遍。返回补成的条数。
///
/// 为什么存在：`body_text` 是 schema v4 加的搜索索引列，老库升级上来那一列
/// 全是 NULL —— 不补的话「升级前收的信搜不着正文」，而且**永远**搜不着：
/// 增量同步只取新信，不会重取旧的。启动时跑一遍（worker::spawn），几秒的事。
///
/// 幂等：补过的 `body_text` 不再是 NULL，跑几遍结果一样。
///
/// 失败**不**改成 `''`（那等于「没正文」，永远不补了），就让 NULL 留着，
/// 下趟启动再试 —— 和硬规矩 3 一脉相承：坏信的原文留着、占位留着，等解析器
/// 修好还能重算。代价是坏信每次启动都进一次日志，那正是该说的事。
pub fn reindex_bodies(store: &Store) -> Result<u32> {
    let mut done = 0u32;
    for (id, rel) in store.list_messages_missing_body()? {
        let text = store
            .read_raw(&rel)
            .and_then(|raw| Ok(mime::parse_message(&raw)?.body_text.unwrap_or_default()));
        match text {
            Ok(text) => {
                store.set_message_body_text(id, &text)?;
                done += 1;
            }
            Err(e) => {
                tracing::warn!(message_id = id, "补正文索引失败，下趟启动再试: {e}");
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmail_system_folders_get_chinese_names() {
        assert_eq!(pretty_folder_name("[Gmail]/All Mail"), "所有邮件");
        assert_eq!(pretty_folder_name("[Gmail]/Sent Mail"), "已发送");
        assert_eq!(pretty_folder_name("[Gmail]/Drafts"), "草稿箱");
        assert_eq!(pretty_folder_name("[Gmail]/Spam"), "垃圾邮件");
        assert_eq!(pretty_folder_name("[Gmail]/Trash"), "已删除");
        assert_eq!(pretty_folder_name("[Gmail]/Important"), "重要");
        // 用户标签原样
        assert_eq!(pretty_folder_name("[Gmail]/Mailspring"), "Mailspring");
    }

    #[test]
    fn non_gmail_names_pass_through() {
        assert_eq!(pretty_folder_name("已发送"), "已发送"); // 163 等
        assert_eq!(pretty_folder_name("INBOX"), "INBOX");
        assert_eq!(pretty_folder_name("工作"), "工作");
    }

    #[test]
    fn gmail_folders_classified() {
        assert_eq!(
            guess_folder_kind("[Gmail]/Sent Mail", "Sent Mail"),
            FolderKind::Sent
        );
        assert_eq!(
            guess_folder_kind("[Gmail]/All Mail", "All Mail"),
            FolderKind::Archive
        );
        assert_eq!(
            guess_folder_kind("[Gmail]/Spam", "Spam"),
            FolderKind::Junk
        );
        assert_eq!(
            guess_folder_kind("[Gmail]/Mailspring", "Mailspring"),
            FolderKind::Normal
        );
    }
}
