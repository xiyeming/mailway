//! IMAP 连接层 —— 协议原语，不含「什么时候同步」
//!
//! 这一层只回答「怎么跟服务器说话」：连上、登录、列目录、选箱、取信、
//! 改标志、IDLE 等变化。什么时候同步、同步哪些、写进哪个表，是 sync 引擎的事。
//!
//! 三个实现上的坑：
//!
//! 1. **TLS 有三种形态**（明文 / 隐式 TLS / STARTTLS），而 `imap::Session<T>`
//!    的 `T` 是具体类型。SSL 和 STARTTLS 都落到 `TlsStream<TcpStream>`，明文是
//!    `TcpStream`。所以 [`Conn`] 是这两种会话的枚举，方法里做两路分发。
//!    与其写 `Read+Write` 的 trait object 跟借用检查打架，不如老实枚举。
//! 2. **`uid_fetch` 返回值借着 session 的内部缓冲区**（零拷贝 `ZeroCopy`）。
//!    所以本层对外的返回一律是自有的（`Vec<u8>` / `String`），借用不外泄，
//!    否则调用方就没法在持有结果的同时再发下一条命令了。
//! 3. **IDLE 的 `Handle` 生命周期也绑在 session 上**，两种 `T` 的 `Handle`
//!    类型不同，不能在枚举层统一。所以做成泛型辅助函数 [`idle_wait_inner`]，
//!    两路各调一次。
//!
//! 本模块里的 `use ::imap::` 前缀是必须的：这个模块自己就叫 `imap`，
//! 不加 `::` 会和外部 crate 撞名。

pub mod utf7;

use std::net::TcpStream;
use std::time::Duration;

use chrono::{DateTime, Utc};
use imap::extensions::idle::{SetReadTimeout, WaitOutcome};
use imap::types::{Flag, NameAttribute};
use native_tls::TlsStream;

use crate::error::{Error, Result};
use crate::types::{Flags, Security};

// ================================================================= 配置

/// 单条命令的 I/O 超时。和 SMTP 同款：没有超时的 socket 在 NAT/代理黑洞下
/// 会永远挂住；连接复用后探活僵尸连接必须有界。IDLE 的长等不受影响 ——
/// imap crate 的 `wait_with_timeout` 在等待期间会自设读超时。
const IO_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
    /// 登录后默认选中的文件夹（一般是 INBOX）
    pub default_folder: String,
}

// ================================================================= 对外结果

/// LIST 的一行。
#[derive(Debug, Clone)]
pub struct RemoteFolder {
    /// 服务器上的原样名字（可能是 modified UTF-7），一切协议交互用它
    pub imap_name: String,
    /// 解码后给人看的名字
    pub display_name: String,
    /// 层级分隔符，`/` 或 `.`；顶层文件夹可能没有
    pub delimiter: Option<char>,
    /// 属性标志的字符串形式，如 `\\NoSelect`、`\\HasChildren`
    pub attributes: Vec<String>,
}

impl RemoteFolder {
    /// `\NoSelect`：只是个容器，不能 SELECT。
    pub fn noselect(&self) -> bool {
        self.attributes.iter().any(|a| a.eq_ignore_ascii_case("\\noselect"))
    }
}

/// SELECT 之后的箱子状态。
#[derive(Debug, Clone, Copy)]
pub struct MailboxStatus {
    /// **硬约束**：这个值一变，本地缓存的 UID 全部作废，必须整箱重建。
    pub uid_validity: u32,
    pub uid_next: u32,
    pub total: u32,
    pub recent: u32,
    pub unseen: Option<u32>,
}

/// 一次 FETCH 拿到的信头摘要。
///
/// 自有字节，不借 session 的缓冲区。
#[derive(Debug, Clone)]
pub struct FetchedMeta {
    pub uid: u32,
    pub flags: Flags,
    /// RFC822.SIZE，服务器说的原始终止大小
    pub size: Option<u64>,
    /// 服务器上的 INTERNALDATE（投递时间），比 `Date` 头更可信
    pub internal_date: Option<DateTime<Utc>>,
    /// 只看头猜的「可能有附件」，给列表页的回形针用。
    /// 真值要解析正文才知道，见 [`crate::mime::headers_hint_attachments`]。
    pub has_attachments: bool,
    /// 原始 header 块，直接喂 [`crate::mime::parse_message`]
    pub raw_headers: Vec<u8>,
}

/// 一次 FETCH 拿到的完整信：原文 + 元信息。
///
/// 同步引擎的主食。和 [`FetchedMeta`] 分开是因为取的东西差一个量级——
/// 列表页只要头，同步要原文。
#[derive(Debug, Clone)]
pub struct FetchedFull {
    pub uid: u32,
    pub flags: Flags,
    pub size: Option<u64>,
    pub internal_date: Option<DateTime<Utc>>,
    /// 完整原文（含头）。直接 `write_raw` 落盘，再喂 [`crate::mime::parse_message`]。
    pub raw: Vec<u8>,
}

// ================================================================= 连接

enum AnySession {
    Plain(::imap::Session<TcpStream>),
    Tls(::imap::Session<TlsStream<TcpStream>>),
}

pub struct Conn {
    session: AnySession,
}

impl Conn {
    /// 按账号记录连上去。业务侧一般用这个，不用自己拼 [`Config`]。
    ///
    /// `default_folder` 固定 INBOX：同步的第一站永远是收件箱，别的箱子
    /// 由同步引擎按 LIST 的结果自己走。
    pub fn for_account(account: &crate::types::Account, password: &str) -> Result<Self> {
        let is_oauth = account.auth_type == "xoauth2";
        Self::connect(
            &Config {
                host: account.imap_host.clone(),
                port: account.imap_port,
                security: account.imap_security,
                username: account.imap_username.clone(),
                default_folder: "INBOX".into(),
            },
            password,
            is_oauth,
        )
    }

    /// 连上并登录。
    ///
    /// 密码（或授权码）由调用方从 keyring 取，**不进这个结构**，也不会落到
    /// 任何日志里。失败一律归到 [`Error::ImapAuth`]：登录是唯一会因为凭据
    /// 出错的地方，`user_message()` 给的提示也对得上。
    ///
    /// 流由我们**自己建**：统一设读/写超时（[`IO_TIMEOUT`]）——见该常量。
    pub fn connect(cfg: &Config, password: &str, is_oauth: bool) -> Result<Self> {
        let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
            .map_err(|e| Error::ImapConnect(e.to_string()))?;
        tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
        tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();

        let session = match cfg.security {
            Security::Plain => {
                // imap crate 没有 connect_insecure，明文要自己连 TcpStream
                let mut client = ::imap::Client::new(tcp);
                client
                    .read_greeting()
                    .map_err(|e| Error::ImapConnect(e.to_string()))?;
                AnySession::Plain(login(client, cfg, password, is_oauth)?)
            }
            Security::Ssl => {
                let tls = tls_connector()?;
                let stream = tls
                    .connect(&cfg.host, tcp)
                    .map_err(|e| Error::ImapConnect(format!("TLS 握手失败: {e}")))?;
                let mut client = ::imap::Client::new(stream);
                client
                    .read_greeting()
                    .map_err(|e| Error::ImapConnect(e.to_string()))?;
                AnySession::Tls(login(client, cfg, password, is_oauth)?)
            }
            Security::StartTls => {
                let tls = tls_connector()?;
                let mut client = ::imap::Client::new(tcp);
                client
                    .read_greeting()
                    .map_err(|e| Error::ImapConnect(e.to_string()))?;
                // `secure` 内部发 STARTTLS 再升级（同 imap::connect_starttls）
                let client = client
                    .secure(cfg.host.as_str(), &tls)
                    .map_err(|e| Error::ImapConnect(e.to_string()))?;
                AnySession::Tls(login(client, cfg, password, is_oauth)?)
            }
        };
        Ok(Conn { session })
    }

    /// `LIST "" "*"`，含未订阅的。层级用 `delimiter` 自己拼。
    pub fn list_folders(&mut self) -> Result<Vec<RemoteFolder>> {
        let names = match &mut self.session {
            AnySession::Plain(s) => s.list(Some(""), Some("*")),
            AnySession::Tls(s) => s.list(Some(""), Some("*")),
        }
        .map_err(|e| Error::Imap(e.to_string()))?;

        Ok(names
            .iter()
            .map(|n| RemoteFolder {
                imap_name: n.name().to_string(),
                display_name: utf7::decode(n.name()),
                delimiter: n.delimiter().and_then(|d| d.chars().next()),
                attributes: n.attributes().iter().map(attr_name).collect(),
            })
            .collect())
    }

    /// 建文件夹。给**人起的名字**（「工作」，不是 `&Vg-`）—— modified UTF-7
    /// 的编解码收在 Conn 这一层（[`Self::list_folders`] 的 decode 同理），
    /// 外面谁也不碰 wire 形态。[`Self::select`] / [`Self::append`] 收的仍是
    /// 库里存的 `imap_name`，那个已经是编好的。
    pub fn create_folder(&mut self, display_name: &str) -> Result<()> {
        let wire = utf7::encode(display_name);
        match &mut self.session {
            AnySession::Plain(s) => s.create(wire),
            AnySession::Tls(s) => s.create(wire),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// 改文件夹名。参数都是人看的名字，理由同 [`Self::create_folder`]。
    /// 子文件夹跟着一起改（服务器的语义）。INBOX 别调这个 —— 协议里改 INBOX
    /// 是「搬到新箱子、自己清空」的特殊操作，客户端没有这个交互。
    pub fn rename_folder(&mut self, from_display: &str, to_display: &str) -> Result<()> {
        let from = utf7::encode(from_display);
        let to = utf7::encode(to_display);
        match &mut self.session {
            AnySession::Plain(s) => s.rename(from, to),
            AnySession::Tls(s) => s.rename(from, to),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// 删文件夹。箱里的信一起没 —— 本地库那边也是 `ON DELETE CASCADE`。
    /// INBOX 不许删是协议明文（RFC 3501 §6.3.4），服务器会拒。
    pub fn delete_folder(&mut self, display_name: &str) -> Result<()> {
        let wire = utf7::encode(display_name);
        match &mut self.session {
            AnySession::Plain(s) => s.delete(wire),
            AnySession::Tls(s) => s.delete(wire),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// 把**当前选中信箱**里的一封信挪到另一个信箱（RFC 6851 `UID MOVE`）。
    ///
    /// `target` 是 wire 名（库里存的 `imap_name`）——和 [`Self::select`] /
    /// [`Self::append`] 一个道理，见 [`Self::create_folder`] 那边的不对称说明。
    ///
    /// 为什么是 MOVE 不是「COPY + STORE \Deleted + EXPUNGE」三连：三步中间
    /// 任何一步断掉，结果是**两份**或者**一份都没有**，而分类挪信偏偏跑在
    /// 收信这种没人盯着的时刻。MOVE 一步到位，服务器保证原子。
    ///
    /// 代价：不支持 RFC 6851 的老服务器会回 `NO`/`BAD`。调用方（sync 的
    /// 来信分类）按失败处理 —— 信留在原箱照常入库，什么都不丢。
    pub fn uid_move(&mut self, uid: u32, target: &str) -> Result<()> {
        // 名字里有引号会截断 —— mUTF-7 编出来的 wire 名不会带引号，
        // 人手拼的才可能。真要防就是 RFC 6855 那套，犯不上。
        let cmd = format!("UID MOVE {uid} \"{target}\"");
        match &mut self.session {
            AnySession::Plain(s) => s.run_command_and_check_ok(cmd),
            AnySession::Tls(s) => s.run_command_and_check_ok(cmd),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// SELECT 一个文件夹，返回它的同步状态。
    ///
    /// ⚠️ `uid_validity` 和本地记录不一致时必须 `purge_folder_messages` 后
    /// 重来 —— 这是 IMAP 协议规定的，见 [`crate::store::Store::purge_folder_messages`]。
    pub fn select(&mut self, name: &str) -> Result<MailboxStatus> {
        let mb = match &mut self.session {
            AnySession::Plain(s) => s.select(name),
            AnySession::Tls(s) => s.select(name),
        }
        .map_err(|e| Error::Imap(e.to_string()))?;

        let uid_validity = mb
            .uid_validity
            .ok_or_else(|| Error::Imap("服务器没给 UIDVALIDITY，没法安全缓存".into()))?;

        Ok(MailboxStatus {
            uid_validity,
            uid_next: mb.uid_next.unwrap_or(0),
            total: mb.exists,
            recent: mb.recent,
            unseen: mb.unseen,
        })
    }

    /// 取一批信头。`uid_set` 是 IMAP 的 UID 集语法：`"5"`, `"1:100"`, `"1:*"`。
    ///
    /// 只取 header，不取正文 —— 列表页不需要正文，取了也是浪费带宽。
    /// `BODY.PEEK` 而不是 `BODY`：后者会顺手置 `\Seen`，收信不该改已读。
    pub fn uid_fetch_meta(&mut self, uid_set: &str) -> Result<Vec<FetchedMeta>> {
        // 查询串**自带括号**：RFC 3501 要求多个 fetch-att 必须括起来，而 imap crate
        // 发的裸列表（`UID FETCH n UID FLAGS …`）——Gmail 等容忍，Coremail（163/126）
        // 只认第一个属性（真实服务器实测：响应只剩 `(UID n)`，原文全丢）。
        const QUERY: &str = "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER])";

        let fetches = match &mut self.session {
            AnySession::Plain(s) => s.uid_fetch(uid_set, QUERY),
            AnySession::Tls(s) => s.uid_fetch(uid_set, QUERY),
        }
        .map_err(|e| Error::Imap(e.to_string()))?;

        let mut out = Vec::with_capacity(fetches.len());
        for f in fetches.iter() {
            let Some(uid) = f.uid else { continue };
            let raw_headers = f.header().unwrap_or_default().to_vec();
            out.push(FetchedMeta {
                uid,
                flags: conv_flags(f.flags()),
                size: f.size.map(|s| s as u64),
                internal_date: f.internal_date().map(|d| d.with_timezone(&Utc)),
                has_attachments: crate::mime::headers_hint_attachments(&raw_headers),
                raw_headers,
            });
        }
        Ok(out)
    }

    /// 取一封的完整原文（含头）。
    ///
    /// `BODY.PEEK[]` 而不是 `RFC822`：后者会置 `\Seen`。打开邮件算不算已读
    /// 由 UI 决定，不该由「取原文」这个动作决定。
    pub fn uid_fetch_raw(&mut self, uid: u32) -> Result<Vec<u8>> {
        let fetches = match &mut self.session {
            AnySession::Plain(s) => s.uid_fetch(uid.to_string(), "(BODY.PEEK[])"),
            AnySession::Tls(s) => s.uid_fetch(uid.to_string(), "(BODY.PEEK[])"),
        }
        .map_err(|e| Error::Imap(e.to_string()))?;

        fetches
            .iter()
            .find_map(|f| f.body().map(|b| b.to_vec()))
            .ok_or_else(|| Error::Imap(format!("服务器没返回 UID {uid} 的正文")))
    }

    /// 取一批信的原文和元信息，**一次往返**。
    ///
    /// 同步引擎用这个，而不是「先 `uid_fetch_meta` 再逐封 `uid_fetch_raw`」：
    /// 后者是 N+1 次往返，收 200 封信就要 201 个来回。
    ///
    /// `BODY.PEEK[]` 不置 `\Seen` —— 「收到信」和「读了信」是两件事。
    pub fn uid_fetch_full(&mut self, uid_set: &str) -> Result<Vec<FetchedFull>> {
        const QUERY: &str = "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[])";

        let fetches = match &mut self.session {
            AnySession::Plain(s) => s.uid_fetch(uid_set, QUERY),
            AnySession::Tls(s) => s.uid_fetch(uid_set, QUERY),
        }
        .map_err(|e| Error::Imap(e.to_string()))?;

        let mut out = Vec::with_capacity(fetches.len());
        for f in fetches.iter() {
            let Some(uid) = f.uid else { continue };
            out.push(FetchedFull {
                uid,
                flags: conv_flags(f.flags()),
                size: f.size.map(|s| s as u64),
                internal_date: f.internal_date().map(|d| d.with_timezone(&Utc)),
                raw: f.body().unwrap_or_default().to_vec(),
            });
        }
        Ok(out)
    }

    /// 只取标志：不取头，不取正文。
    ///
    /// 刷新已有邮件的已读/星标用。为改一个标志把全文拉一遍是几百 KB 的浪费，
    /// 尤其是刚开始同步几百封的时候。
    pub fn uid_fetch_flags(&mut self, uid_set: &str) -> Result<Vec<(u32, Flags)>> {
        let fetches = match &mut self.session {
            AnySession::Plain(s) => s.uid_fetch(uid_set, "(UID FLAGS)"),
            AnySession::Tls(s) => s.uid_fetch(uid_set, "(UID FLAGS)"),
        }
        .map_err(|e| Error::Imap(e.to_string()))?;

        Ok(fetches
            .iter()
            .filter_map(|f| f.uid.map(|uid| (uid, conv_flags(f.flags()))))
            .collect())
    }

    /// 改标志。`add` / `remove` 里的项是 IMAP 标志字面量，如 `"\\Seen"`。
    /// 用 `uid_store` 而不是 `store`：UID 在 UIDVALIDITY 不变的前提下稳定。
    pub fn uid_store_flags(&mut self, uid_set: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        if !add.is_empty() {
            let q = format!("+FLAGS.SILENT ({})", add.join(" "));
            self.store(uid_set, &q)?;
        }
        if !remove.is_empty() {
            let q = format!("-FLAGS.SILENT ({})", remove.join(" "));
            self.store(uid_set, &q)?;
        }
        Ok(())
    }

    fn store(&mut self, uid_set: &str, query: &str) -> Result<()> {
        let res = match &mut self.session {
            AnySession::Plain(s) => s.uid_store(uid_set, query),
            AnySession::Tls(s) => s.uid_store(uid_set, query),
        };
        res.map_err(|e| Error::Imap(e.to_string())).map(|_| ())
    }

    /// 把打了 `\Deleted` 的信**真删掉**（EXPUNGE）。
    ///
    /// 优先 `UID EXPUNGE <set>`（RFC 4315 UIDPLUS）：只删指定的那几封。
    /// 没有 UIDPLUS 的老服务器回 `NO`/`BAD` 就退回裸 `EXPUNGE` —— 删的范围
    /// 大一点（整个信箱的 `\Deleted`），但那正是老协议下「删信」的唯一做法，
    /// 与用户在别处删信的语义一致。两步全失败才报错。
    pub fn uid_expunge(&mut self, uid_set: &str) -> Result<()> {
        let uid_cmd = format!("UID EXPUNGE {uid_set}");
        match &mut self.session {
            AnySession::Plain(s) => s.run_command_and_check_ok(uid_cmd),
            AnySession::Tls(s) => s.run_command_and_check_ok(uid_cmd),
        }
        .or_else(|_| match &mut self.session {
            AnySession::Plain(s) => s.run_command_and_check_ok("EXPUNGE"),
            AnySession::Tls(s) => s.run_command_and_check_ok("EXPUNGE"),
        })
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// APPEND 一封信进某个文件夹 —— 发完信存「已发送」就靠这条。
    ///
    /// `flags` 是 IMAP 标志的字面量写法（`"\\Seen"`、`"$Forwarded"`）。自己发出去的
    /// 信一般直接标已读，所以存已发送时通常传 `&["\\Seen"]`。
    /// `raw` 就是 [`crate::compose::Composer::build`] 的输出，一个字节都不改 ——
    /// 「存下来的和发出去的是同一封」这条性质靠它成立。
    ///
    /// ⚠️ **文件夹不存在时服务器直接报错，不会自动建**（RFC 3501 明确说了）。
    /// 所以「已发送」箱子没有的话，调用方要么先 CREATE，要么就不落盘 ——
    /// 见 [`crate::send`] 里 `saved_to_sent` 那条分支。
    pub fn append(&mut self, mailbox: &str, flags: &[&str], raw: &str) -> Result<()> {
        let flags: Vec<Flag<'_>> = flags.iter().map(|f| conv_flag(f)).collect();
        match &mut self.session {
            AnySession::Plain(s) => s.append_with_flags(mailbox, raw.as_bytes(), &flags),
            AnySession::Tls(s) => s.append_with_flags(mailbox, raw.as_bytes(), &flags),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// 阻塞等邮箱变化，最多等 `timeout`。返回 `true` = 有变化。
    ///
    /// 一轮 IDLE 的边界就是 `timeout`：超时后发 `DONE` 收掉，再看要不要继续。
    /// 所以取消延迟约等于 `timeout`，调用方按需要选（同步引擎用 25 秒左右）。
    ///
    /// 有变化时**只知道「变了」，不知道变成什么** —— RFC 2177 的 IDLE 只推
    /// `* n EXISTS` 这类行，`imap` crate 也不往上抛。所以调用方要重新 SELECT
    /// 拿最新计数。
    pub fn idle_wait(&mut self, timeout: Duration) -> Result<bool> {
        match &mut self.session {
            AnySession::Plain(s) => idle_wait_inner(s, timeout),
            AnySession::Tls(s) => idle_wait_inner(s, timeout),
        }
    }

    /// 服务器是否支持 IDLE（RFC 2177）？不支持的客户端只能轮询。
    pub fn supports_idle(&mut self) -> bool {
        let caps = match &mut self.session {
            AnySession::Plain(s) => s.capabilities(),
            AnySession::Tls(s) => s.capabilities(),
        };
        match caps {
            Ok(caps) => caps.has_str("IDLE"),
            Err(_) => false,
        }
    }

    /// NOOP 一次。`imap` crate 会丢掉 untagged 响应，所以这个只是保活/探活。
    pub fn noop(&mut self) -> Result<()> {
        match &mut self.session {
            AnySession::Plain(s) => s.noop(),
            AnySession::Tls(s) => s.noop(),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }

    /// 登出。丢弃连接也行，但礼貌一点。
    pub fn logout(&mut self) -> Result<()> {
        match &mut self.session {
            AnySession::Plain(s) => s.logout(),
            AnySession::Tls(s) => s.logout(),
        }
        .map_err(|e| Error::Imap(e.to_string()))
    }
}

// ================================================================= 内部

fn tls_connector() -> Result<native_tls::TlsConnector> {
    native_tls::TlsConnector::builder()
        .build()
        .map_err(|e| Error::ImapConnect(format!("TLS 初始化失败: {e}")))
}

fn login<T: std::io::Read + std::io::Write>(
    client: ::imap::Client<T>,
    cfg: &Config,
    secret: &str,
    is_oauth: bool,
) -> Result<::imap::Session<T>> {
    // login 失败会把 client 还回来（可以再试），我们不需要，丢掉它
    let mut session = if is_oauth {
        // XOAUTH2（Google 等）：`secret` 是 access_token，走 `authenticate`
        let auth = Xoauth2Auth {
            user: cfg.username.clone(),
            token: secret.to_string(),
        };
        client
            .authenticate("XOAUTH2", &auth)
            .map_err(|(e, _client)| Error::ImapAuth(e.to_string()))
    } else {
        client
            .login(cfg.username.as_str(), secret)
            .map_err(|(e, _client)| Error::ImapAuth(e.to_string()))
    }?;

    // 声明客户端身份（RFC 2971 ID）。163/126 不认无名客户端：不发这句
    // SELECT 会报「Unsafe Login」（真实服务器实测）。失败不致命 ——
    // 别的服务器不支持 ID 也不影响收信。
    if let Err(e) = session.run_command_and_check_ok(
        r#"ID ("name" "Mailway" "version" "0.1.0" "vendor" "mailway")"#,
    ) {
        tracing::debug!("服务器不认 ID 命令（不影响收信）: {e}");
    }
    Ok(session)
}

/// XOAUTH2 的认证器：`process` 返回原始 SASL 字节（握手会 base64 后发）。
struct Xoauth2Auth {
    user: String,
    token: String,
}
impl ::imap::Authenticator for Xoauth2Auth {
    type Response = String;
    fn process(&self, _challenge: &[u8]) -> String {
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token)
    }
}

/// `NameAttribute` 没实现 `Display`，自己映射成协议上的 `\Flag` 写法。
fn attr_name(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\Noinferiors".into(),
        NameAttribute::NoSelect => "\\Noselect".into(),
        NameAttribute::Marked => "\\Marked".into(),
        NameAttribute::Unmarked => "\\Unmarked".into(),
        NameAttribute::Custom(c) => c.to_string(),
    }
}

/// 一轮 IDLE。两种 `T` 的 `Handle` 类型不同，所以做成泛型而不是在枚举里写两遍。
fn idle_wait_inner<T>(s: &mut ::imap::Session<T>, timeout: Duration) -> Result<bool>
where
    T: std::io::Read + std::io::Write + SetReadTimeout,
{
    let handle = s.idle().map_err(|e| Error::Imap(e.to_string()))?;
    let outcome = handle
        .wait_with_timeout(timeout)
        .map_err(|e| Error::Imap(e.to_string()))?;
    // handle 在这里 drop → 自动发 DONE 收掉本轮 IDLE
    Ok(outcome == WaitOutcome::MailboxChanged)
}

/// IMAP 标志的字面量写法（`"\\Seen"`）→ `imap::types::Flag`。
/// [`conv_flags`] 的反方向，[`Conn::append`] 用。
fn conv_flag(raw: &str) -> Flag<'_> {
    match raw {
        "\\Seen" | "Seen" => Flag::Seen,
        "\\Answered" | "Answered" => Flag::Answered,
        "\\Flagged" | "Flagged" => Flag::Flagged,
        "\\Deleted" | "Deleted" => Flag::Deleted,
        "\\Draft" | "Draft" => Flag::Draft,
        // 自定义关键字（`$Forwarded` 之类）原样透传。`Flag::Custom` 的
        // `Display` 就是打印里面那串，所以协议上写的和这里给的一字不差。
        other => Flag::Custom(std::borrow::Cow::Borrowed(other)),
    }
}

/// `imap::types::Flag` → 我们的 [`Flags`]。
fn conv_flags(raw: &[Flag<'_>]) -> Flags {
    let mut f = Flags::default();
    for flag in raw {
        match flag {
            Flag::Seen => f.seen = true,
            Flag::Answered => f.answered = true,
            Flag::Flagged => f.flagged = true,
            Flag::Draft => f.draft = true,
            Flag::Deleted => f.deleted = true,
            Flag::Recent => {}
            Flag::Custom(c) => {
                let s = c.to_string();
                // `\Recent` 有时也走 Custom 分支（服务端自定义写法）
                if !s.eq_ignore_ascii_case("\\recent") {
                    f.keywords.push(s);
                }
            }
            _ => {}
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_folder_noselect_detection() {
        let f = RemoteFolder {
            imap_name: "Archive".into(),
            display_name: "Archive".into(),
            delimiter: Some('/'),
            attributes: vec!["\\NoSelect".into()],
        };
        assert!(f.noselect());

        let f = RemoteFolder {
            imap_name: "INBOX".into(),
            display_name: "INBOX".into(),
            delimiter: Some('/'),
            attributes: vec!["\\HasNoChildren".into()],
        };
        assert!(!f.noselect());
    }

    #[test]
    fn flag_conversion_covers_system_and_keywords() {
        use std::borrow::Cow;
        let raw = [
            Flag::Seen,
            Flag::Flagged,
            Flag::Custom(Cow::Borrowed("$Forwarded")),
            Flag::Custom(Cow::Borrowed("\\Recent")),
        ];
        let f = conv_flags(&raw);
        assert!(f.seen && f.flagged && !f.answered && !f.draft && !f.deleted);
        assert_eq!(f.keywords, vec!["$Forwarded".to_string()]);
    }

    #[test]
    fn flag_literal_round_trips_through_append_form() {
        // `append` 收的是字面量写法（`"\\Seen"`），得能变回 `Flag`，再变回
        // 我们的 [`Flags`]。断在这里等于把「存进已发送的信标志不丢」钉死。
        let f = conv_flags(&[conv_flag("\\Seen"), conv_flag("\\Flagged"), conv_flag("$Forwarded")]);
        assert!(f.seen && f.flagged && !f.answered && !f.draft && !f.deleted);
        assert_eq!(f.keywords, vec!["$Forwarded".to_string()]);
    }
}
