//! SQLite 元数据 + 原文落盘
//!
//! 分工是刻意的：
//!   - **SQLite 只存元数据**（列表页要的东西）和**索引**
//!   - **MIME 原文落盘**，SQLite 里只存相对路径
//!
//! 为什么这么分：一封营销邮件的原文动辄几百 KB（内嵌 base64 图片），
//! 全塞进 SQLite 会让 `VACUUM` 和备份变得很痛苦，而且列表查询会把无关的
//! 正文一起读出来。原文按路径存，需要阅读时再读。
//!
//! 线程模型：`rusqlite` 是同步的。`Store` 内部用 `Mutex<Connection>`，
//! 方法都是同步的。**调用方不要在 tokio 的 async fn 里直接调**，要包在
//! `spawn_blocking` 里，否则会卡住 executor。M1 数据量小，这个约束够用。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::error::{Error, Result};
use crate::rules::{Action, Condition, Rule};
use crate::types::*;

/// 当前 schema 版本。以后改表结构要在这里 +`migrations` 里同时加。
pub const SCHEMA_VERSION: i64 = 6;

pub struct Store {
    conn: Mutex<Connection>,
    /// 数据根目录，原文存在 `$root/raw/...`
    root: PathBuf,
}

impl Store {
    /// 打开（必要时创建）一个数据目录下的库。
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("raw"))?;
        let conn = Connection::open(root.join("mailway.db"))?;
        let store = Self { conn: Mutex::new(conn), root };
        store.init()?;
        Ok(store)
    }

    /// 内存库，测试用。
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
            root: std::env::temp_dir().join(format!("mailway-test-{}", std::process::id())),
        };
        store.init()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn init(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        migrate(&conn)?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("数据库锁被毒化")))
    }

    // ================================================================ 账号

    pub fn insert_account(&self, a: &NewAccount<'_>) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO accounts
               (name, email, protocol,
                imap_host, imap_port, imap_security, imap_username,
                smtp_host, smtp_port, smtp_security, smtp_username,
                signature, enabled, auth_type, created_at)
             VALUES (?1,?2,?3, ?4,?5,?6,?7, ?8,?9,?10,?11, ?12,?13,?14,?15)",
            params![
                a.name,
                a.email,
                a.protocol,
                a.imap_host,
                a.imap_port,
                a.imap_security,
                a.imap_username,
                a.smtp_host,
                a.smtp_port,
                a.smtp_security,
                a.smtp_username,
                a.signature,
                a.enabled,
                a.auth_type,
                Utc::now(),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_accounts(&self) -> Result<Vec<Account>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM accounts ORDER BY id")?;
        let rows = stmt.query_map([], row_to_account)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_account(&self, id: i64) -> Result<Option<Account>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM accounts WHERE id = ?1")?;
        let row = stmt.query_row(params![id], row_to_account).optional()?;
        Ok(row)
    }

    /// 改签名。签名是账号级设置，撰写窗口里改的是它 —— 所以它跟着「写邮件」走，
    /// 不需要单独开一个设置页才改得动。
    pub fn set_account_signature(&self, id: i64, signature: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE accounts SET signature = ?2 WHERE id = ?1",
            params![id, signature],
        )?;
        Ok(())
    }

    /// 发件人姓名（= 显示名，`accounts.name`）。
    pub fn set_account_name(&self, id: i64, name: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE accounts SET name = ?2 WHERE id = ?1",
            params![id, name],
        )?;
        Ok(())
    }

    pub fn set_account_enabled(&self, id: i64, enabled: bool) -> Result<()> {        let conn = self.lock()?;
        conn.execute(
            "UPDATE accounts SET enabled = ?2 WHERE id = ?1",
            params![id, enabled],
        )?;
        Ok(())
    }

    pub fn delete_account(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ================================================================ 凭据
    //
    // 密码不进 SQLite。这里只存「去哪个 keyring 条目拿」。

    pub fn set_secret_ref(&self, account_id: i64, keyring_key: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO account_secrets (account_id, keyring_key) VALUES (?1, ?2)
             ON CONFLICT(account_id) DO UPDATE SET keyring_key = excluded.keyring_key",
            params![account_id, keyring_key],
        )?;
        Ok(())
    }

    pub fn secret_ref(&self, account_id: i64) -> Result<Option<String>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT keyring_key FROM account_secrets WHERE account_id = ?1")?;
        let row = stmt.query_row(params![account_id], |r| r.get(0)).optional()?;
        Ok(row)
    }

    // ================================================================ 文件夹

    /// 写入或更新一个文件夹。按 `(account_id, imap_name)` 幂等。
    /// 同步状态字段（uid_validity / last_synced_uid …）**不会**被覆盖，
    /// 它们由 `record_folder_sync_state` 单独维护——LIST 响应里没有这些值。
    pub fn upsert_folder(&self, f: &NewFolder<'_>) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO folders
               (account_id, imap_name, display_name, kind, parent_id, delimiter, subscribed)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(account_id, imap_name) DO UPDATE SET
               display_name = excluded.display_name,
               kind         = excluded.kind,
               parent_id    = excluded.parent_id,
               delimiter    = excluded.delimiter,
               subscribed   = excluded.subscribed",
            params![
                f.account_id,
                f.imap_name,
                f.display_name,
                f.kind,
                f.parent_id,
                f.delimiter.map(|c| c.to_string()),
                f.subscribed,
            ],
        )?;
        let mut stmt =
            conn.prepare("SELECT id FROM folders WHERE account_id=?1 AND imap_name=?2")?;
        let id = stmt.query_row(params![f.account_id, f.imap_name], |r| r.get(0))?;
        Ok(id)
    }

    pub fn list_folders(&self, account_id: i64) -> Result<Vec<Folder>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT * FROM folders WHERE account_id = ?1 ORDER BY imap_name")?;
        let rows = stmt.query_map(params![account_id], row_to_folder)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_folder(&self, id: i64) -> Result<Option<Folder>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM folders WHERE id = ?1")?;
        let row = stmt.query_row(params![id], row_to_folder).optional()?;
        Ok(row)
    }

    /// 改文件夹名。IMAP RENAME 成功之后才调 —— 先改库后改服务器的话，
    /// 中间断网就留下一个「本地叫 A、服务器叫 B」的箱子，下一趟 LIST
    /// 又把它当新箱子插一行。按 id 改，不动同步状态那几列。
    pub fn rename_folder(&self, id: i64, imap_name: &str, display_name: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE folders SET imap_name = ?2, display_name = ?3 WHERE id = ?1",
            params![id, imap_name, display_name],
        )?;
        Ok(())
    }

    /// 删文件夹。箱里的信跟着走（`messages.folder_id` 是 `ON DELETE CASCADE`）——
    /// 服务器上箱子没了，本地缓存留着也只是幽灵。同样要求 IMAP DELETE 先成功。
    pub fn delete_folder(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM folders WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// 记录一次同步后的状态。
    ///
    /// **UIDVALIDITY 变了必须清空该文件夹的邮件**——这是 IMAP 协议规定的：
    /// UID 在 UIDVALIDITY 变化后不再唯一，继续用旧的本地映射会张冠李戴。
    /// 这一步由 `SyncEngine` 判定后调用 `purge_folder_messages`，这里只负责记状态。
    pub fn record_folder_sync_state(
        &self,
        folder_id: i64,
        uid_validity: u32,
        uid_next: Option<u32>,
        last_synced_uid: Option<u32>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE folders
                SET uid_validity    = ?2,
                    uid_next        = ?3,
                    last_synced_uid = ?4
              WHERE id = ?1",
            params![folder_id, uid_validity, uid_next, last_synced_uid],
        )?;
        Ok(())
    }

    pub fn purge_folder_messages(&self, folder_id: i64) -> Result<u64> {
        let conn = self.lock()?;
        let n = conn.execute("DELETE FROM messages WHERE folder_id = ?1", params![folder_id])?;
        Ok(n as u64)
    }

    // ================================================================ 邮件

    /// 入库一封邮件。返回主键。
    ///
    /// 按 `(folder_id, uid)` 幂等：重复收同一封不会产生两行，只会更新标志。
    pub fn upsert_message(&self, m: &NewMessage<'_>) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO messages
               (account_id, folder_id, uid, message_id,
                subject, from_json, to_json, date, size,
                flags_seen, flags_answered, flags_flagged, flags_draft, flags_deleted,
                flags_keywords, has_attachments, preview, body_text, received_at, raw_path)
             VALUES (?1,?2,?3,?4, ?5,?6,?7,?8,?9, ?10,?11,?12,?13,?14, ?15,?16,?17,?18,?19,?20)
             ON CONFLICT(folder_id, uid) DO UPDATE SET
               message_id       = excluded.message_id,
               subject          = excluded.subject,
               from_json        = excluded.from_json,
               to_json          = excluded.to_json,
               date             = excluded.date,
               size             = excluded.size,
               flags_seen       = excluded.flags_seen,
               flags_answered   = excluded.flags_answered,
               flags_flagged    = excluded.flags_flagged,
               flags_draft      = excluded.flags_draft,
               flags_deleted    = excluded.flags_deleted,
               flags_keywords   = excluded.flags_keywords,
               has_attachments  = excluded.has_attachments,
               preview          = excluded.preview,
               body_text        = excluded.body_text,
               raw_path         = excluded.raw_path",
            params![
                m.account_id,
                m.folder_id,
                m.uid,
                m.message_id,
                m.subject,
                serde_json::to_string(&m.from)?,
                serde_json::to_string(&m.to)?,
                m.date,
                m.size,
                m.flags.seen,
                m.flags.answered,
                m.flags.flagged,
                m.flags.draft,
                m.flags.deleted,
                serde_json::to_string(&m.flags.keywords)?,
                m.has_attachments,
                m.preview,
                m.body_text,
                m.received_at,
                // rusqlite 不给 `Path` 实现 ToSql；库里存的是相对路径字符串
                m.raw_path.map(|p| p.to_string_lossy().into_owned()),
            ],
        )?;
        let mut stmt = conn.prepare("SELECT id FROM messages WHERE folder_id=?1 AND uid=?2")?;
        let id = stmt.query_row(params![m.folder_id, m.uid], |r| r.get(0))?;
        Ok(id)
    }

    /// 列表页查询。刻意只取摘要字段，不 join 原文。
    pub fn list_messages(
        &self,
        folder_id: i64,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<MessageSummary>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM messages
              WHERE folder_id = ?1
              ORDER BY pinned DESC, COALESCE(date, received_at) DESC, uid DESC
              LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![folder_id, limit, offset], row_to_summary)?;
        let mut msgs = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        attach_thread_counts(&conn, &mut msgs)?;
        Ok(msgs)
    }

    /// 智能箱 / 快捷文件夹：按谓词**跨文件夹**（可选跨账号）查摘要。
    /// `filter` ∈ `unread` / `flagged` / `inbox` / `sent`。
    pub fn list_smart(
        &self,
        filter: &str,
        account_id: Option<i64>,
    ) -> Result<Vec<MessageSummary>> {
        let conn = self.lock()?;
        let cond = match filter {
            "unread" => "m.flags_seen = 0",
            "flagged" => "m.flags_flagged = 1",
            "inbox" => "f.kind = 'inbox'",
            "sent" => "f.kind = 'sent'",
            other => return Err(Error::Config(format!("未知智能箱类型: {other}"))),
        };
        let order =
            " ORDER BY m.pinned DESC, COALESCE(m.date, m.received_at) DESC, m.uid DESC LIMIT 500";
        let rows = match account_id {
            Some(id) => {
                let sql = format!(
                    "SELECT m.* FROM messages m JOIN folders f ON m.folder_id = f.id \
                      WHERE ({cond}) AND m.account_id = ?1{order}"
                );
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(params![id], row_to_summary)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let sql = format!(
                    "SELECT m.* FROM messages m JOIN folders f ON m.folder_id = f.id \
                      WHERE ({cond}){order}"
                );
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map([], row_to_summary)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        let mut msgs = rows;
        attach_thread_counts(&conn, &mut msgs)?;
        Ok(msgs)
    }

    /// 侧栏各种计数（快捷文件夹 + 每文件夹未读 + 每账号红旗）一次查全。
    pub fn smart_counts(&self) -> Result<SmartCounts> {
        let conn = self.lock()?;
        let inbox_unread: u64 = conn.query_row(
            "SELECT COUNT(*) FROM messages m JOIN folders f ON m.folder_id=f.id \
              WHERE f.kind='inbox' AND m.flags_seen=0",
            [],
            |r| r.get(0),
        )?;
        let all_unread: u64 =
            conn.query_row("SELECT COUNT(*) FROM messages WHERE flags_seen=0", [], |r| r.get(0))?;
        let all_flagged: u64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE flags_flagged=1",
            [],
            |r| r.get(0),
        )?;
        let all_sent_unread: u64 = conn.query_row(
            "SELECT COUNT(*) FROM messages m JOIN folders f ON m.folder_id=f.id \
              WHERE f.kind='sent' AND m.flags_seen=0",
            [],
            |r| r.get(0),
        )?;
        let all_drafts: u64 =
            conn.query_row("SELECT COUNT(*) FROM drafts", [], |r| r.get(0))?;
        let folder_unread = {
            let mut stmt = conn
                .prepare("SELECT folder_id, COUNT(*) FROM messages WHERE flags_seen=0 GROUP BY folder_id")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<(i64, u64)>>>()?
        };
        let account_unread = {
            let mut stmt = conn
                .prepare("SELECT account_id, COUNT(*) FROM messages WHERE flags_seen=0 GROUP BY account_id")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<(i64, u64)>>>()?
        };
        let account_flagged = {
            let mut stmt = conn
                .prepare("SELECT account_id, COUNT(*) FROM messages WHERE flags_flagged=1 GROUP BY account_id")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<(i64, u64)>>>()?
        };
        Ok(SmartCounts {
            inbox_unread,
            all_unread,
            all_flagged,
            all_sent_unread,
            all_drafts,
            folder_unread,
            account_unread,
            account_flagged,
        })
    }

    /// 所有账号的文件夹（侧栏账号树用）。
    pub fn list_all_folders(&self) -> Result<Vec<Folder>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM folders ORDER BY account_id, imap_name")?;
        let rows = stmt.query_map([], row_to_folder)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 会话聚合：取同一 `thread_key` 的所有信（**跨文件夹**，同账号），按时间正序。
    /// 阅读页的会话视图用它把「收件 + 已发送」同一话题堆到一起。
    pub fn thread_messages(
        &self,
        account_id: i64,
        thread_key: &str,
    ) -> Result<Vec<MessageSummary>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM messages WHERE account_id = ?1 \
              ORDER BY COALESCE(date, received_at) ASC, uid ASC",
        )?;
        let rows = stmt.query_map(params![account_id], row_to_summary)?;
        let all = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(all
            .into_iter()
            .filter(|m: &MessageSummary| m.thread_key == thread_key)
            .collect())
    }

    // ------------------------------------------------------------ 通讯录（M4）

    /// 联系人列表（可选关键字：姓名/邮箱/电话/公司模糊匹配）。
    pub fn list_contacts(&self, query: Option<&str>) -> Result<Vec<Contact>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM contacts ORDER BY name COLLATE NOCASE, id")?;
        let rows = stmt.query_map([], row_to_contact)?;
        let all: Vec<Contact> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(match query {
            Some(q) if !q.trim().is_empty() => {
                let q = q.trim().to_lowercase();
                all.into_iter()
                    .filter(|c| {
                        c.name.to_lowercase().contains(&q)
                            || c.email.to_lowercase().contains(&q)
                            || c.phone.contains(&q)
                            || c.org.to_lowercase().contains(&q)
                    })
                    .collect()
            }
            _ => all,
        })
    }

    pub fn create_contact(&self, c: &NewContact<'_>) -> Result<i64> {
        let conn = self.lock()?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO contacts (name, email, phone, org, note, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?6)",
            params![c.name, c.email, c.phone, c.org, c.note, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_contact(&self, c: &Contact) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE contacts SET name=?2, email=?3, phone=?4, org=?5, note=?6, updated_at=?7 WHERE id=?1",
            params![c.id, c.name, c.email, c.phone, c.org, c.note, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn delete_contact(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM contacts WHERE id = ?1", params![id])?;
        Ok(())
    }

    // -------------------------------------------------------------- 日历（M4）

    /// 区间内的事件（月视图用；ISO 字符串比较即可）。
    pub fn list_events_in_range(&self, start: &str, end: &str) -> Result<Vec<Event>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT * FROM events WHERE end_at >= ?1 AND start_at < ?2 ORDER BY start_at")?;
        let rows = stmt.query_map(params![start, end], row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn create_event(&self, e: &NewEvent<'_>) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO events (title, start_at, end_at, all_day, location, note, reminder, repeat_rule)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![e.title, e.start, e.end, e.all_day as i64, e.location, e.note, e.reminder, e.repeat],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_event(&self, e: &Event) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE events SET title=?2, start_at=?3, end_at=?4, all_day=?5, location=?6,
               note=?7, reminder=?8, repeat_rule=?9 WHERE id=?1",
            params![e.id, e.title, e.start, e.end, e.all_day as i64, e.location, e.note, e.reminder, e.repeat],
        )?;
        Ok(())
    }

    pub fn delete_event(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM events WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ------------------------------------------------------------ 邮件模板（M6）

    pub fn list_templates(&self) -> Result<Vec<Template>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM templates ORDER BY name COLLATE NOCASE, id")?;
        let rows = stmt.query_map([], row_to_template)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 新建（`id=None`）或更新（带 id）。返回 id。
    pub fn save_template(&self, id: Option<i64>, name: &str, subject: &str, body: &str) -> Result<i64> {
        let conn = self.lock()?;
        let now = Utc::now().to_rfc3339();
        match id {
            Some(id) => {
                conn.execute(
                    "UPDATE templates SET name=?2, subject=?3, body=?4, updated_at=?5 WHERE id=?1",
                    params![id, name, subject, body, now],
                )?;
                Ok(id)
            }
            None => {
                conn.execute(
                    "INSERT INTO templates (name, subject, body, created_at, updated_at) VALUES (?1,?2,?3,?4,?4)",
                    params![name, subject, body, now],
                )?;
                Ok(conn.last_insert_rowid())
            }
        }
    }

    pub fn delete_template(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM templates WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ------------------------------------------------------------ 设置（键值）

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let row = stmt
            .query_row(params![key], |r| r.get::<_, String>(0))
            .optional()?;
        Ok(row)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_settings(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 取一封邮件的完整记录（含原文路径）。
    pub fn get_message_raw(&self, id: i64) -> Result<Option<StoredMessage>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM messages WHERE id = ?1")?;
        let row = stmt.query_row(params![id], row_to_stored).optional()?;
        Ok(row)
    }

    /// 也支持按 UID 查——同步时经常只知道 UID。
    pub fn get_message_by_uid(
        &self,
        folder_id: i64,
        uid: u32,
    ) -> Result<Option<StoredMessage>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT * FROM messages WHERE folder_id = ?1 AND uid = ?2")?;
        let row = stmt.query_row(params![folder_id, uid], row_to_stored).optional()?;
        Ok(row)
    }

    /// 按 POP3 的 UIDL 找信（**账号范围**）。增量收信的去重入口 —— POP3 的序号
    /// 会随服务器删信而漂，UIDL 才是那封信的身份（RFC 1939 §7）。按账号而不是
    /// 按箱找：被来信分类/用户挪去别的箱的信不能下两遍。
    pub fn get_message_uidl_account(
        &self,
        account_id: i64,
        uidl: &str,
    ) -> Result<Option<StoredMessage>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT * FROM messages WHERE account_id = ?1 AND uidl = ?2 LIMIT 1")?;
        let row = stmt.query_row(params![account_id, uidl], row_to_stored).optional()?;
        Ok(row)
    }

    /// 本地挪箱（POP3 专用）：POP3 没有服务器文件夹，`UID MOVE` 无从谈起，
    /// 改改本地行就够了。uid 按目标箱重新发一个，别和目标箱里的旧信撞。
    pub fn move_message_local(&self, id: i64, to_folder_id: i64) -> Result<()> {
        let uid = self.next_message_uid(to_folder_id)?;
        let conn = self.lock()?;
        conn.execute(
            "UPDATE messages SET folder_id = ?2, uid = ?3 WHERE id = ?1",
            params![id, to_folder_id, uid],
        )?;
        Ok(())
    }

    /// 给 POP3 新信发一个本地 uid（箱内最大 +1）。POP3 没有服务器 uid，
    /// 序号又会漂，所以本地用递增号占位 —— 唯一职责是不撞 (folder_id, uid)。
    pub fn next_message_uid(&self, folder_id: i64) -> Result<u32> {
        let conn = self.lock()?;
        let max: i64 = conn.query_row(
            "SELECT COALESCE(MAX(uid), 0) FROM messages WHERE folder_id = ?1",
            params![folder_id],
            |r| r.get(0),
        )?;
        Ok((max as u32).saturating_add(1))
    }

    /// 把 UIDL 记到已入库的行上（POP3 下次增量去重用）。
    /// 已经有值就别覆盖 —— 同一封信被规则挪箱后重新落行的场景用不上重写。
    pub fn set_message_uidl(&self, id: i64, uidl: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE messages SET uidl = ?2 WHERE id = ?1",
            params![id, uidl],
        )?;
        Ok(())
    }

    /// 保证账号有一个收件箱文件夹，返回它。IMAP 账号的文件夹由 LIST 建；
    /// POP3 只有收件箱，同步前用这个把行建出来。
    pub fn ensure_inbox_folder(&self, account_id: i64) -> Result<Folder> {
        if let Some(f) = self
            .list_folders(account_id)?
            .into_iter()
            .find(|f| f.kind == crate::types::FolderKind::Inbox)
        {
            return Ok(f);
        }
        let id = self.upsert_folder(&NewFolder {
            account_id,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: crate::types::FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })?;
        self.get_folder(id)?.ok_or_else(|| {
            crate::error::Error::Other(anyhow::anyhow!(
                "upsert_folder 刚建的收件箱(id={id})又查不到"
            ))
        })
    }

    pub fn set_message_flags(&self, id: i64, flags: &Flags) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE messages
                SET flags_seen=?2, flags_answered=?3, flags_flagged=?4,
                    flags_draft=?5, flags_deleted=?6, flags_keywords=?7
              WHERE id=?1",
            params![
                id,
                flags.seen,
                flags.answered,
                flags.flagged,
                flags.draft,
                flags.deleted,
                serde_json::to_string(&flags.keywords)?,
            ],
        )?;
        Ok(())
    }

    /// 置顶。**纯本地**：IMAP 没有这个概念，同步既不拉它也不推它，
    /// 所以这里也只有一句 UPDATE，没有「推到服务器」那半边。
    pub fn set_message_pinned(&self, id: i64, pinned: bool) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE messages SET pinned = ?2 WHERE id = ?1",
            params![id, pinned],
        )?;
        Ok(())
    }

    /// 标签，整份替换（和 `flags_keywords` 一个道理 —— 前端手里就是整份名单）。
    /// 同样是纯本地的。
    pub fn set_message_labels(&self, id: i64, labels: &[String]) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE messages SET labels_json = ?2 WHERE id = ?1",
            params![id, serde_json::to_string(labels)?],
        )?;
        Ok(())
    }

    /// 整箱标已读。返回**改过的**那些 uid，给调用方推服务器用。
    ///
    /// 一条 UPDATE 搞定本地；推回服务器是调用方（commands 的后台线程）的
    /// 事 —— 这里不碰网络，跟 `set_message_flags` 一个分工。只捞
    /// `flags_seen = 0` 的行，推的时候也就只动这些 uid，不会把还没收下来
    /// 的新信顺手标成已读。
    pub fn mark_folder_read(&self, folder_id: i64) -> Result<Vec<u32>> {
        let conn = self.lock()?;
        let uids: Vec<u32> = {
            let mut stmt =
                conn.prepare("SELECT uid FROM messages WHERE folder_id = ?1 AND flags_seen = 0")?;
            let rows = stmt.query_map(params![folder_id], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if !uids.is_empty() {
            conn.execute(
                "UPDATE messages SET flags_seen = 1 WHERE folder_id = ?1 AND flags_seen = 0",
                params![folder_id],
            )?;
        }
        Ok(uids)
    }

    /// 删一封信的本地行。附件行靠外键级联删，原文文件顺手清掉（清不掉
    /// 不算错 —— 上一次删到一半也会这样）。服务器那半边（MOVE 去废纸篓
    /// 或 EXPUNGE）不归这里管，见 commands 的 `delete_message`。
    pub fn delete_message(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        let rel: Option<Option<String>> = conn
            .query_row(
                "SELECT raw_path FROM messages WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        conn.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        if let Some(Some(rel)) = rel {
            let _ = std::fs::remove_file(self.root.join(rel));
        }
        Ok(())
    }

    pub fn count_messages(&self, folder_id: i64) -> Result<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder_id = ?1",
            params![folder_id],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// 正文索引回填（`body_text` 的 NULL → 实际文本）。
    /// 给 `sync::reindex_bodies` 用；`''` 和 NULL 的区别见 `NewMessage::body_text`。
    pub fn set_message_body_text(&self, id: i64, body_text: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE messages SET body_text = ?2 WHERE id = ?1",
            params![id, body_text],
        )?;
        Ok(())
    }

    /// 还没建正文索引的信：id + 原文相对路径。
    ///
    /// `body_text IS NULL` 是唯一的筛选条件 —— 建过索引的（哪怕 `''`）不再回来，
    /// 所以补索引跑几遍都幂等。没有原文路径的（本地草稿箱之类）不补：没得补。
    pub fn list_messages_missing_body(&self) -> Result<Vec<(i64, PathBuf)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, raw_path FROM messages
              WHERE body_text IS NULL AND raw_path IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get(0)?, PathBuf::from(r.get::<_, String>(1)?)))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 全文搜索：主题 / 收发件人 / 预览 / 正文，跨文件夹，排序和列表页一致
    /// （置顶的先、新的先）—— 搜索结果的阅读体验就该和列表一样。
    ///
    /// 用 `LIKE '%…%'` 而不是 FTS5：中文是按字找的（「会议」搜得到「下午开会」），
    /// FTS 的分词器对中文要额外配，还把「开」这种单字词漏掉；本地缓存就几千封，
    /// 全表扫是毫秒级的事。代价是没有相关度排序、不建索引 —— M3 要的是
    /// 「搜得到」，不是搜索引擎。
    ///
    /// 用户输入里的 `%` / `_` / `\` 按字面量找（转义进 pattern），不然搜个
    /// 「100%」会命中所有信。
    pub fn search_messages(
        &self,
        account_id: i64,
        query: &str,
        limit: u32,
    ) -> Result<Vec<MessageSummary>> {
        let pattern = like_pattern(query);
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM messages
              WHERE account_id = ?1
                AND (subject LIKE ?2 ESCAPE '\\'
                  OR from_json LIKE ?2 ESCAPE '\\'
                  OR to_json LIKE ?2 ESCAPE '\\'
                  OR preview LIKE ?2 ESCAPE '\\'
                  OR COALESCE(body_text, '') LIKE ?2 ESCAPE '\\')
              ORDER BY pinned DESC, COALESCE(date, received_at) DESC, uid DESC
              LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![account_id, pattern, limit], row_to_summary)?;
        let mut msgs = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        attach_thread_counts(&conn, &mut msgs)?;
        Ok(msgs)
    }

    // ================================================================ 来信分类规则

    /// 一个账号的规则，按 `ord` —— 这个顺序就是执行顺序
    /// （[`crate::rules::apply_all`] 从头跑到尾）。
    pub fn list_rules(&self, account_id: i64) -> Result<Vec<Rule>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM rules WHERE account_id = ?1 ORDER BY ord, id")?;
        let rows = stmt.query_map(params![account_id], row_to_rule)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 新规则进队尾（`ord` = 队尾 + 1）。返回 id。
    pub fn insert_rule(
        &self,
        account_id: i64,
        name: &str,
        conditions: &[Condition],
        actions: &[Action],
    ) -> Result<i64> {
        let conn = self.lock()?;
        let ord: i64 = conn.query_row(
            "SELECT COALESCE(MAX(ord), 0) + 1 FROM rules WHERE account_id = ?1",
            params![account_id],
            |r| r.get(0),
        )?;
        conn.execute(
            "INSERT INTO rules (account_id, name, enabled, conditions_json, actions_json, ord)
             VALUES (?1, ?2, 1, ?3, ?4, ?5)",
            params![
                account_id,
                name,
                serde_json::to_string(conditions)?,
                serde_json::to_string(actions)?,
                ord
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// 开关一条规则。停用的规则留着不删 —— 「先关掉试试」是常事。
    pub fn set_rule_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE rules SET enabled = ?2 WHERE id = ?1",
            params![id, enabled],
        )?;
        Ok(())
    }

    pub fn delete_rule(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ================================================================ 原文

    /// 原文落盘路径：<root>/raw/<account_id>/<folder_id>/<uid>.eml
    pub fn raw_path_for(&self, account_id: i64, folder_id: i64, uid: u32) -> PathBuf {
        self.root
            .join("raw")
            .join(account_id.to_string())
            .join(folder_id.to_string())
            .join(format!("{uid}.eml"))
    }

    /// 写入原文，返回相对 `root` 的路径（存进 `messages.raw_path`）。
    pub fn write_raw(&self, account_id: i64, folder_id: i64, uid: u32, bytes: &[u8]) -> Result<PathBuf> {
        let abs = self.raw_path_for(account_id, folder_id, uid);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, bytes)?;
        Ok(abs.strip_prefix(&self.root).unwrap_or(&abs).to_path_buf())
    }

    /// 读出原文。
    pub fn read_raw(&self, rel: &Path) -> Result<Vec<u8>> {
        let abs = self.root.join(rel);
        Ok(std::fs::read(abs)?)
    }

    // ================================================================ 草稿

    /// 存一封草稿（自动保存）。返回它的 id。
    ///
    /// **旧的保存不会盖掉新的**：`rev` 小于等于库里那条就整个跳过，附件也
    /// 一起跳过。自动保存是「打字停下来就存一次」，两次保存可能在路上错开 ——
    /// 慢的那次后到，不该把用户刚打的字抹掉。跳过之后返回的仍是**当前**那条的 id。
    pub fn upsert_draft(&self, d: &NewDraft<'_>) -> Result<i64> {
        // 附件 id 会变成磁盘文件名，先**全部**验一遍再动任何东西。
        //
        // 放到写行之后验的话，验失败了行已经进去了 —— 用户看到的是「这条草稿
        // 存了，但附件少了俩」。那种半截状态比整个保存失败难查得多。
        for a in d.attachments {
            check_attachment_id(a.id)?;
        }

        let conn = self.lock()?;
        // 整个保存是一个事务：行 + 附件行要么全进去，要么全不进去。
        // 附件那步中途失败（磁盘写不动、`content: None` 但文件不在）时，
        // 单靠「先验 id」挡不住 —— 那时候行已经写了。
        let tx = conn.unchecked_transaction()?;
        let now = Utc::now();

        let id = match d.id {
            Some(id) => {
                let current: Option<i64> = tx
                    .query_row("SELECT rev FROM drafts WHERE id = ?1", params![id], |r| r.get(0))
                    .optional()?;
                match current {
                    // 旧的，丢掉。用户刚打的字在新那份里
                    // （`tx` 半路 return 就 drop 掉，自动回滚 —— 本来也没写东西）
                    Some(cur) if d.rev <= cur => return Ok(id),
                    // 没这条也照写：草稿可能被删了，这次保存当新建，
                    // 别把用户打的字丢掉
                    _ => write_draft_row(&tx, Some(id), d, now)?,
                }
            }
            None => write_draft_row(&tx, None, d, now)?,
        };

        // ---- 附件（这一份是全量，不在里面的连文件一起删掉）----------------
        let mut keep: Vec<String> = Vec::new();
        for (ord, a) in d.attachments.iter().enumerate() {
            keep.push(a.id.to_string());

            let rel = draft_att_path(id, a.id);
            let abs = self.root.join(&rel);
            let size = match a.content {
                Some(bytes) => {
                    if let Some(parent) = abs.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&abs, bytes)?;
                    bytes.len() as i64
                }
                // 别重写。但文件得在 —— 不在就是状态坏了，报错好过悄悄存个空附件
                None => std::fs::metadata(&abs)?.len() as i64,
            };
            let rel_str = rel.to_string_lossy().into_owned();
            tx.execute(
                "INSERT INTO draft_attachments
                   (draft_id, id, filename, mime_type, content_id, size, ord, rel_path)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(draft_id, id) DO UPDATE SET
                   filename=excluded.filename, mime_type=excluded.mime_type,
                   content_id=excluded.content_id, size=excluded.size,
                   ord=excluded.ord, rel_path=excluded.rel_path",
                params![
                    id,
                    a.id,
                    a.filename,
                    a.mime_type,
                    a.content_id,
                    size,
                    ord as i64,
                    rel_str
                ],
            )?;
        }

        let dropped = {
            let mut stmt = tx.prepare(
                "SELECT id, rel_path FROM draft_attachments WHERE draft_id = ?1",
            )?;
            let rows = stmt.query_map(params![id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (aid, rel) in dropped {
            if keep.iter().any(|k| k == &aid) {
                continue;
            }
            tx.execute(
                "DELETE FROM draft_attachments WHERE draft_id = ?1 AND id = ?2",
                params![id, aid],
            )?;
            let _ = std::fs::remove_file(self.root.join(rel));
        }

        tx.commit()?;
        Ok(id)
    }

    pub fn get_draft(&self, id: i64) -> Result<Option<Draft>> {
        let conn = self.lock()?;
        let row = conn
            .query_row("SELECT * FROM drafts WHERE id = ?1", params![id], row_to_draft)
            .optional()?;
        let Some(mut d) = row else { return Ok(None) };
        d.attachments = draft_attachments(&conn, id)?;
        Ok(Some(d))
    }

    /// 草稿列表。**不带正文** —— 理由同 [`crate::types::MessageSummary`]。
    pub fn list_drafts(&self, account_id: i64) -> Result<Vec<DraftSummary>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.account_id, d.subject, d.to_json, d.updated_at,
                    (SELECT COUNT(*) FROM draft_attachments a WHERE a.draft_id = d.id) AS n
               FROM drafts d
              WHERE d.account_id = ?1
              ORDER BY d.updated_at DESC",
        )?;
        let rows = stmt.query_map(params![account_id], |r| {
            let updated_at: String = r.get("updated_at")?;
            Ok(DraftSummary {
                id: r.get("id")?,
                account_id: r.get("account_id")?,
                subject: r.get("subject")?,
                to: json_to_mailboxes(r.get("to_json")?),
                attachment_count: r.get::<_, i64>("n")? as u32,
                updated_at: updated_at.parse().unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 附件内容。可能几 MB，所以和元数据分开读。
    pub fn read_draft_attachment(&self, draft_id: i64, attachment_id: &str) -> Result<Vec<u8>> {
        let conn = self.lock()?;
        let rel: Option<String> = conn
            .query_row(
                "SELECT rel_path FROM draft_attachments WHERE draft_id = ?1 AND id = ?2",
                params![draft_id, attachment_id],
                |r| r.get(0),
            )
            .optional()?;
        let rel = rel.ok_or_else(|| {
            Error::Config(format!("草稿 {draft_id} 没有附件 {attachment_id:?}"))
        })?;
        Ok(std::fs::read(self.root.join(rel))?)
    }

    /// 删掉一封草稿，连附件文件一起。**不可恢复**，确认是调用方的事。
    pub fn delete_draft(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        let rels: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT rel_path FROM draft_attachments WHERE draft_id = ?1")?;
            let rows = stmt.query_map(params![id], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        // 附件行靠外键级联删
        conn.execute("DELETE FROM drafts WHERE id = ?1", params![id])?;
        for rel in rels {
            // 文件不在了不算错 —— 上一次删到一半也会这样
            let _ = std::fs::remove_file(self.root.join(rel));
        }
        let _ = std::fs::remove_dir(self.root.join("drafts").join(id.to_string()));
        Ok(())
    }
}

// ================================================================= 插入用的
// 「还没写库」的中间类型。和 `types` 里的读模型分开，是因为 id / received_at
// 这些是数据库生成的，构造时还没有。

#[derive(Debug, Clone)]
pub struct NewAccount<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub protocol: Protocol,
    pub imap_host: &'a str,
    pub imap_port: u16,
    pub imap_security: Security,
    pub imap_username: &'a str,
    pub smtp_host: &'a str,
    pub smtp_port: u16,
    pub smtp_security: Security,
    pub smtp_username: &'a str,
    pub signature: &'a str,
    pub enabled: bool,
    /// 登录方式：`password` 或 `xoauth2`。
    pub auth_type: &'a str,
}

#[derive(Debug, Clone)]
pub struct NewFolder<'a> {
    pub account_id: i64,
    pub imap_name: &'a str,
    pub display_name: &'a str,
    pub kind: FolderKind,
    pub parent_id: Option<i64>,
    pub delimiter: Option<char>,
    pub subscribed: bool,
}

#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub account_id: i64,
    pub folder_id: i64,
    pub uid: u32,
    pub message_id: &'a str,
    pub subject: &'a str,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub date: Option<DateTime<Utc>>,
    pub size: Option<u64>,
    pub flags: Flags,
    pub has_attachments: bool,
    pub preview: &'a str,
    /// 正文纯文本，搜索索引。`None` = 还没建（老信补索引的路子），
    /// `Some("")` = 建过了、确实没正文。入库时两个含义分得开才有得补。
    pub body_text: Option<&'a str>,
    pub received_at: DateTime<Utc>,
    pub raw_path: Option<&'a Path>,
}

/// 从库里读出来的一整行（列表摘要 + 原文路径）。
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub summary: MessageSummary,
    pub raw_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct NewDraft<'a> {
    /// 已有草稿的 id。`None` 是新建。
    pub id: Option<i64>,
    pub account_id: i64,
    /// 自动保存的版本号，**调用方负责单调递增**。
    pub rev: i64,
    pub subject: &'a str,
    pub to: &'a [Mailbox],
    pub cc: &'a [Mailbox],
    pub bcc: &'a [Mailbox],
    pub text: &'a str,
    pub html: Option<&'a str>,
    pub in_reply_to: Option<&'a str>,
    pub references: &'a [String],
    /// 顺序就是编辑器里那个顺序。这一份是**全量**：不在里面的会被删掉。
    pub attachments: &'a [NewDraftAttachment<'a>],
}

#[derive(Debug, Clone)]
pub struct NewDraftAttachment<'a> {
    /// 同一次编辑里稳定的 id，前端插入时生成。
    ///
    /// **它会变成磁盘上的文件名**，所以只接受字母数字和 `-` `_`（见
    /// [`check_attachment_id`]）。放行 `../` 之类就是目录穿越。
    pub id: &'a str,
    pub filename: &'a str,
    pub mime_type: &'a str,
    /// 带这个就是正文里的内嵌图（`cid:` 引用它）
    pub content_id: Option<&'a str>,
    /// `None` = 「内容和上次一样，别重写」。
    ///
    /// 自动保存是打字停一下就存一次，每次都把几 MB 的附件重写一遍纯属浪费。
    /// 前端只在**新拖进来的**附件上给内容。给了 `None` 但磁盘上没有，那是 bug，
    /// 直接报错，别悄悄存一个空附件。
    pub content: Option<&'a [u8]>,
}

// ================================================================= 迁移

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT    NOT NULL,
            email          TEXT    NOT NULL UNIQUE,
            protocol       TEXT    NOT NULL DEFAULT 'imap',
            imap_host      TEXT    NOT NULL,
            imap_port      INTEGER NOT NULL,
            imap_security  TEXT    NOT NULL,
            imap_username  TEXT    NOT NULL,
            smtp_host      TEXT    NOT NULL DEFAULT '',
            smtp_port      INTEGER NOT NULL DEFAULT 587,
            smtp_security  TEXT    NOT NULL DEFAULT 'start_tls',
            smtp_username  TEXT    NOT NULL DEFAULT '',
            signature      TEXT    NOT NULL DEFAULT '',
            enabled        INTEGER NOT NULL DEFAULT 1,
            created_at     TEXT    NOT NULL
        );

        -- 密码不进库，只存「去哪个 keyring 条目拿」
        CREATE TABLE IF NOT EXISTS account_secrets (
            account_id   INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            keyring_key  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS folders (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            imap_name       TEXT    NOT NULL,
            display_name    TEXT    NOT NULL,
            kind            TEXT    NOT NULL DEFAULT 'normal',
            parent_id       INTEGER REFERENCES folders(id) ON DELETE CASCADE,
            delimiter       TEXT,
            subscribed      INTEGER NOT NULL DEFAULT 1,
            uid_validity    INTEGER,
            uid_next        INTEGER,
            last_synced_uid INTEGER,
            total           INTEGER,
            unseen          INTEGER,
            UNIQUE(account_id, imap_name)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id       INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            folder_id        INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
            uid              INTEGER NOT NULL,
            message_id       TEXT    NOT NULL DEFAULT '',
            subject          TEXT    NOT NULL DEFAULT '',
            from_json        TEXT    NOT NULL DEFAULT '[]',
            to_json          TEXT    NOT NULL DEFAULT '[]',
            date             TEXT,
            size             INTEGER,
            flags_seen       INTEGER NOT NULL DEFAULT 0,
            flags_answered   INTEGER NOT NULL DEFAULT 0,
            flags_flagged    INTEGER NOT NULL DEFAULT 0,
            flags_draft      INTEGER NOT NULL DEFAULT 0,
            flags_deleted    INTEGER NOT NULL DEFAULT 0,
            flags_keywords   TEXT    NOT NULL DEFAULT '[]',
            -- 以下两个是**本地**状态，同步既不拉也不推（IMAP 没这概念）。
            -- upsert_message 也刻意不碰它们：收信重建这一行时，用户钉的顶、
            -- 贴的标签不能被服务器来的内容冲掉。
            pinned           INTEGER NOT NULL DEFAULT 0,
            labels_json      TEXT    NOT NULL DEFAULT '[]',
            has_attachments  INTEGER NOT NULL DEFAULT 0,
            preview          TEXT    NOT NULL DEFAULT '',
            -- 正文纯文本，全文搜索用（v4）。**可空**：NULL = 还没建索引
            -- （老库升级上来的信），启动时由 sync::reindex_bodies 补；
            -- '' = 建过了，确实没正文。两种状态搜索都得能走。
            body_text        TEXT,
            received_at      TEXT    NOT NULL,
            raw_path         TEXT,
            UNIQUE(folder_id, uid)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_folder_date ON messages(folder_id, date DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_folder_uid  ON messages(folder_id, uid);
        CREATE INDEX IF NOT EXISTS idx_messages_account     ON messages(account_id);
        CREATE INDEX IF NOT EXISTS idx_messages_msgid       ON messages(message_id);

        CREATE TABLE IF NOT EXISTS attachments (
            id          TEXT    PRIMARY KEY,
            message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            filename    TEXT    NOT NULL DEFAULT '',
            mime_type   TEXT    NOT NULL DEFAULT 'application/octet-stream',
            size        INTEGER NOT NULL DEFAULT 0,
            inline      INTEGER NOT NULL DEFAULT 0,
            content_id  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);

        -- 草稿。存的是**撰写状态**，不是拼好的 RFC 5322 —— 用户还会回来改，
        -- 拼好的原文改回去是有损的。真要发的时候才 build。
        CREATE TABLE IF NOT EXISTS drafts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            -- 自动保存的版本号。旧的保存不能盖掉新的，见 upsert_draft
            rev             INTEGER NOT NULL DEFAULT 0,
            subject         TEXT    NOT NULL DEFAULT '',
            to_json         TEXT    NOT NULL DEFAULT '[]',
            cc_json         TEXT    NOT NULL DEFAULT '[]',
            bcc_json        TEXT    NOT NULL DEFAULT '[]',
            text            TEXT    NOT NULL DEFAULT '',
            html            TEXT,
            in_reply_to     TEXT,
            references_json TEXT    NOT NULL DEFAULT '[]',
            updated_at      TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_drafts_account ON drafts(account_id, updated_at DESC);

        -- 草稿的附件。内容落盘（可能几 MB），库里只有元数据 + 路径。
        -- 主键是 (draft_id, id)：id 是前端在**一次编辑里**生成的，不必全局唯一。
        CREATE TABLE IF NOT EXISTS draft_attachments (
            draft_id   INTEGER NOT NULL REFERENCES drafts(id) ON DELETE CASCADE,
            id         TEXT    NOT NULL,
            filename   TEXT    NOT NULL DEFAULT '',
            mime_type  TEXT    NOT NULL DEFAULT 'application/octet-stream',
            content_id TEXT,
            size       INTEGER NOT NULL DEFAULT 0,
            ord        INTEGER NOT NULL DEFAULT 0,
            rel_path   TEXT    NOT NULL,
            PRIMARY KEY (draft_id, id)
        );

        -- 来信分类规则（M3）。条件/动作存 JSON 不拆表：形状在 `rules` 模块，
        -- 规则总共几十条，拆表 join 纯属自找麻烦。`ord` 就是执行顺序。
        CREATE TABLE IF NOT EXISTS rules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            name            TEXT    NOT NULL DEFAULT '',
            enabled         INTEGER NOT NULL DEFAULT 1,
            conditions_json TEXT    NOT NULL DEFAULT '[]',
            actions_json    TEXT    NOT NULL DEFAULT '[]',
            ord             INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_rules_account ON rules(account_id, ord);

        -- 通讯录联系人（M4）。本地库，撰写窗自动补全用。
        CREATE TABLE IF NOT EXISTS contacts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL DEFAULT '',
            email      TEXT    NOT NULL DEFAULT '',
            phone      TEXT    NOT NULL DEFAULT '',
            org        TEXT    NOT NULL DEFAULT '',
            note       TEXT    NOT NULL DEFAULT '',
            created_at TEXT    NOT NULL,
            updated_at TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_contacts_name ON contacts(name);
        CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);

        -- 日历事件（M4）。时间存 ISO 字符串（本地墙钟，前端算日历网格）。
        -- 列名 `start_at`/`end_at`/`repeat_rule`：`end`/`repeat` 是 SQL 关键字，回避掉。
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL DEFAULT '',
            start_at    TEXT    NOT NULL,
            end_at      TEXT    NOT NULL,
            all_day     INTEGER NOT NULL DEFAULT 0,
            location    TEXT    NOT NULL DEFAULT '',
            note        TEXT    NOT NULL DEFAULT '',
            reminder    TEXT    NOT NULL DEFAULT 'none',
            repeat_rule TEXT    NOT NULL DEFAULT 'none'
        );

        CREATE INDEX IF NOT EXISTS idx_events_start ON events(start_at);

        -- 邮件模板（M6）：常用正文一键插入撰写。
        CREATE TABLE IF NOT EXISTS templates (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL DEFAULT '',
            subject    TEXT    NOT NULL DEFAULT '',
            body       TEXT    NOT NULL DEFAULT '',
            created_at TEXT    NOT NULL,
            updated_at TEXT    NOT NULL
        );

        -- 键值设置（主题/通知/托盘等开关）：跨前端与 Rust 的小配置。
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )?;

    // ---- 迁移 ---------------------------------------------------------
    // 补列必须在版本检查**之前**做完：v1 的老库还没有这一列，而下面的
    // `row_to_account` 是按 `SELECT *` 读的，缺列直接报错。
    if !has_column(conn, "accounts", "signature")? {
        conn.execute(
            "ALTER TABLE accounts ADD COLUMN signature TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    // v2 → v3：messages 加 `pinned` / `labels_json`（本地状态，见表定义里的注释）。
    if !has_column(conn, "messages", "pinned")? {
        conn.execute(
            "ALTER TABLE messages ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_column(conn, "messages", "labels_json")? {
        conn.execute(
            "ALTER TABLE messages ADD COLUMN labels_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    // v3 → v4：messages 加 `body_text`（搜索索引，见表定义里的注释）。
    // 刻意不给默认值 —— 老信留 NULL 当「还没索引」的记号，让 reindex_bodies
    // 认得出要补哪些。给 DEFAULT '' 的话，老信和「确实没正文」就分不出来了。
    if !has_column(conn, "messages", "body_text")? {
        conn.execute("ALTER TABLE messages ADD COLUMN body_text TEXT", [])?;
    }
    // v5 → v6：账号加 `auth_type`（password / xoauth2，Google OAuth 登录用）。
    if !has_column(conn, "accounts", "auth_type")? {
        conn.execute(
            "ALTER TABLE accounts ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'password'",
            [],
        )?;
    }
    // v5 → v6：messages 加 `uidl`（POP3 的稳定标识，增量去重用；IMAP 不用）。
    // POP3 的序号会随服务器删信而漂，UIDL 才是那封信的身份。
    if !has_column(conn, "messages", "uidl")? {
        conn.execute(
            "ALTER TABLE messages ADD COLUMN uidl TEXT NOT NULL DEFAULT ''",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_uidl ON messages(folder_id, uidl)",
            [],
        )?;
    }

    let current: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'version'",
            [],
            |r| r.get(0),
        )
        .optional()?;

    match current {
        None => {
            conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('version', ?1)",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tracing::info!(version = SCHEMA_VERSION, "初始化数据库 schema");
        }
        Some(v) if v.parse::<i64>().unwrap_or(0) == SCHEMA_VERSION => {}
        // v1 → v2：accounts 加 `signature`。改动已经在上面补完了，这里只抬版本号。
        //
        // 版本号说的是「这个库长什么样」，不是「这次改动能不能兼容」。加一列
        // 带默认值确实是兼容的，但下一个读代码的人需要知道这个库对应哪套代码。
        Some(v) if v.parse::<i64>().unwrap_or(0) == 1 => {
            conn.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tracing::info!("数据库 schema 1 → {}", SCHEMA_VERSION);
        }
        // v2 → v3：messages 加 `pinned` / `labels_json`。同样只抬版本号。
        Some(v) if v.parse::<i64>().unwrap_or(0) == 2 => {
            conn.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tracing::info!("数据库 schema 2 → {}", SCHEMA_VERSION);
        }
        // v3 → v4：messages 加 `body_text`。老信那一列是 NULL，启动时
        // `sync::reindex_bodies` 从原文补（增量同步不会重取旧信，不补就永远缺）。
        Some(v) if v.parse::<i64>().unwrap_or(0) == 3 => {
            conn.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tracing::info!("数据库 schema 3 → {}", SCHEMA_VERSION);
        }
        // v4 → v5：加 `rules` 表（来信分类）。新表老库没有，`CREATE TABLE
        // IF NOT EXISTS` 在上面补过了，这里只抬版本号。
        Some(v) if v.parse::<i64>().unwrap_or(0) == 4 => {
            conn.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tracing::info!("数据库 schema 4 → {}", SCHEMA_VERSION);
        }
        // v5 → v6：messages 加 `uidl`（POP3）。同上，改动已补完，只抬版本号。
        Some(v) if v.parse::<i64>().unwrap_or(0) == 5 => {
            conn.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            tracing::info!("数据库 schema 5 → {}", SCHEMA_VERSION);
        }
        Some(v) => {
            // 以后有新迁移就往上加分支。版本对不上只能报错 —— 静默降级比崩溃更危险。
            return Err(Error::Config(format!(
                "数据库 schema 版本 {v} 与本程序期望的 {SCHEMA_VERSION} 不符"
            )));
        }
    }
    Ok(())
}

/// 把用户输入包成 LIKE 的 pattern（前后都加 `%`，子串匹配）。
/// `%` `_` `\` 前面垫反斜杠按字面量找 —— 配合 SQL 里的 `ESCAPE '\'`。
fn like_pattern(query: &str) -> String {
    let mut s = String::with_capacity(query.len() + 2);
    s.push('%');
    for c in query.chars() {
        if matches!(c, '%' | '_' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('%');
    s
}

/// 表里有没有这一列。
///
/// `table` / `column` 只能是代码里写死的标识符 —— 这里拼 SQL 是因为
/// `PRAGMA table_info(?)` 不吃参数。别把任何外来字符串传进来。
fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    for name in [table, column] {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(Error::Other(anyhow::anyhow!("非法标识符: {name}")));
        }
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(cols.iter().any(|c| c == column))
}

// ================================================================= 行映射

fn parse_security(s: &str) -> Security {
    match s {
        "plain" => Security::Plain,
        "start_tls" => Security::StartTls,
        _ => Security::Ssl,
    }
}

fn parse_protocol(s: &str) -> Protocol {
    match s {
        "pop3" => Protocol::Pop3,
        _ => Protocol::Imap,
    }
}

fn security_str(s: Security) -> &'static str {
    match s {
        Security::Plain => "plain",
        Security::Ssl => "ssl",
        Security::StartTls => "start_tls",
    }
}

fn parse_kind(s: &str) -> FolderKind {
    match s {
        "inbox" => FolderKind::Inbox,
        "sent" => FolderKind::Sent,
        "drafts" => FolderKind::Drafts,
        "trash" => FolderKind::Trash,
        "junk" => FolderKind::Junk,
        "archive" => FolderKind::Archive,
        _ => FolderKind::Normal,
    }
}

/// 注意：`serde(rename_all = "snake_case")` 让枚举在 JSON 里也是 snake_case，
/// 这里存库用同一套字符串，避免两套编码。
fn kind_str(k: FolderKind) -> &'static str {
    match k {
        FolderKind::Inbox => "inbox",
        FolderKind::Sent => "sent",
        FolderKind::Drafts => "drafts",
        FolderKind::Trash => "trash",
        FolderKind::Junk => "junk",
        FolderKind::Archive => "archive",
        FolderKind::Normal => "normal",
    }
}

fn row_to_account(r: &Row) -> rusqlite::Result<Account> {
    Ok(Account {
        id: r.get("id")?,
        name: r.get("name")?,
        email: r.get("email")?,
        protocol: parse_protocol(&r.get::<_, String>("protocol")?),
        imap_host: r.get("imap_host")?,
        imap_port: r.get("imap_port")?,
        imap_security: parse_security(&r.get::<_, String>("imap_security")?),
        imap_username: r.get("imap_username")?,
        smtp_host: r.get("smtp_host")?,
        smtp_port: r.get("smtp_port")?,
        smtp_security: parse_security(&r.get::<_, String>("smtp_security")?),
        smtp_username: r.get("smtp_username")?,
        signature: r.get("signature")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        auth_type: r.get::<_, String>("auth_type").unwrap_or_else(|_| "password".into()),
        created_at: r.get::<_, String>("created_at")?.parse().unwrap_or_default(),
    })
}

fn row_to_folder(r: &Row) -> rusqlite::Result<Folder> {
    let delimiter: Option<String> = r.get("delimiter")?;
    Ok(Folder {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        imap_name: r.get("imap_name")?,
        display_name: r.get("display_name")?,
        kind: parse_kind(&r.get::<_, String>("kind")?),
        parent_id: r.get("parent_id")?,
        delimiter: delimiter.and_then(|s| s.chars().next()),
        subscribed: r.get::<_, i64>("subscribed")? != 0,
        uid_validity: r.get("uid_validity")?,
        uid_next: r.get("uid_next")?,
        last_synced_uid: r.get("last_synced_uid")?,
        total: r.get("total")?,
        unseen: r.get("unseen")?,
    })
}

fn json_to_mailboxes(s: String) -> Vec<Mailbox> {
    serde_json::from_str(&s).unwrap_or_default()
}

fn json_to_keywords(s: String) -> Vec<String> {
    serde_json::from_str(&s).unwrap_or_default()
}

fn row_to_flags(r: &Row) -> rusqlite::Result<Flags> {
    Ok(Flags {
        seen: r.get::<_, i64>("flags_seen")? != 0,
        answered: r.get::<_, i64>("flags_answered")? != 0,
        flagged: r.get::<_, i64>("flags_flagged")? != 0,
        draft: r.get::<_, i64>("flags_draft")? != 0,
        deleted: r.get::<_, i64>("flags_deleted")? != 0,
        keywords: json_to_keywords(r.get("flags_keywords")?),
    })
}

fn row_to_summary(r: &Row) -> rusqlite::Result<MessageSummary> {
    let date: Option<String> = r.get("date")?;
    let received_at: String = r.get("received_at")?;
    let subject: String = r.get("subject")?;
    let thread_key = crate::thread::normalized_subject(&subject);
    Ok(MessageSummary {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        folder_id: r.get("folder_id")?,
        uid: r.get("uid")?,
        message_id: r.get("message_id")?,
        subject,
        from: json_to_mailboxes(r.get("from_json")?),
        to: json_to_mailboxes(r.get("to_json")?),
        date: date.and_then(|s| s.parse().ok()),
        size: r.get("size")?,
        flags: row_to_flags(r)?,
        pinned: r.get::<_, i64>("pinned")? != 0,
        labels: json_to_keywords(r.get("labels_json")?),
        has_attachments: r.get::<_, i64>("has_attachments")? != 0,
        preview: r.get("preview")?,
        thread_key,
        thread_count: 1,
        received_at: received_at.parse().unwrap_or_default(),
    })
}

/// 给一批摘要附上「会话封数」（同 `account_id` + `thread_key` 的总数，跨文件夹）。
/// 读一遍 `(account_id, subject)` 在内存里按主题归一分组计数 —— 邮件量不大时够用，
/// 免得为了一个角标给 messages 表再加一列 + 迁移回填。
fn attach_thread_counts(conn: &Connection, msgs: &mut [MessageSummary]) -> rusqlite::Result<()> {
    let mut map: std::collections::HashMap<(i64, String), u32> = std::collections::HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT account_id, subject FROM messages")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (acc, subj) = row?;
            let key = (acc, crate::thread::normalized_subject(&subj));
            *map.entry(key).or_insert(0) += 1;
        }
    }
    for m in msgs.iter_mut() {
        m.thread_count = map
            .get(&(m.account_id, m.thread_key.clone()))
            .copied()
            .unwrap_or(1);
    }
    Ok(())
}

fn row_to_stored(r: &Row) -> rusqlite::Result<StoredMessage> {
    let raw_path: Option<String> = r.get("raw_path")?;
    Ok(StoredMessage {
        summary: row_to_summary(r)?,
        raw_path: raw_path.map(PathBuf::from),
    })
}

fn row_to_contact(r: &Row) -> rusqlite::Result<Contact> {
    let created: String = r.get("created_at")?;
    let updated: String = r.get("updated_at")?;
    Ok(Contact {
        id: r.get("id")?,
        name: r.get("name")?,
        email: r.get("email")?,
        phone: r.get("phone")?,
        org: r.get("org")?,
        note: r.get("note")?,
        created_at: created.parse().unwrap_or_default(),
        updated_at: updated.parse().unwrap_or_default(),
    })
}

fn row_to_event(r: &Row) -> rusqlite::Result<Event> {
    Ok(Event {
        id: r.get("id")?,
        title: r.get("title")?,
        start: r.get("start_at")?,
        end: r.get("end_at")?,
        all_day: r.get::<_, i64>("all_day")? != 0,
        location: r.get("location")?,
        note: r.get("note")?,
        reminder: r.get("reminder")?,
        repeat: r.get("repeat_rule")?,
    })
}

fn row_to_template(r: &Row) -> rusqlite::Result<Template> {
    let created: String = r.get("created_at")?;
    let updated: String = r.get("updated_at")?;
    Ok(Template {
        id: r.get("id")?,
        name: r.get("name")?,
        subject: r.get("subject")?,
        body: r.get("body")?,
        created_at: created.parse().unwrap_or_default(),
        updated_at: updated.parse().unwrap_or_default(),
    })
}

fn row_to_rule(r: &Row) -> rusqlite::Result<Rule> {
    // JSON 坏了当空列表（和 json_to_mailboxes 一个态度）：空条件不匹配、
    // 空动作什么都不做，两条都是「这条规则失效」，不会闯祸。
    let conditions: String = r.get("conditions_json")?;
    let actions: String = r.get("actions_json")?;
    Ok(Rule {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        name: r.get("name")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        conditions: serde_json::from_str(&conditions).unwrap_or_default(),
        actions: serde_json::from_str(&actions).unwrap_or_default(),
    })
}

// ================================================================= 草稿

fn row_to_draft(r: &Row) -> rusqlite::Result<Draft> {
    let html: Option<String> = r.get("html")?;
    let in_reply_to: Option<String> = r.get("in_reply_to")?;
    let updated_at: String = r.get("updated_at")?;
    Ok(Draft {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        rev: r.get("rev")?,
        subject: r.get("subject")?,
        to: json_to_mailboxes(r.get("to_json")?),
        cc: json_to_mailboxes(r.get("cc_json")?),
        bcc: json_to_mailboxes(r.get("bcc_json")?),
        text: r.get("text")?,
        html,
        in_reply_to,
        references: json_to_keywords(r.get("references_json")?),
        // 附件单独查：一行一附件，硬塞进同一个 row_to_* 会变成笛卡尔积
        attachments: Vec::new(),
        updated_at: updated_at.parse().unwrap_or_default(),
    })
}

fn row_to_draft_attachment(r: &Row) -> rusqlite::Result<DraftAttachment> {
    let content_id: Option<String> = r.get("content_id")?;
    Ok(DraftAttachment {
        id: r.get("id")?,
        filename: r.get("filename")?,
        mime_type: r.get("mime_type")?,
        content_id,
        size: r.get::<_, i64>("size")? as u64,
    })
}

fn draft_attachments(conn: &Connection, draft_id: i64) -> Result<Vec<DraftAttachment>> {
    let mut stmt = conn.prepare(
        "SELECT id, filename, mime_type, content_id, size
           FROM draft_attachments WHERE draft_id = ?1 ORDER BY ord",
    )?;
    let rows = stmt.query_map(params![draft_id], row_to_draft_attachment)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// 写草稿的主行。`id` 是 `None` 就新建。
///
/// 「有就更新」走 `ON CONFLICT(id) DO UPDATE`，一份 SQL 两条路 —— 分成两条写
/// 就得把十几个字段抄两遍，早晚抄漏一个。
fn write_draft_row(
    conn: &Connection,
    id: Option<i64>,
    d: &NewDraft<'_>,
    now: DateTime<Utc>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO drafts (id, account_id, rev, subject, to_json, cc_json, bcc_json,
                             text, html, in_reply_to, references_json, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         ON CONFLICT(id) DO UPDATE SET
           account_id=excluded.account_id, rev=excluded.rev, subject=excluded.subject,
           to_json=excluded.to_json, cc_json=excluded.cc_json, bcc_json=excluded.bcc_json,
           text=excluded.text, html=excluded.html, in_reply_to=excluded.in_reply_to,
           references_json=excluded.references_json, updated_at=excluded.updated_at",
        params![
            id,
            d.account_id,
            d.rev,
            d.subject,
            serde_json::to_string(d.to)?,
            serde_json::to_string(d.cc)?,
            serde_json::to_string(d.bcc)?,
            d.text,
            d.html,
            d.in_reply_to,
            serde_json::to_string(d.references)?,
            now,
        ],
    )?;
    Ok(id.unwrap_or_else(|| conn.last_insert_rowid()))
}

/// 草稿附件的落盘路径（相对 root）：`drafts/<draft_id>/<attachment_id>`
fn draft_att_path(draft_id: i64, attachment_id: &str) -> PathBuf {
    PathBuf::from("drafts").join(draft_id.to_string()).join(attachment_id)
}

/// 附件 id 会变成磁盘上的文件名，所以只放行 `[A-Za-z0-9_-]`。
///
/// 放行 `../` 就是目录穿越 —— 前端发过来的字符串直接拼进路径是经典漏洞。
fn check_attachment_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!("附件 id 只能是字母数字和 - _，实际 {id:?}")))
    }
}

// `security_str` 现在只在写库用；`insert_account` 用的是 serde 的 Display
// 其实没有，这里补一个显式转换，避免以后改枚举时漏改。
#[allow(dead_code)]
fn sec_str(s: Security) -> &'static str {
    security_str(s)
}

// 让 params! 里能直接传 Security / Protocol
impl rusqlite::ToSql for Security {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(security_str(*self)))
    }
}

impl rusqlite::ToSql for Protocol {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(match self {
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
        }))
    }
}

impl rusqlite::ToSql for FolderKind {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(kind_str(*self)))
    }
}

// `DateTime<Utc>` 的 ToSql/FromSql 由 rusqlite 的 `chrono` feature 提供。
// 自己 impl 会撞孤儿规则（两个类型都不是本 crate 的）。
