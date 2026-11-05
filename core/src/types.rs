//! 领域类型
//!
//! 这些类型会在 SQLite、IMAP 层和前端之间来回走，所以统一 `Serialize`。
//! 命名刻意避开网易的品牌词（大师号 / 大师空间 / 邮件群等），
//! 见 ../mailway-重写方案.md 第 8、9 节。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- 账号

/// 传输层安全模式。对应 `data/server.cfg` 里的 `flag`（1=明文 2=SSL 3=STARTTLS），
/// 但这里用枚举而不是魔数——魔数是原版的做法，读代码的人看不懂。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    /// 明文（143 / 25）。局域网或显式要求时才用。
    Plain,
    /// 隐式 TLS，连接一开始就握手（993 / 465）。
    Ssl,
    /// 明文连接后发 STARTTLS 升级（143 / 587）。
    StartTls,
}

impl Security {
    pub fn from_server_cfg_flag(flag: i64) -> Option<Self> {
        match flag {
            1 => Some(Security::Plain),
            2 => Some(Security::Ssl),
            3 => Some(Security::StartTls),
            _ => None,
        }
    }
}

/// 收信协议。M1 只做 IMAP；Exchange ActiveSync 推到 M6。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Imap,
    /// POP3（RFC 1939）。只收信：没有服务器端文件夹/标志，同步按 UIDL 增量，
    /// 已读/标星等全部只存本地。
    Pop3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// SQLite 自增主键
    pub id: i64,
    /// 显示名（用户自己起的，比如「工作」）
    pub name: String,
    /// 邮箱地址，如 `someone@gmail.com`
    pub email: String,
    pub protocol: Protocol,

    // ---------------- 收信
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub imap_username: String,

    // ---------------- 发信（M2 才用，但字段先占上）
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
    pub smtp_username: String,

    /// 签名。**不在正文里** —— 发信时才拼到正文最后（见 [`crate::compose`]）。
    /// 撰写窗口里看不到它，因为用户写正文时也确实不该被那几行占地方。
    pub signature: String,

    /// 是否启用（停用的账号不参与收信）
    pub enabled: bool,
    /// 登录方式：`password`（授权码）或 `xoauth2`（Google 等 OAuth 令牌）。
    pub auth_type: String,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------- 文件夹

/// 文件夹类型。IMAP 的特殊文件夹各家命名不一（`INBOX`、`[Gmail]/已发送`、
/// `Sent Messages`…），所以这里存的是**语义**，不是名字。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderKind {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
    /// 用户自建的普通文件夹
    Normal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: i64,
    pub account_id: i64,
    /// IMAP 上的原始名字，用于一切协议交互
    pub imap_name: String,
    /// 给用户看的名字（通常是 imap_name 的最后一段）
    pub display_name: String,
    pub kind: FolderKind,
    /// 父文件夹 id，顶层为 None
    pub parent_id: Option<i64>,
    /// IMAP 的分隔符，如 `/` 或 `.`
    pub delimiter: Option<char>,
    pub subscribed: bool,
    /// 新邮件提醒（文件夹级开关；关了就不为这个箱的新信弹通知）
    pub remind: bool,
    /// 设为快捷文件夹（侧栏「快捷文件夹」区置顶显示）
    pub quick: bool,

    // ---------------- 同步状态
    /// IMAP UIDVALIDITY。变了就必须整箱重建，这是协议规定的硬约束。
    pub uid_validity: Option<u32>,
    pub uid_next: Option<u32>,
    /// 已成功同步到本地的最高 UID
    pub last_synced_uid: Option<u32>,
    pub total: Option<u32>,
    pub unseen: Option<u32>,
}

// ---------------------------------------------------------------- 邮件

/// 邮件标志。IMAP 的 `\Seen` / `\Answered` 之类。
/// 序列化约定：**读模型一律用 serde 默认的字段名，也就是和 Rust 一致的
/// snake_case。**
///
/// 曾经这里有一层 `rename_all = "camelCase"`，结果是前端必须猜每个字段到底
/// 是哪种写法——`Message` 转了、`Folder` 没转，读起来像两套 API。现在统一
/// 不转，`src-tauri` 的命令参数也 `rename_all = "snake_case"`（见
/// `src-tauri/src/commands.rs`），于是 JS 里写的名字和 Rust 里一模一样。
///
/// **别再往这些类型上加 `rename_all`。**要改就整个 IPC 一起改。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Flags {
    pub seen: bool,
    pub answered: bool,
    pub flagged: bool,
    pub draft: bool,
    pub deleted: bool,
    /// 用户自定义关键词，如 `$Forwarded`、`Junk`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

/// 列表页要的摘要。刻意不带正文，避免列表查询把整个邮箱读进内存。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSummary {
    pub id: i64,
    pub account_id: i64,
    pub folder_id: i64,
    pub uid: u32,

    /// RFC 5322 Message-ID，去尖括号后的值
    pub message_id: String,
    pub subject: String,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub date: Option<DateTime<Utc>>,
    pub size: Option<u64>,

    pub flags: Flags,
    /// **本地**的置顶。IMAP 没有这个概念，所以同步既不拉它也不推它 ——
    /// 换台机器就没了，这是有意的取舍（M3 先要「能当日用」）。
    pub pinned: bool,
    /// **本地**的标签名列表。同上不上服务器；存 JSON，不为它建表 ——
    /// 标签就是几个名字，一次 join 的代价换不来什么（`flags_keywords` 同理）。
    pub labels: Vec<String>,
    /// 有附件
    pub has_attachments: bool,
    /// 仅纯文本的预览（列表页右侧那一行灰字）
    pub preview: String,

    /// 会话/主题聚合的分组键（主题归一，见 `thread::normalized_subject`）
    pub thread_key: String,
    /// 会话里的封数（跨文件夹，同账号）—— 列表行的聚合徽标。
    pub thread_count: u32,

    /// 收到时间（本地入库时间），用于排序兜底
    pub received_at: DateTime<Utc>,
}

/// 侧栏各种计数（快捷文件夹 + 每文件夹/账号）一次查全，见 `Store::smart_counts`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartCounts {
    /// 所有收件箱里的未读（快捷「所有收件箱」角标）
    pub inbox_unread: u64,
    /// 全部未读（快捷「所有未读」角标）
    pub all_unread: u64,
    /// 全部红旗（快捷「所有红旗」角标）
    pub all_flagged: u64,
    /// 已发送里的未读（快捷「所有已发送」角标）
    pub all_sent_unread: u64,
    /// 本地草稿总数（快捷「所有草稿箱」角标）
    pub all_drafts: u64,
    /// `folder_id -> 未读数`（账号树每文件夹角标）
    pub folder_unread: Vec<(i64, u64)>,
    /// `account_id -> 未读数`（每账号智能箱「未读邮件」）
    pub account_unread: Vec<(i64, u64)>,
    /// `account_id -> 红旗数`（每账号智能箱「红旗邮件」）
    pub account_flagged: Vec<(i64, u64)>,
}

/// 通讯录联系人（M4）。**本地库**，不进邮件正文。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: i64,
    /// 姓名
    pub name: String,
    /// 邮箱（撰写窗自动补全用）
    pub email: String,
    /// 电话
    pub phone: String,
    /// 公司/组织
    pub org: String,
    /// 备注
    pub note: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 新建联系人（入参）。
#[derive(Debug, Clone)]
pub struct NewContact<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub phone: &'a str,
    pub org: &'a str,
    pub note: &'a str,
}

/// 日历事件（M4）。时间存 ISO 字符串（**本地墙钟**，前端做日历网格的日期计算）。
/// 字段对齐参考图 12 的会议：标题/起止/全天/地点/备注/提醒/重复。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    /// 标题（参考图 `summary`）
    pub title: String,
    /// 起始（ISO，如 `2026-11-03T15:00`）
    pub start: String,
    /// 结束（ISO）
    pub end: String,
    /// 全天事件（`allDay`）
    pub all_day: bool,
    /// 地点（`location`）
    pub location: String,
    /// 备注/描述（`description`）
    pub note: String,
    /// 提醒：`none` / `10m` / `30m` / `1h` / `1d`
    pub reminder: String,
    /// 重复：`none` / `daily` / `weekly` / `monthly`
    pub repeat: String,
}

/// 新建/更新事件（入参）。
#[derive(Debug, Clone)]
pub struct NewEvent<'a> {
    pub title: &'a str,
    pub start: &'a str,
    pub end: &'a str,
    pub all_day: bool,
    pub location: &'a str,
    pub note: &'a str,
    pub reminder: &'a str,
    pub repeat: &'a str,
}

/// 邮件模板（M6）：常用正文一键插入撰写。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: i64,
    /// 模板名（列表里显示）
    pub name: String,
    /// 预填主题（可空）
    pub subject: String,
    /// 正文（纯文本，插入时进编辑区）
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 一个邮箱地址。`display` 可能是 `张三 <a@b.com>` 里的 `张三`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub display: Option<String>,
    pub address: String,
}

impl std::fmt::Display for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display {
            Some(d) if !d.is_empty() => write!(f, "{d} <{}>", self.address),
            _ => write!(f, "{}", self.address),
        }
    }
}

/// 完整邮件（阅读页用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub summary: MessageSummary,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,

    /// 净化后的 HTML（可直接 innerHTML，但前端仍应配合 CSP）
    pub body_html: Option<String>,
    /// 纯文本正文
    pub body_text: Option<String>,
    /// 用的是 HTML 还是纯文本（决定阅读页默认渲染哪种）
    pub body_kind: BodyKind,

    pub attachments: Vec<Attachment>,
    /// 原始 MIME 头（「详情」面板用）
    pub raw_headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyKind {
    Html,
    Plain,
    /// 一封邮件里既没 text 也没 html（比如纯附件邮件）
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    /// 是否 inline（正文里的小图）
    pub inline: bool,
    /// content-id，去掉尖括号；用于把 `cid:` 引用换成实际内容
    pub content_id: Option<String>,
}

// ---------------------------------------------------------------- 草稿

/// 一封还没发出去的信 —— 撰写窗口里的内容。
///
/// 存的是**撰写状态**，不是拼好的 RFC 5322 原文。用户还会回来改收件人、改正文，
/// 而拼好的原文改回去是有损的（HTML → 编辑器状态一来一回就掉了东西）。
/// 真要发的时候才 [`crate::compose::Composer::build`]。
///
/// 正文里**不含签名**：签名是账号设置，发信时才拼上去。用户在编辑器里看到的
/// 也确实没有那几行。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draft {
    pub id: i64,
    pub account_id: i64,

    /// 自动保存的版本号，单调递增。用途见 [`crate::store::Store::upsert_draft`]。
    pub rev: i64,

    pub subject: String,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,

    /// 纯文本正文
    pub text: String,
    /// HTML 正文。纯文本信是 `None`
    pub html: Option<String>,

    /// 在回哪封信（Message-ID，去尖括号）
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,

    /// 顺序就是编辑器里那个顺序
    pub attachments: Vec<DraftAttachment>,

    /// 最后一次自动保存的时间
    pub updated_at: DateTime<Utc>,
}

/// 草稿里的一个附件。**内容不在这里** —— 它动辄几 MB，而列表页和自动保存
/// 都用不到。要内容找 [`crate::store::Store::read_draft_attachment`]。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftAttachment {
    /// 同一次编辑里稳定的 id，前端插入时生成
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    /// 带这个就是正文里的内嵌图（`cid:` 引用它），不带就是普通附件
    pub content_id: Option<String>,
    pub size: u64,
}

/// 草稿列表的一行。**不带正文**，理由同 [`MessageSummary`]。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftSummary {
    pub id: i64,
    pub account_id: i64,
    pub subject: String,
    pub to: Vec<Mailbox>,
    pub attachment_count: u32,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------- 阅读视图

/// 远程图片是否放行。默认拦截，逐封豁免——和原版的行为一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteImagePolicy {
    /// 全局拦截（默认）
    Block,
    /// 这一封放行（用户点了「显示图片」）
    AllowOne,
    /// 全局放行
    AllowAll,
}

// ================================================================= IPC 形状

#[cfg(test)]
mod ipc_shape {
    use super::*;

    /// 前端就是按这些名字取值的（见 `src/app.js`）。
    ///
    /// 这条测试存在的理由：曾经 `Message` 一族带 `rename_all = "camelCase"`
    /// 而 `Folder` / `Account` 没带，前端只能猜，猜错了运行时才炸
    /// （`undefined is not an object`）。把字段名钉住，改名就得先改这里。
    fn keys<T: Serialize>(v: &T) -> Vec<String> {
        let mut k: Vec<String> = serde_json::to_value(v)
            .unwrap()
            .as_object()
            .expect("读模型应该序列化成对象")
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    }

    fn flags() -> Flags {
        Flags {
            seen: true,
            flagged: true,
            keywords: vec!["$Forwarded".into()],
            ..Flags::default()
        }
    }

    fn summary() -> MessageSummary {
        MessageSummary {
            id: 1,
            account_id: 2,
            folder_id: 3,
            uid: 4,
            message_id: "m@x".into(),
            subject: "s".into(),
            from: vec![Mailbox {
                display: Some("张三".into()),
                address: "a@x".into(),
            }],
            to: vec![],
            date: None,
            size: Some(10),
            flags: flags(),
            pinned: true,
            labels: vec!["工作".into()],
            has_attachments: true,
            preview: "p".into(),
            thread_key: "s".into(),
            thread_count: 1,
            received_at: Utc::now(),
        }
    }

    fn attachment() -> Attachment {
        Attachment {
            id: "0".into(),
            filename: "a.pdf".into(),
            mime_type: "application/pdf".into(),
            size: 3,
            inline: false,
            content_id: None,
        }
    }

    #[test]
    fn flags_keys_are_snake_case() {
        assert_eq!(
            keys(&flags()),
            vec!["answered", "deleted", "draft", "flagged", "keywords", "seen"]
        );
    }

    #[test]
    fn summary_keys_are_snake_case() {
        assert_eq!(
            keys(&summary()),
            vec![
                "account_id",
                "date",
                "flags",
                "folder_id",
                "from",
                "has_attachments",
                "id",
                "labels",
                "message_id",
                "pinned",
                "preview",
                "received_at",
                "size",
                "subject",
                "thread_count",
                "thread_key",
                "to",
                "uid",
            ]
        );
    }

    #[test]
    fn attachment_keys_are_snake_case() {
        assert_eq!(
            keys(&attachment()),
            vec!["content_id", "filename", "id", "inline", "mime_type", "size"]
        );
    }

    #[test]
    fn message_keys_are_snake_case() {
        let m = Message {
            summary: summary(),
            cc: vec![],
            bcc: vec![],
            reply_to: vec![],
            body_html: None,
            body_text: None,
            body_kind: BodyKind::Plain,
            attachments: vec![attachment()],
            raw_headers: vec![],
        };
        assert_eq!(
            keys(&m),
            vec![
                "attachments",
                "bcc",
                "body_html",
                "body_kind",
                "body_text",
                "cc",
                "raw_headers",
                "reply_to",
                "summary",
            ]
        );
    }

    #[test]
    fn enum_variants_are_snake_case() {
        // 前端靠 `remote_policy !== "block"` 判断要不要显示横幅
        assert_eq!(
            serde_json::to_string(&RemoteImagePolicy::Block).unwrap(),
            "\"block\""
        );
        assert_eq!(
            serde_json::to_string(&RemoteImagePolicy::AllowOne).unwrap(),
            "\"allow_one\""
        );
        assert_eq!(
            serde_json::to_string(&FolderKind::Inbox).unwrap(),
            "\"inbox\""
        );
        assert_eq!(serde_json::to_string(&BodyKind::Html).unwrap(), "\"html\"");
    }

    #[test]
    fn draft_shape_is_stable() {
        // 自动保存这条链路上前后端对的是同一个形状。改字段名就得先改这里 ——
        // 否则旧草稿读回来会静悄悄少几个字段，表现为「打开草稿正文没了」。
        let d = Draft {
            id: 1,
            account_id: 2,
            rev: 3,
            subject: "s".into(),
            to: vec![Mailbox { display: None, address: "a@x".into() }],
            cc: vec![],
            bcc: vec![],
            text: "t".into(),
            html: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![DraftAttachment {
                id: "att-1".into(),
                filename: "a.pdf".into(),
                mime_type: "application/pdf".into(),
                content_id: None,
                size: 9,
            }],
            updated_at: Utc::now(),
        };
        assert_eq!(
            keys(&d),
            vec![
                "account_id",
                "attachments",
                "bcc",
                "cc",
                "html",
                "id",
                "in_reply_to",
                "references",
                "rev",
                "subject",
                "text",
                "to",
                "updated_at",
            ]
        );
        assert_eq!(
            keys(&d.attachments[0]),
            vec!["content_id", "filename", "id", "mime_type", "size"]
        );
    }

    #[test]
    fn draft_summary_shape_is_stable() {
        let s = DraftSummary {
            id: 1,
            account_id: 2,
            subject: "s".into(),
            to: vec![],
            attachment_count: 0,
            updated_at: Utc::now(),
        };
        assert_eq!(
            keys(&s),
            vec!["account_id", "attachment_count", "id", "subject", "to", "updated_at"]
        );
    }
}
