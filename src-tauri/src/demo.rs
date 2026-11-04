//! 演示数据集
//!
//! M1 没有真的邮箱可连。要「端到端验证」，就得让 UI 走一条**和真实收信完全
//! 相同**的路：原始 RFC 5322 字节 → [`mailway_core::mime`]
//! → [`mailway_core::sanitize`] → SQLite → IPC → 界面。这里的信就是那些原始字节。
//!
//! 同步引擎本身另有实打实的验证（`core/tests/sync.rs`，真 TCP 假服务器）；
//! 这里补的是「解析/净化/界面」这一段。想连收信一起跑，见
//! [`seed_fake_imap_account`]。
//!
//! 每封信刻意覆盖一条不同的解析/安全路径，一眼就能看出哪条坏了：
//!
//! | # | 覆盖的路径 |
//! |---|---|
//! | 1 | 纯文本 + 中文 + RFC 2047 主题 |
//! | 2 | `cid:` 内嵌图 / 远程图拦截 / `data:` 链接摘除 |
//! | 3 | `multipart/mixed` + 附件 |
//! | 4 | `charset=gbk` 正文 |
//! | 5 | `multipart/alternative` + `References` + 地址组 |
//!
//! 只在**库里一个账号都没有**时写入，所以它不会污染以后接的真实账号。

use chrono::Utc;
use mailway_core::mime;
use mailway_core::sanitize;
use mailway_core::store::{NewAccount, NewFolder, NewMessage, Store};
use mailway_core::types::{Flags, FolderKind, Protocol, Security};
use mailway_core::{Error, Result};

/// 开发用：把账号指向 `core/src/bin/fake-imap.rs` 起的假服务器。
///
/// **只在设了 `MAILWAY_DEV_FAKE_IMAP=<端口>` 时生效**，不设就完全不碰。
/// 用它能不靠真实邮箱把「收信」整条路跑一遍：起假服务器 → 起应用 → 点
/// 「收信」，信是真从 TCP 上收下来的，走的和真实邮箱一模一样。
///
/// 发信同理，但那是**另一台**假服务器（`core/src/bin/fake-smtp.rs`），端口
/// 由 `MAILWAY_DEV_FAKE_SMTP=<端口>` 给。
///
/// 密码固定 `good`（假服务器只认这个），写进**真钥匙串**，不进库。
/// 幂等：账号已存在就不重建，只保证钥匙串里有密码 —— 重启多少次都一样。
///
/// ⚠️ 这是开发脚手架，不是产品功能。真加账号走界面上的「添加账号」
/// （`src/accounts.js` → `create_account`），那条路才是产品。
pub fn seed_fake_imap_account(store: &Store) -> Result<bool> {
    let Ok(port) = std::env::var("MAILWAY_DEV_FAKE_IMAP") else {
        return Ok(false);
    };
    let port: u16 = port
        .trim()
        .parse()
        .map_err(|_| Error::Config(format!("MAILWAY_DEV_FAKE_IMAP 该是端口号，收到 {port:?}")))?;

    // 不给就退回 IMAP 那个端口 —— 于是发信会连到一个讲 IMAP 的端口上、
    // 握手就失败。至少看得出是没配，而不是悄悄发到别处去。
    let smtp_port: u16 = match std::env::var("MAILWAY_DEV_FAKE_SMTP") {
        Ok(p) => p
            .trim()
            .parse()
            .map_err(|_| Error::Config(format!("MAILWAY_DEV_FAKE_SMTP 该是端口号，收到 {p:?}")))?,
        Err(_) => {
            tracing::warn!("没设 MAILWAY_DEV_FAKE_SMTP，发信会连到假 IMAP 的端口上，必然失败");
            port
        }
    };

    const EMAIL: &str = "me@example.com";

    let account_id = match store.list_accounts()?.into_iter().find(|a| a.email == EMAIL) {
        Some(a) => {
            // 幂等，但端口对不上得吵出来：账号是建在库里的，改环境变量不会
            // 回头去改它。不说的话，发信会一直连到一个说 IMAP 的端口上。
            if a.smtp_port != smtp_port {
                tracing::warn!(
                    "假账号的 smtp_port 是 {}，MAILWAY_DEV_FAKE_SMTP 指向 {smtp_port}；\
                     删掉这个账号（或整个数据目录）再启动才会改过来",
                    a.smtp_port
                );
            }
            a.id
        }
        None => store.insert_account(&NewAccount {
            name: "本地假服务器",
            email: EMAIL,
            protocol: Protocol::Imap,
            imap_host: "127.0.0.1",
            imap_port: port,
            imap_security: Security::Plain,
            imap_username: EMAIL,
            smtp_host: "127.0.0.1",
            smtp_port,
            smtp_security: Security::Plain,
            smtp_username: EMAIL,
            // 签名是**分隔线之后**那几行 —— 分隔线 `-- ` 由 `Composer::build`
            // 加（见 `compose.rs` 的 `apply_signature_text`）。自带一行 `--`
            // 也不会重复（`signature_body` 会认出来），但规范写法是不带。
            signature: "本地假服务器（开发用）",
            enabled: true,
            auth_type: "password",
        })?,
    };

    let account = store
        .get_account(account_id)?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("刚建的账号(id={account_id})又查不到了")))?;

    crate::secrets::set(store, &account, "good")?;
    tracing::info!("开发用假账号已就绪: {EMAIL} -> IMAP 127.0.0.1:{port}, SMTP 127.0.0.1:{smtp_port}");
    Ok(true)
}

/// 写入演示数据。已有账号就什么都不做。
///
/// **只在设了 `MAILWAY_DEV_DEMO=1` 时才该调用**（闸在 `main.rs`）：默认就播的话，
/// 真用户第一次打开应用会凭空多出一个账号和五封写死的信。演示数据是给开发看
/// 界面用的，不是产品的初始状态 —— 产品的初始状态是「还没有账号」。
pub fn seed(store: &Store) -> Result<()> {
    if !store.list_accounts()?.is_empty() {
        return Ok(());
    }

    let account_id = store.insert_account(&NewAccount {
        name: "示例邮箱",
        email: "demo@mailway.local",
        protocol: Protocol::Imap,
        imap_host: "imap.mailway.local",
        imap_port: 993,
        imap_security: Security::Ssl,
        imap_username: "demo@mailway.local",
        smtp_host: "smtp.mailway.local",
        smtp_port: 465,
        smtp_security: Security::Ssl,
        smtp_username: "demo@mailway.local",
        signature: "--\n示例签名",
        enabled: true,
        auth_type: "password",
    })?;

    let inbox = store.upsert_folder(&NewFolder {
        account_id,
        imap_name: "INBOX",
        display_name: "收件箱",
        kind: FolderKind::Inbox,
        parent_id: None,
        delimiter: Some('/'),
        subscribed: true,
    })?;
    store.upsert_folder(&NewFolder {
        account_id,
        // 已发送（modified UTF-7），顺带验一下文件夹名的编码往返
        imap_name: "&XfJT0ZAB-",
        display_name: "已发送",
        kind: FolderKind::Sent,
        parent_id: None,
        delimiter: Some('/'),
        subscribed: true,
    })?;
    store.upsert_folder(&NewFolder {
        account_id,
        imap_name: "Archive",
        display_name: "归档",
        kind: FolderKind::Archive,
        parent_id: None,
        delimiter: Some('/'),
        subscribed: true,
    })?;

    let mails: &[(&str, &str, Flags)] = &[
        (
            "5",
            M5_ALT_AND_REFERENCES,
            Flags { seen: true, ..Flags::default() },
        ),
        (
            "4",
            M4_GBK_HTML,
            Flags { seen: true, ..Flags::default() },
        ),
        (
            "3",
            M3_ATTACHMENT,
            Flags::default(),
        ),
        (
            "2",
            M2_CID_AND_REMOTE_IMAGES,
            Flags { flagged: true, ..Flags::default() },
        ),
        (
            "1",
            M1_PLAIN_CHINESE,
            Flags { seen: true, ..Flags::default() },
        ),
    ];

    for (uid, raw, flags) in mails {
        seed_message(store, account_id, inbox, uid.parse().unwrap(), raw, flags.clone())?;
    }

    tracing::info!("演示数据写入完成：1 个账号，3 个文件夹，{} 封信", mails.len());
    Ok(())
}

/// 一封信入库：先解析，再落原文，最后写摘要行。
///
/// `preview` 和 `has_attachments` 都由**真实解析**算出来，不是写死的常量——
/// 这样演示数据本身就是 MIME 层的一次冒烟测试。
fn seed_message(
    store: &Store,
    account_id: i64,
    folder_id: i64,
    uid: u32,
    raw: &str,
    flags: Flags,
) -> Result<()> {
    let parsed = mime::parse_message(raw.as_bytes())?;
    let text = parsed.body_text.clone().unwrap_or_default();
    let preview = sanitize::build_preview(&text);
    let raw_path = write_raw(store, account_id, folder_id, uid, raw.as_bytes())?;

    store.upsert_message(&NewMessage {
        account_id,
        folder_id,
        uid,
        message_id: parsed.message_id.as_deref().unwrap_or(""),
        subject: &parsed.subject,
        from: parsed.from.clone(),
        to: parsed.to.clone(),
        date: parsed.date,
        size: Some(raw.len() as u64),
        flags,
        has_attachments: parsed.has_attachments(),
        preview: &preview,
        body_text: Some(&text),
        received_at: Utc::now(),
        raw_path: Some(&raw_path),
    })?;
    Ok(())
}

fn write_raw(
    store: &Store,
    account_id: i64,
    folder_id: i64,
    uid: u32,
    bytes: &[u8],
) -> Result<std::path::PathBuf> {
    store.write_raw(account_id, folder_id, uid, bytes)
}

// ================================================================= 原始信件
//
// 行尾必须是 CRLF（RFC 5322）。`\` 续行会吃掉下一行开头的缩进，所以这些
// 字面量看着歪，出来的字节是齐的。

/// 1. 纯文本 + 中文 + RFC 2047 主题。
const M1_PLAIN_CHINESE: &str = "\
From: =?UTF-8?B?5byg5LiJ?= <zhangsan@example.com>\r\n\
To: me@mailway.local\r\n\
Subject: =?UTF-8?B?5ZGo5Lya5pS55Yiw5ZGo5Zub?=\r\n\
Date: Mon, 10 Oct 2016 09:15:00 +0800\r\n\
Message-ID: <demo-1@mailway.local>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
各位好，\r\n\
\r\n\
原定周三上午的周会改到周四下午两点，地点还是 3 号会议室。\r\n\
议题：Q4 排期，以及上季度遗留的两个技术债。\r\n\
\r\n\
张三\r\n\
";

/// 2. `multipart/related`：正文里同时有内嵌图、远程图和 `data:` 链接。
///
/// 期望的界面表现：内嵌图显示、远程图被拦住（横幅说 N 张）、`data:` 链接
/// 没有 href（点了不跳，更不会执行脚本）。
const M2_CID_AND_REMOTE_IMAGES: &str = "\
From: 图文排版 <layout@example.com>\r\n\
To: me@mailway.local\r\n\
Subject: =?UTF-8?B?6L+c56iL5Zu+54mH5LiO5YaF5bWM5Zu+?=\r\n\
Date: Tue, 11 Oct 2016 10:00:00 +0800\r\n\
Message-ID: <demo-2@mailway.local>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/related; boundary=rel\r\n\
\r\n\
--rel\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>下面这张图是<b>内嵌</b>的，应该能显示：</p>\r\n\
<p><img src=\"cid:logo@mailway.local\" alt=\"内嵌图\"></p>\r\n\
<p>下面这张是<b>远程</b>图，默认应该被拦住：</p>\r\n\
<p><img src=\"https://tracker.example.com/pixel.gif\" alt=\"远程图\"></p>\r\n\
<p>下面这个链接的 href 是 <code>data:</code>，应该被摘掉：</p>\r\n\
<p><a href=\"data:text/html,<script>alert(1)</script>\">点我</a></p>\r\n\
--rel\r\n\
Content-Type: image/png\r\n\
Content-ID: <logo@mailway.local>\r\n\
Content-Disposition: inline; filename=\"logo.png\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAgklEQVR42s2XWwrAIAwEvVGP1oN7iJb+iNCXmk0yA/7KIBp3y7bXI3MV6wYXaQI94QJPhAl84S4wgpvADHKBFWQCFswCCpYFlEwLeDAs4MmvQASvApHcBDJoApkwTgBxBxCvADEHEJMQ8RcgfkNEHkAkIkQmRKRiRC9ANCNEN1S14xO94tupZdIbbAAAAABJRU5ErkJggg==\r\n\
--rel--\r\n\
";

/// 3. `multipart/mixed`：一封正文 + 一个 PDF 附件。
const M3_ATTACHMENT: &str = "\
From: 报表 <report@example.com>\r\n\
To: me@mailway.local\r\n\
Subject: =?UTF-8?B?5bim6ZmE5Lu255qE5a2j5bqm5oql6KGo?=\r\n\
Date: Wed, 12 Oct 2016 14:30:00 +0800\r\n\
Message-ID: <demo-3@mailway.local>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=mix\r\n\
\r\n\
--mix\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
见附件。\r\n\
--mix\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"Q3.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZz4+ZW5kb2JqCnRyYWlsZXI8PC9Sb290IDEgMCBSPj4KJSVFT0YK\r\n\
--mix--\r\n\
";

/// 4. `charset=gbk` 的 HTML 正文。老邮件系统常见，解错就是一堆乱码。
const M4_GBK_HTML: &str = "\
From: 老系统 <legacy@example.com>\r\n\
To: me@mailway.local\r\n\
Subject: =?UTF-8?B?5Lit5paHIEhUTUwg5L+h?=\r\n\
Date: Thu, 13 Oct 2016 08:00:00 +0800\r\n\
Message-ID: <demo-4@mailway.local>\r\n\
Content-Type: text/html; charset=gbk\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PHA+1eK34tDFyscgR0JLILHgwuu1xKGjPC9wPjxwPsDP08q8/s+1zbOzo7z7o6y94sLrtO3By77NysfSu7bRwtLC66GjPC9wPg==\r\n\
";

/// 5. `multipart/alternative` + 引用链 + 地址组。
const M5_ALT_AND_REFERENCES: &str = "\
From: 李四 <lisi@example.com>\r\n\
To: Team: zhangsan@example.com, lisi@example.com;\r\n\
Cc: me@mailway.local\r\n\
Subject: =?UTF-8?B?UmU6IOS4iuWto+W6puaKgOacr+WAug==?=\r\n\
Date: Fri, 14 Oct 2016 17:45:00 +0800\r\n\
Message-ID: <demo-5@mailway.local>\r\n\
In-Reply-To: <demo-1@mailway.local>\r\n\
References: <demo-1@mailway.local>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=alt\r\n\
\r\n\
--alt\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
收到，我把技术债拆成两条看板了。\r\n\
--alt\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>收到，我把技术债拆成两条<b>看板</b>了。</p>\r\n\
--alt--\r\n\
";
