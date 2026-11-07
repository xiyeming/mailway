//! 发信 —— SMTP 送出去，再 APPEND 回「已发送」
//!
//! 和 [`crate::sync`] 一样是编排层：协议原语在 [`crate::smtp`] / [`crate::imap`]，
//! 这里只回答「按什么顺序做、哪一步失败算什么」。
//!
//! ## 两步是独立的，别把它们混成一个成败
//!
//! 1. **SMTP 发出去** —— 这一步成了，信就到对方手里了。
//! 2. **APPEND 进「已发送」** —— 只是给自己留个副本。
//!
//! 第 2 步失败**不是发送失败**。谎报的后果是用户再点一次「发送」，对方收到
//! 两封 —— 比自己少个副本严重得多。所以 [`SendReport::saved_to_sent`] 单列
//! 出来，调用方据此决定草稿留不留：信已经出去了，自己这边又没留下副本，
//! 草稿就是那唯一的副本（这就是「失败退本地」）。
//!
//! 第 2 步内部还分先后：**APPEND 成了就算存上了**，之后的 LOGOUT 只是收尾。
//! 收尾失败同样不能推翻「已经存上」这个事实。
//!
//! ## 密码
//!
//! 和收信一样从 keyring 现取，由调用方传进来，**不进这里的任何结构**，
//! 也永远不进日志（见 [`crate::smtp`]）。SMTP 和 IMAP 各连一次，用同一个授权码。

use crate::compose::{self, Composer};
use crate::error::{Error, Result};
use crate::imap;
use crate::smtp;
use crate::types::Account;

/// 发一封信的结果。
#[derive(Debug, Clone)]
pub struct SendReport {
    /// 发出去那封的 Message-ID（不含尖括号）。排错时拿它对服务器那边的记录。
    pub message_id: String,
    /// 存进「已发送」没有。`false` = 信**已经发出去了**，只是自己没留副本，
    /// 调用方要保住草稿 —— 否则这封信就只剩对方那边有。
    pub saved_to_sent: bool,
}

/// 发一封信。
///
/// `composer` 按值收下：一封信发出去就归服务器了，留在调用方手里也没用，
/// 这样 [`Composer::message_id`] 可以在这里定死（要报给调用方，不能让
/// 「报出去的 id」和「信头里的 id」是两个）。
///
/// `sent_folder` 是「已发送」箱子的 **IMAP 名字**（不是显示名），来自
/// [`crate::store`] 里 `kind == Sent` 那一行。没有就不落副本，
/// [`SendReport::saved_to_sent`] 会是 `false`。
pub fn send_and_file(
    account: &Account,
    password: &str,
    composer: Composer,
    sent_folder: Option<&str>,
) -> Result<SendReport> {
    let mut composer = composer;
    if composer.message_id.is_none() {
        composer.message_id = Some(compose::generate_message_id(&composer.from.address));
    }
    let message_id = composer.message_id.clone().unwrap_or_default();
    let raw = composer.build()?;

    // Gmail + OAuth：**优先走 Gmail API（HTTPS 443）**——SMTP 端口（465/587）
    // 在很多网络/代理节点上被掐或被封，HTTPS 通常活着。服务端会自动把信
    // 存进「已发送」，所以不再 APPEND（会存两份）。失败则回落 SMTP 老路。
    if account.auth_type == "xoauth2" && is_gmail(account) {
        match gmail_api_send(password, &raw) {
            Ok(report) => return Ok(report),
            Err(err) => {
                tracing::warn!(
                    account = account.email,
                    error = %err.user_message(),
                    "Gmail API 发信失败，回落 SMTP 通道"
                );
            }
        }
    }

    // ---- 1. 发出去 ---------------------------------------------------
    //
    // 这一步之前的失败都是「没发出去」，可以放心报错；这一步之后就不行了。
    let env = smtp::Envelope {
        from: composer.from.address.clone(),
        to: composer
            .to
            .iter()
            .chain(&composer.cc)
            .chain(&composer.bcc)
            .map(|m| m.address.clone())
            .collect(),
    };
    let mut conn = smtp::Conn::for_account(account, password)?;
    conn.send(&env, &raw)?;
    // QUIT 而不是直接断开：有些服务器只在 QUIT 之后才把信真正投出去。
    let _ = conn.quit();

    // ---- 2. 给自己留个副本 -------------------------------------------
    //
    // 失败**只记一笔，不往上抛** —— 理由见模块头。
    let saved_to_sent = match sent_folder {
        None => {
            tracing::warn!(account = account.email, "没有「已发送」文件夹，这封信不留副本");
            false
        }
        Some(name) => match file_into_sent(account, password, name, &raw) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    account = account.email,
                    folder = name,
                    error = %e.user_message(),
                    "信发出去了，但存进「已发送」失败 —— 草稿要留着当副本"
                );
                false
            }
        },
    };

    Ok(SendReport { message_id, saved_to_sent })
}

/// 这个账号是不是 Gmail（API 通道的适用范围）。
fn is_gmail(account: &Account) -> bool {
    let domain = account.email.rsplit('@').next().unwrap_or("").to_ascii_lowercase();
    domain == "gmail.com" || domain == "googlemail.com"
}

/// Gmail API 发信（`users/me/messages/send`）。`token` 是 OAuth access token。
///
/// - 原文整封 MIME base64url 编码后交给 API，一个字节不改；
/// - Gmail **自动留「已发送」副本**（服务端标签），不再走 IMAP APPEND；
/// - 连接层错误归 [`Error::SmtpConnect`]（让上层的连接重试一并覆盖），
///   API 拒绝归 [`Error::Smtp`]。
fn gmail_api_send(token: &str, raw: &str) -> Result<SendReport> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Message-ID 在 raw 的信头里 —— 从 raw 里挖出来报给调用方。
    let message_id = raw
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("message-id:"))
        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default();

    let payload = serde_json::json!({ "raw": URL_SAFE_NO_PAD.encode(raw.as_bytes()) });
    let resp = ureq::post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string());

    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let detail: String = r.into_string().unwrap_or_default();
            let detail: String = detail.chars().take(300).collect();
            return Err(Error::Smtp(format!("Gmail API 拒绝（{code}）：{detail}")));
        }
        // 连不上 gmail.googleapis.com（网络问题）——归连接类，享受重试
        Err(err) => return Err(Error::SmtpConnect(format!("连不上 Gmail API：{err}"))),
    };
    let body = resp
        .into_string()
        .map_err(|err| Error::Smtp(format!("读 Gmail API 响应失败：{err}")))?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|err| Error::Smtp(format!("Gmail API 响应不是 JSON：{err}")))?;
    if json["id"].as_str().is_none() {
        return Err(Error::Smtp("Gmail API 没回执信件 id".into()));
    }
    Ok(SendReport { message_id, saved_to_sent: true })
}

/// APPEND 一份原文进「已发送」。原文字节一个不改。
fn file_into_sent(account: &Account, password: &str, folder: &str, raw: &str) -> Result<()> {
    let mut conn = imap::Conn::for_account(account, password)?;
    // 自己发的信就是自己看的，存下来时顺手标已读，省得已发送里全是未读
    conn.append(folder, &["\\Seen"], raw)?;
    // 登出是客气，不是义务：**走到这里副本已经在服务器上了**。
    // 把登出的错误往上抛，调用方就会以为没存上 —— 用户看到「发送失败」再点
    // 一次「发送」，对方收到两封。所以和 `src-tauri` 里那几处一样，丢掉它。
    let _ = conn.logout();
    Ok(())
}
