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
use crate::error::Result;
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
