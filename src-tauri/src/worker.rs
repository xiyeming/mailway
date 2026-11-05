//! 后台同步线程 —— 「能收」的最后一段
//!
//! 每个**启用的**账号一条线程：连上 → 全量同步一轮 → IDLE 等变化 → 再来一轮
//! → 发事件让前端刷新。断线退避重连；还没授权码就待命，别空转。
//!
//! 为什么是「每账号一条线程」而不是统一调度器：M1 只有 IMAP 一个协议，一个
//! 账号就是一条连接，几条线程完全够用。等 M6 要接 ActiveSync 那种需要共享
//! 调度的，再抽出来也不迟。
//!
//! 两个刻意的分工，别合并：
//!
//!   * IDLE **有变化** → 同步一轮（收新信 + 刷标志）。新信是用户最想看到的。
//!   * IDLE **超时** → 只刷标志，不取正文。
//!
//! 后者是为了「手机上标了已读、电脑上还是未读」能对上，又不至于为一个已读
//! 标记把两百封信的正文重下一遍。

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tauri::Emitter;

use mailway_core::error::Result;
use mailway_core::imap::Conn;
use mailway_core::store::Store;
use mailway_core::sync::{FolderSync, SyncEngine};
use mailway_core::types::{Account, Folder, FolderKind, Protocol};

use crate::secrets;
use crate::tokens;

/// 同步有变化时发给前端的事件名。
pub const EVENT_SYNC_CHANGED: &str = "sync://changed";

/// IMAP 一轮 IDLE 的时长（重发间隔）。RFC 2177 要求 29 分钟内重新发一次
/// （服务器会掐长连接）。**可配置**（设置→邮件读写→收信频率），钳在
/// 5~25 分钟；IDLE 本身是推送、新信秒级到，这值只是保活节奏。
fn idle_interval(store: &Store) -> Duration {
    Duration::from_secs(sync_minutes(store).clamp(5, 25) * 60)
}

/// 收信频率（分钟）—— 设置 `sync_interval_min`，默认 3。
/// 主要影响 POP3 轮询（协议无推送）；IMAP 只取其保活节奏。
fn sync_minutes(store: &Store) -> u64 {
    store
        .get_setting("sync_interval_min")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3)
        .clamp(1, 30)
}

/// 还没授权码时的轮询间隔。填好密码后最迟这么久就能用上。
const WAIT_FOR_SECRET: Duration = Duration::from_secs(30);

/// POP3 轮询间隔 = 收信频率设置（协议无推送，只能定时问；默认 3 分钟）。
fn pop3_poll(store: &Store) -> Duration {
    Duration::from_secs(sync_minutes(store) * 60)
}

/// 连不上的退避：5 秒起，翻倍到 5 分钟封顶。
const BACKOFF_MIN: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

/// 给每个启用的账号起一条后台线程。**不返回**——线程是守护型的，
/// 跟着应用一起活。
pub fn spawn(app: tauri::AppHandle, store: Arc<Store>) {
    // 老库升级（v3 → v4）后补正文搜索索引。单独一条线程：升级后第一趟可能要
    // 重解析几百封信的原文，不该卡住窗口出现。跑完自己结束。
    {
        let store = Arc::clone(&store);
        let spawned = thread::Builder::new()
            .name("mailway-reindex".into())
            .spawn(move || match mailway_core::sync::reindex_bodies(&store) {
                Ok(0) => {}
                Ok(n) => tracing::info!("补了 {n} 封信的正文搜索索引"),
                Err(e) => tracing::warn!("补正文搜索索引失败: {}", e.user_message()),
            });
        if let Err(e) = spawned {
            tracing::error!("起补索引线程失败（老信搜不着正文）: {e}");
        }
    }

    let accounts = match store.list_accounts() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("读账号列表失败，后台同步没起来: {}", e.user_message());
            return;
        }
    };

    for account in accounts.into_iter().filter(|a| a.enabled) {
        let app = app.clone();
        let store = Arc::clone(&store);
        let name = format!("mailway-sync-{}", account.email);
        if let Err(e) = thread::Builder::new().name(name).spawn(move || run(app, store, account)) {
            tracing::error!("起后台同步线程失败: {e}");
        }
    }
}

// ================================================================= 循环

fn run(app: tauri::AppHandle, store: Arc<Store>, account: Account) {
    match account.protocol {
        Protocol::Pop3 => run_pop3(app, store, account),
        Protocol::Imap => run_imap(app, store, account),
    }
}

/// POP3 循环：连上 → 收一轮 → 断开 → 睡一会再来。没有 IDLE 可等，
/// 也没有服务器标志可刷 —— 每轮就是一次纯增量收信。
fn run_pop3(app: tauri::AppHandle, store: Arc<Store>, account: Account) {
    let mut backoff = BACKOFF_MIN;

    loop {
        let password = match tokens::effective_secret(&store, &account) {
            Ok(Some(p)) => p,
            Ok(None) => {
                tracing::debug!(account = %account.email, "还没授权码，后台同步待命");
                thread::sleep(WAIT_FOR_SECRET);
                continue;
            }
            Err(e) => {
                tracing::warn!(account = %account.email, "取授权码失败: {}", e.user_message());
                thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };

        let mut pop = match mailway_core::pop3::Conn::for_account(&account, &password) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(account = %account.email, "POP3 连不上: {}", e.user_message());
                thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        backoff = BACKOFF_MIN;
        drop(password);

        match SyncEngine::new(&store).sync_pop3(&mut pop, account.id) {
            Ok(out) => report(&app, account.id, std::slice::from_ref(&out)),
            Err(e) => {
                tracing::warn!(account = %account.email, "POP3 同步失败: {}", e.user_message());
                thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        }
        pop.quit().ok();
        thread::sleep(pop3_poll(&store));
    }
}

fn run_imap(app: tauri::AppHandle, store: Arc<Store>, account: Account) {
    let mut backoff = BACKOFF_MIN;

    loop {
        // ---- 授权码 ---------------------------------------------------
        // 没填就别连：每轮都问一次钥匙串，用户填好后最迟 WAIT_FOR_SECRET 就能用。
        let password = match tokens::effective_secret(&store, &account) {
            Ok(Some(p)) => p,
            Ok(None) => {
                tracing::debug!(account = %account.email, "还没授权码，后台同步待命");
                thread::sleep(WAIT_FOR_SECRET);
                continue;
            }
            Err(e) => {
                tracing::warn!(account = %account.email, "取授权码失败: {}", e.user_message());
                thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };

        // ---- 连上 -----------------------------------------------------
        let mut conn = match Conn::for_account(&account, &password) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(account = %account.email, "后台同步连不上: {}", e.user_message());
                thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        backoff = BACKOFF_MIN;
        // 用完即弃，别让密码在栈上多活一秒
        drop(password);

        // ---- 起步全量 -------------------------------------------------
        // 这一步还顺带把文件夹行建出来（LIST → upsert_folder），之后才认得 INBOX。
        if let Err(e) = sync_all(&app, &store, account.id, &mut conn) {
            tracing::warn!(account = %account.email, "起步同步失败: {}", e.user_message());
        }

        // ---- IDLE 等变化 ----------------------------------------------
        // IDLE 挂在「当前选中的箱子」上，起步同步可能停在 LIST 的最后一个文件夹，
        // 所以这里必须显式选回 INBOX。
        if let Err(e) = conn.select("INBOX") {
            tracing::warn!(account = %account.email, "选 INBOX 失败，重连: {}", e.user_message());
            continue;
        }

        // 不支持 IDLE 的服务器只能轮询 —— 不能反复试 IDLE（连接成功会把
        // backoff 重置成 5 秒，就成了 5 秒一圈的空转，实测会把服务器问烦）。
        let idle_ok = conn.supports_idle();
        if !idle_ok {
            tracing::info!(account = %account.email, "服务器不支持 IDLE，按收信频率轮询");
        }

        loop {
            if !idle_ok {
                // 轮询模式：按收信频率（设置→邮件读写）探活 + 收一轮
                thread::sleep(pop3_poll(&store));
                if conn.noop().is_err() {
                    tracing::warn!(account = %account.email, "连接断了，重连");
                    break;
                }
                if let Err(e) = sync_inbox(&app, &store, account.id, &mut conn) {
                    tracing::warn!(account = %account.email, "同步失败，重连: {}", e.user_message());
                    break;
                }
                continue;
            }
            match conn.idle_wait(idle_interval(&store)) {
                Ok(true) => {
                    // 有变化：收新信 + 刷标志
                    if let Err(e) = sync_inbox(&app, &store, account.id, &mut conn) {
                        tracing::warn!(account = %account.email, "同步失败，重连: {}", e.user_message());
                        break;
                    }
                }
                Ok(false) => {
                    // 等到超时：只刷标志，别把正文重下一遍
                    if let Err(e) = refresh_inbox(&app, &store, account.id, &mut conn) {
                        tracing::warn!(account = %account.email, "刷标志失败，重连: {}", e.user_message());
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(account = %account.email, "IDLE 断了，重连: {}", e.user_message());
                    break;
                }
            }
        }
    }
}

// ================================================================= 轮次

/// 全量一轮：每个可选的文件夹都同步一遍。
fn sync_all(app: &tauri::AppHandle, store: &Store, account_id: i64, conn: &mut Conn) -> Result<()> {
    let outs = SyncEngine::new(store).sync_account(conn, account_id)?;
    report(app, account_id, &outs);
    Ok(())
}

/// INBOX 一轮：收新信 + 刷标志。
fn sync_inbox(app: &tauri::AppHandle, store: &Store, account_id: i64, conn: &mut Conn) -> Result<()> {
    let Some(folder) = inbox_folder(store, account_id)? else {
        return Ok(()); // 起步同步还没建出 INBOX，这轮跳过
    };
    let out = SyncEngine::new(store).sync_folder(conn, account_id, &folder)?;
    report(app, account_id, std::slice::from_ref(&out));
    Ok(())
}

/// 只刷 INBOX 的标志（不取正文）。
fn refresh_inbox(app: &tauri::AppHandle, store: &Store, account_id: i64, conn: &mut Conn) -> Result<()> {
    let Some(folder) = inbox_folder(store, account_id)? else {
        return Ok(());
    };
    let changed = SyncEngine::new(store).refresh_flags(conn, &folder)?;
    if changed > 0 {
        tracing::info!(account_id, changed, "标志刷新了 {changed} 封");
        emit(app, account_id, 0, 0, changed, 0);
    }
    Ok(())
}

fn inbox_folder(store: &Store, account_id: i64) -> Result<Option<Folder>> {
    // 优先看语义；`imap_name` 兜底 —— 有些服务器的 INBOX 不会被猜成 Inbox
    // （比如大小写奇怪的），但名字永远是 INBOX。
    Ok(store
        .list_folders(account_id)?
        .into_iter()
        .find(|f| f.kind == FolderKind::Inbox || f.imap_name.eq_ignore_ascii_case("INBOX")))
}

// ================================================================= 通知

fn report(app: &tauri::AppHandle, account_id: i64, outs: &[FolderSync]) {
    let fetched: u32 = outs.iter().map(|o| o.fetched).sum();
    let broken: u32 = outs.iter().map(|o| o.broken).sum();
    let flags_changed: u32 = outs.iter().map(|o| o.flags_changed).sum();
    let rebuilt: u32 = outs.iter().filter(|o| o.rebuilt).count() as u32;

    // 什么都没变就别吵醒前端 —— IDLE 每 20 分钟就来一次
    if fetched == 0 && broken == 0 && flags_changed == 0 && rebuilt == 0 {
        return;
    }
    tracing::info!(account_id, fetched, broken, flags_changed, rebuilt, "同步完成");
    emit(app, account_id, fetched, broken, flags_changed, rebuilt);
    // 收到新信 → 桌面通知（M5，`org.freedesktop.Notifications`）。
    // 按文件夹「新邮件提醒」开关过滤（右键文件夹可关）。
    if fetched > 0 {
        notify_new_mail(app, account_id, outs);
    }
}

/// 新信桌面通知。走 DBus（notify-rust），失败只记日志。
///
/// 尊重设置（设置→邮件通知，全部键名与前端一致）：
///   * `notify_popup` = off → 不弹；
///   * `notify_show_sender` = on → 带上最新几封的「发件人 · 主题」；
///   * `notify_sound` = on → 带提示音（`message-new-instant` 主题音）。
fn notify_new_mail(app: &tauri::AppHandle, account_id: i64, outs: &[FolderSync]) {
    use tauri::Manager;
    let store = &app.state::<crate::commands::AppState>().store;
    let setting = |key: &str, default_on: bool| -> bool {
        match store.get_setting(key) {
            Ok(Some(v)) => v != "off",
            _ => default_on,
        }
    };

    if !setting("notify_popup", true) {
        return;
    }

    // 只统计「新邮件提醒」开着的箱（文件夹右键可关）
    let folders = store.list_folders(account_id).unwrap_or_default();
    let mut fetched = 0u32;
    let mut sample_folder: Option<i64> = None;
    for o in outs {
        if o.fetched == 0 {
            continue;
        }
        let remind = folders
            .iter()
            .find(|f| f.id == o.folder_id)
            .map(|f| f.remind)
            .unwrap_or(true);
        if remind {
            fetched += o.fetched;
            sample_folder = Some(o.folder_id);
        }
    }
    if fetched == 0 {
        return; // 新信都落在关了提醒的箱里
    }

    let mut body = format!("收到 {fetched} 封新邮件");
    if setting("notify_show_sender", true) {
        // 最新几封的「发件人 · 主题」——从有新信的箱里取
        if let Some(fid) = sample_folder {
            if let Ok(msgs) = store.list_messages(fid, 2, 0) {
                for m in &msgs {
                    let who = m
                        .from
                        .first()
                        .map(|a| a.display.clone().unwrap_or_else(|| a.address.clone()))
                        .unwrap_or_default();
                    body.push_str(&format!("\n{} · {}", who, m.subject));
                }
            }
        }
    }

    let mut note = notify_rust::Notification::new();
    note.summary("Mailway").appname("mailway").body(&body);
    if setting("notify_sound", true) {
        note.hint(notify_rust::Hint::SoundName("message-new-instant".into()));
    } else {
        note.hint(notify_rust::Hint::SuppressSound(true));
    }
    if let Err(e) = note.show() {
        tracing::debug!("桌面通知失败: {e}");
    }
}

fn emit(app: &tauri::AppHandle, account_id: i64, fetched: u32, broken: u32, flags_changed: u32, rebuilt: u32) {
    let payload = serde_json::json!({
        "account_id": account_id,
        "fetched": fetched,
        "broken": broken,
        "flags_changed": flags_changed,
        "rebuilt": rebuilt,
    });
    if let Err(e) = app.emit(EVENT_SYNC_CHANGED, payload) {
        // 前端还没起来 / 窗口关了，都属于正常，别当错误处理
        tracing::debug!("发同步事件失败（前端可能还没就绪）: {e}");
    }
}
