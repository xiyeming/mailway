//! IPC 命令
//!
//! 这一层是**薄的**：取数、组装、返回。判断和解析都在 [`mailway_core`]，
//! 这样同一条逻辑能脱离 GUI 单测。任何在这里写业务规则的做法都是走错了地方。
//!
//! 返回值一律是 `types` 里的模型（都已经 `Serialize`），前端拿到就是现成的
//! JSON。错误统一走 [`Error::user_message`]，**不能**把内部错误串直接抛给
//! 用户——里面可能带路径和主机名。

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tauri::State;

use mailway_core::compose::{self, Composer, OutAttachment};
use mailway_core::error::{Error, Result as CoreResult};
use mailway_core::imap::Conn;
use mailway_core::mime;
use mailway_core::rules::{Action, Condition, Rule};
use mailway_core::sanitize::{self, SanitizedBody};
use mailway_core::store::{NewAccount, NewDraft, NewDraftAttachment, Store};
use mailway_core::sync::SyncEngine;
use mailway_core::types::{
    Account, Attachment, Contact, Draft, DraftSummary, Event, Flags, Folder, FolderKind, Mailbox,
    Message, MessageSummary, NewContact, NewEvent, Protocol, RemoteImagePolicy, Security, SmartCounts,
    Template,
};

use crate::secrets;
use crate::tokens;
use crate::pool::ConnPool;

pub struct AppState {
    /// `Arc` 是给后台同步线程用的：它要能独立于任何一次 IPC 调用访问数据库。
    /// [`Store`] 自己内部是 `Mutex<Connection>`，方法都只借 `&self`，所以共享
    /// 一份就够，不需要把状态搬来搬去。
    pub store: Arc<Store>,
    /// IMAP 连接复用池（见 [`crate::pool`]）：同账号的连续操作共用一条
    /// 已登录连接，慢网下省掉每趟 TLS+LOGIN 的 2~5 秒。
    pub pool: Arc<ConnPool<Conn>>,
    /// 用户点了「显示图片」的那些邮件。
    ///
    /// 策略是**逐封豁免**，不是全局开关——和原版一致，也更安全：默认拦，
    /// 想看再放开，且只放开这一封。所以它是个集合，不是个 bool。
    ///
    /// 只在内存里：重启回到默认拦截。放行是一个「这次我想看」的动作，
    /// 不是一条要长期记住的偏好。
    allowed_remote: Mutex<HashSet<i64>>,
}

impl AppState {
    pub fn new(store: Arc<Store>) -> Self {
        // 建连闭包就是原来 `connect()` 那套：查账号 → 取凭据（xoauth2 会顺带
        // 刷 token）→ 连上登录。探活用 NOOP（一个极小的来回）。
        let store_for_pool = Arc::clone(&store);
        let pool = Arc::new(ConnPool::new(
            move |account_id| {
                let account = store_for_pool
                    .get_account(account_id)?
                    .ok_or_else(|| Error::Config("账号已不存在".into()))?;
                let password = crate::tokens::effective_secret(&store_for_pool, &account)?
                    .ok_or_else(|| Error::Secret("没有授权码".into()))?;
                Conn::for_account(&account, &password)
            },
            |conn| conn.noop().is_ok(),
        ));
        AppState {
            store,
            pool,
            allowed_remote: Mutex::new(HashSet::new()),
        }
    }

    fn remote_allowed(&self, message_id: i64) -> bool {
        self.allowed_remote
            .lock()
            .map(|s| s.contains(&message_id))
            .unwrap_or(false)
    }
}

/// 内部错误 → 用户能看懂的一句话。这是唯一的出口。
fn e(err: Error) -> String {
    err.user_message()
}

fn not_found(what: &str) -> String {
    format!("找不到{what}")
}

// ================================================================= 账号 / 文件夹

#[tauri::command(rename_all = "snake_case")]
pub fn list_accounts(state: State<'_, AppState>) -> Result<Vec<Account>, String> {
    state.store.list_accounts().map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_folders(state: State<'_, AppState>, account_id: i64) -> Result<Vec<Folder>, String> {
    state.store.list_folders(account_id).map_err(e)
}

/// 建文件夹。名字空不空是这里的事（交互规则）；编 mUTF-7、落库都在
/// [`SyncEngine::create_folder`]。
///
/// 网络操作秒级起步 —— 丢进**阻塞线程池**，别占着 IPC 派发线程（主线程）：
/// 同步命令在派发线程里内联跑，会把 busy DOM 的绘制卡住，前端 loading
/// 只能等命令结束才「闪一下」。改名/删除/同步同理。
#[tauri::command(rename_all = "snake_case")]
pub async fn create_folder(
    state: State<'_, AppState>,
    account_id: i64,
    name: String,
) -> Result<Folder, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("文件夹名不能空着".into());
    }
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    tauri::async_runtime::spawn_blocking(move || {
        pool.with(account_id, |conn| {
            SyncEngine::new(&store).create_folder(conn, account_id, &name)
        })
        .map_err(e)
    })
    .await
    .map_err(|err| err.to_string())?
}

/// 改文件夹名。收件箱不给改 —— 协议里改 INBOX 是「搬空自己」的特殊语义，
/// 我们没有这个交互，放出去只会让人莫名其妙丢箱子。
#[tauri::command(rename_all = "snake_case")]
pub async fn rename_folder(
    state: State<'_, AppState>,
    folder_id: i64,
    new_name: String,
) -> Result<Folder, String> {
    let new_name = new_name.trim().to_string();
    if new_name.is_empty() {
        return Err("文件夹名不能空着".into());
    }
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    tauri::async_runtime::spawn_blocking(move || {
        let folder = store
            .get_folder(folder_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个文件夹"))?;
        if folder.kind == FolderKind::Inbox {
            return Err("收件箱不能改名".into());
        }
        pool.with(folder.account_id, |conn| {
            SyncEngine::new(&store).rename_folder(conn, &folder, &new_name)
        })
        .map_err(e)?;
        store
            .get_folder(folder_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个文件夹"))
    })
    .await
    .map_err(|err| err.to_string())?
}

/// 删文件夹，箱里的信一起删。收件箱不给删（RFC 3501 §6.3.4 明文禁止）。
///「真的要删吗」是前端的两步确认，这里只管动手。
#[tauri::command(rename_all = "snake_case")]
pub async fn delete_folder(state: State<'_, AppState>, folder_id: i64) -> Result<(), String> {
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    tauri::async_runtime::spawn_blocking(move || {
        let folder = store
            .get_folder(folder_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个文件夹"))?;
        if folder.kind == FolderKind::Inbox {
            return Err("收件箱不能删".into());
        }
        pool.with(folder.account_id, |conn| {
            SyncEngine::new(&store).delete_folder(conn, &folder)
        })
        .map_err(e)
    })
    .await
    .map_err(|err| err.to_string())?
}

// ================================================================= 同步

/// 一次文件夹同步的结果。
///
/// 刻意不直接暴露 [`mailway_core::sync::FolderSync`]：IPC 的形状归 IPC 层管
/// （同 [`OpenedMessage`]）。core 的内部类型改字段名，不该把前端一起带崩。
#[derive(serde::Serialize)]
pub struct FolderSyncInfo {
    pub folder_id: i64,
    pub imap_name: String,
    pub rebuilt: bool,
    pub fetched: u32,
    pub broken: u32,
    pub flags_changed: u32,
    pub total: u32,
}

impl From<mailway_core::sync::FolderSync> for FolderSyncInfo {
    fn from(f: mailway_core::sync::FolderSync) -> Self {
        FolderSyncInfo {
            folder_id: f.folder_id,
            imap_name: f.imap_name,
            rebuilt: f.rebuilt,
            fetched: f.fetched,
            broken: f.broken,
            flags_changed: f.flags_changed,
            total: f.total,
        }
    }
}

/// 一轮账号同步的汇总。
#[derive(serde::Serialize)]
pub struct SyncReport {
    pub folders: Vec<FolderSyncInfo>,
    pub fetched: u32,
    pub broken: u32,
    /// 有几个文件夹因为 UIDVALIDITY 变化被整箱重建
    pub rebuilt: u32,
}

impl SyncReport {
    fn from_outs(outs: Vec<mailway_core::sync::FolderSync>) -> Self {
        SyncReport {
            fetched: outs.iter().map(|o| o.fetched).sum(),
            broken: outs.iter().map(|o| o.broken).sum(),
            rebuilt: outs.iter().filter(|o| o.rebuilt).count() as u32,
            folders: outs.into_iter().map(Into::into).collect(),
        }
    }
}

/// 收信：把这个账号下所有**可选**的文件夹同步一遍。
///
/// 会真的连一次服务器，所以是**慢操作**（几百毫秒到几秒）。前端该转圈，
/// 不要拿它当列表刷新用 —— 列表刷新读本地库就行。
#[tauri::command(rename_all = "snake_case")]
pub async fn sync_account(state: State<'_, AppState>, account_id: i64) -> Result<SyncReport, String> {
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    tauri::async_runtime::spawn_blocking(move || {
        let account = store
            .get_account(account_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个账号"))?;
        // POP3 走自己的同步（UIDL 增量，没有文件夹/标志概念）
        if account.protocol == Protocol::Pop3 {
            let password = tokens::effective_secret(&store, &account)
                .map_err(e)?
                .ok_or_else(|| "还没有这个账号的授权码，去账号设置里填一下".to_string())?;
            let mut pop = mailway_core::pop3::Conn::for_account(&account, &password).map_err(e)?;
            let out = SyncEngine::new(&store).sync_pop3(&mut pop, account.id);
            pop.quit().ok();
            return Ok(SyncReport::from_outs(vec![out.map_err(e)?]));
        }
        let outs = pool
            .with(account.id, |conn| {
                SyncEngine::new(&store).sync_account(conn, account.id)
            })
            .map_err(e)?;
        Ok(SyncReport::from_outs(outs))
    })
    .await
    .map_err(|err| err.to_string())?
}

/// 只同步一个文件夹。
#[tauri::command(rename_all = "snake_case")]
pub async fn sync_folder(state: State<'_, AppState>, folder_id: i64) -> Result<FolderSyncInfo, String> {
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    tauri::async_runtime::spawn_blocking(move || {
        let folder = store
            .get_folder(folder_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个文件夹"))?;
        // POP3：没有「单个服务器文件夹」可同步，整账号一轮（只会新增）
        let account = store
            .get_account(folder.account_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个账号"))?;
        if account.protocol == Protocol::Pop3 {
            let password = tokens::effective_secret(&store, &account)
                .map_err(e)?
                .ok_or_else(|| "还没有这个账号的授权码，去账号设置里填一下".to_string())?;
            let mut pop = mailway_core::pop3::Conn::for_account(&account, &password).map_err(e)?;
            let out = SyncEngine::new(&store).sync_pop3(&mut pop, account.id);
            pop.quit().ok();
            return Ok(out.map_err(e)?.into());
        }
        let out = pool
            .with(folder.account_id, |conn| {
                SyncEngine::new(&store).sync_folder(conn, folder.account_id, &folder)
            })
            .map_err(e)?;
        Ok(out.into())
    })
    .await
    .map_err(|err| err.to_string())?
}

/// 只拉回这个文件夹的标志（已读 / 星标），**不取正文**。
///
/// 「在手机上标了已读，电脑上还是未读」点一下就对上。返回被改动的封数。
#[tauri::command(rename_all = "snake_case")]
pub async fn refresh_folder_flags(
    state: State<'_, AppState>,
    folder_id: i64,
) -> Result<u32, String> {
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    tauri::async_runtime::spawn_blocking(move || {
        let folder = store
            .get_folder(folder_id)
            .map_err(e)?
            .ok_or_else(|| not_found("这个文件夹"))?;
        pool.with(folder.account_id, |conn| {
            SyncEngine::new(&store).refresh_flags(conn, &folder)
        })
        .map_err(e)
    })
    .await
    .map_err(|err| err.to_string())?
}

/// 存（或换）一个账号的授权码。值进系统钥匙串，库里只留一个指路的 key。
#[tauri::command(rename_all = "snake_case")]
pub fn set_account_password(
    state: State<'_, AppState>,
    account_id: i64,
    password: String,
) -> Result<(), String> {
    let account = state
        .store
        .get_account(account_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这个账号"))?;
    secrets::set(&state.store, &account, &password).map_err(e)
}

/// 删掉一个账号，连同它在钥匙串里的授权码。
///
/// **先删钥匙串，再删库**：反过来库里那行没了，就拿不到 `keyring_key`，
/// 那条密码会永远留在别人的钥匙串里。删钥匙串失败不拦着删账号（那会把用户
/// 卡在一个删不掉的账号上），但要留日志 —— 那条密码还在。
#[tauri::command(rename_all = "snake_case")]
pub fn delete_account(state: State<'_, AppState>, account_id: i64) -> Result<(), String> {
    let account = state
        .store
        .get_account(account_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这个账号"))?;
    if let Err(err) = secrets::delete(&state.store, &account) {
        tracing::warn!(account_id, "钥匙串里的授权码没删干净: {}", err.user_message());
    }
    // 连接池里的闲置连接也丢掉 —— 账号都没了，留着一条已登录的连接没意义
    state.pool.invalidate(account_id);
    state.store.delete_account(account_id).map_err(e)
}

// ---------------------------------------------------------------- 同步的内部

/// 把标志推回服务器，放在后台线程里做。
fn push_flags_in_background(
    state: &State<'_, AppState>,
    message_id: i64,
    uid: u32,
    folder_id: i64,
    old: Flags,
    new: Flags,
) {
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    let spawned = std::thread::Builder::new()
        .name(format!("mailway-push-{message_id}"))
        .spawn(move || {
            if let Err(err) = push_flags(&store, &pool, folder_id, uid, &old, &new) {
                // `user_message()` 是固定的一句话，不会把密码或主机细节带出来
                tracing::warn!(message_id, folder_id, uid, "推标志失败: {}", err.user_message());
            }
        });
    if let Err(err) = spawned {
        tracing::warn!("起推标志线程失败: {err}");
    }
}

fn push_flags(
    store: &Store,
    pool: &ConnPool<Conn>,
    folder_id: i64,
    uid: u32,
    old: &Flags,
    new: &Flags,
) -> CoreResult<()> {
    let folder = store
        .get_folder(folder_id)?
        .ok_or_else(|| Error::Config("文件夹已不存在".into()))?;
    let account = store
        .get_account(folder.account_id)?
        .ok_or_else(|| Error::Config("账号已不存在".into()))?;
    if account.protocol == Protocol::Pop3 {
        return Ok(()); // POP3 没有服务器标志，已读/标星是纯本地概念
    }
    pool.with(account.id, |conn| {
        SyncEngine::new(store).push_flags(conn, &folder, uid, old, new)
    })
}

// ================================================================= 列表页

#[tauri::command(rename_all = "snake_case")]
pub fn list_messages(
    state: State<'_, AppState>,
    folder_id: i64,
    limit: u32,
    offset: u32,
) -> Result<Vec<MessageSummary>, String> {
    state.store.list_messages(folder_id, limit, offset).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn message_count(state: State<'_, AppState>, folder_id: i64) -> Result<u64, String> {
    state.store.count_messages(folder_id).map_err(e)
}

/// 智能箱 / 快捷文件夹：跨文件夹（可选跨账号）按谓词取摘要。
#[tauri::command(rename_all = "snake_case")]
pub fn list_smart(
    state: State<'_, AppState>,
    filter: String,
    account_id: Option<i64>,
) -> Result<Vec<MessageSummary>, String> {
    state.store.list_smart(&filter, account_id).map_err(e)
}

/// 侧栏各种计数一次查全（快捷文件夹 + 每文件夹/账号）。
#[tauri::command(rename_all = "snake_case")]
pub fn smart_counts(state: State<'_, AppState>) -> Result<SmartCounts, String> {
    state.store.smart_counts().map_err(e)
}

/// 所有账号的文件夹（侧栏账号树）。
#[tauri::command(rename_all = "snake_case")]
pub fn list_all_folders(state: State<'_, AppState>) -> Result<Vec<Folder>, String> {
    state.store.list_all_folders().map_err(e)
}

/// 会话聚合：取同一 `thread_key` 的所有信（跨文件夹，同账号）。
#[tauri::command(rename_all = "snake_case")]
pub fn thread_messages(
    state: State<'_, AppState>,
    account_id: i64,
    thread_key: String,
) -> Result<Vec<MessageSummary>, String> {
    state
        .store
        .thread_messages(account_id, &thread_key)
        .map_err(e)
}

// ================================================================= 通讯录（M4）

/// 新建/编辑联系人共用入参；带 `id` 是改，不带是新建。
#[derive(serde::Deserialize)]
pub struct ContactInput {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub note: String,
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_contacts(
    state: State<'_, AppState>,
    query: Option<String>,
) -> Result<Vec<Contact>, String> {
    state.store.list_contacts(query.as_deref()).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn save_contact(state: State<'_, AppState>, input: ContactInput) -> Result<i64, String> {
    match input.id {
        Some(id) => {
            let c = Contact {
                id,
                name: input.name,
                email: input.email,
                phone: input.phone,
                org: input.org,
                note: input.note,
                created_at: Default::default(),
                updated_at: Default::default(),
            };
            state.store.update_contact(&c).map_err(e)?;
            Ok(id)
        }
        None => state
            .store
            .create_contact(&NewContact {
                name: &input.name,
                email: &input.email,
                phone: &input.phone,
                org: &input.org,
                note: &input.note,
            })
            .map_err(e),
    }
}

#[tauri::command(rename_all = "snake_case")]
pub fn delete_contact(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.store.delete_contact(id).map_err(e)
}

// ================================================================= 日历（M4）

/// 新建/编辑事件共用入参；带 `id` 是改，不带是新建。
#[derive(serde::Deserialize)]
pub struct EventInput {
    pub id: Option<i64>,
    pub title: String,
    pub start: String,
    pub end: String,
    #[serde(default)]
    pub all_day: bool,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub reminder: String,
    #[serde(default)]
    pub repeat: String,
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_events(
    state: State<'_, AppState>,
    start: String,
    end: String,
) -> Result<Vec<Event>, String> {
    state.store.list_events_in_range(&start, &end).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn save_event(state: State<'_, AppState>, input: EventInput) -> Result<i64, String> {
    match input.id {
        Some(id) => {
            let ev = Event {
                id,
                title: input.title,
                start: input.start,
                end: input.end,
                all_day: input.all_day,
                location: input.location,
                note: input.note,
                reminder: input.reminder,
                repeat: input.repeat,
            };
            state.store.update_event(&ev).map_err(e)?;
            Ok(id)
        }
        None => state
            .store
            .create_event(&NewEvent {
                title: &input.title,
                start: &input.start,
                end: &input.end,
                all_day: input.all_day,
                location: &input.location,
                note: &input.note,
                reminder: &input.reminder,
                repeat: &input.repeat,
            })
            .map_err(e),
    }
}

#[tauri::command(rename_all = "snake_case")]
pub fn delete_event(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.store.delete_event(id).map_err(e)
}

// ============================================================= 域名自动配置（M6）

/// 邮箱域名 → IMAP/POP3/SMTP 服务器（前端加账号填表用）。字段同 `Security`。
#[derive(serde::Serialize)]
pub struct AutoConfig {
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub pop3_host: String,
    pub pop3_port: u16,
    pub pop3_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
}

/// 按邮箱域名猜收发服务器（公开 ISPDB/标准配置），查不到给通用亢底。
#[tauri::command(rename_all = "snake_case")]
pub fn autoconfig(email: String) -> Option<AutoConfig> {
    mailway_core::autoconfig::guess(&email).map(|c| AutoConfig {
        imap_host: c.imap_host,
        imap_port: c.imap_port,
        imap_security: c.imap_security,
        pop3_host: c.pop3_host,
        pop3_port: c.pop3_port,
        pop3_security: c.pop3_security,
        smtp_host: c.smtp_host,
        smtp_port: c.smtp_port,
        smtp_security: c.smtp_security,
    })
}

// ============================================================= 邮件模板（M6）

#[derive(serde::Deserialize)]
pub struct TemplateInput {
    pub id: Option<i64>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_templates(state: State<'_, AppState>) -> Result<Vec<Template>, String> {
    state.store.list_templates().map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn save_template(state: State<'_, AppState>, input: TemplateInput) -> Result<i64, String> {
    state
        .store
        .save_template(input.id, &input.name, &input.subject, &input.body)
        .map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn delete_template(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.store.delete_template(id).map_err(e)
}

/// Google 登录（应用内 webview 跳 Google 授权 → 回调取 code → 换 token）。
/// 凭据写死在 `google_oauth::CLIENT_ID/CLIENT_SECRET`，不走设置。建窗在主线程；
/// 这里 `spawn_blocking` 等 code，不阻塞主线程。
#[tauri::command(rename_all = "snake_case")]
pub async fn google_oauth_login(app: tauri::AppHandle) -> Result<crate::google_oauth::Token, String> {
    let r: Result<crate::google_oauth::Token, String> =
        tauri::async_runtime::spawn_blocking(move || crate::google_oauth::run_in_window(&app))
            .await
            .map_err(|e| e.to_string())?;
    r
}

// ============================================================= 设置（键值）

#[tauri::command(rename_all = "snake_case")]
pub fn get_setting(state: State<'_, AppState>, key: String) -> Result<Option<String>, String> {
    state.store.get_setting(&key).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn set_setting(state: State<'_, AppState>, key: String, value: String) -> Result<(), String> {
    state.store.set_setting(&key, &value).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn get_settings(state: State<'_, AppState>) -> Result<Vec<(String, String)>, String> {
    state.store.get_settings().map_err(e)
}

/// 全文搜索（主题 / 收发件人 / 正文），跨文件夹。**纯本地** —— 不连服务器，
/// 搜的是已经收下来的缓存。
///
/// 空查询（trim 后）返回空列表：「什么都没输」不是「什么都匹配」，
/// 不然手一抖整个库都涌进结果列表。
#[tauri::command(rename_all = "snake_case")]
pub fn search_messages(
    state: State<'_, AppState>,
    account_id: i64,
    query: String,
    limit: u32,
) -> Result<Vec<MessageSummary>, String> {
    let query = query.trim();
    if query.is_empty() {
        return Ok(Vec::new());
    }
    state
        .store
        .search_messages(account_id, query, limit)
        .map_err(e)
}

// ================================================================= 来信分类

/// 一个账号的规则，按执行顺序。
#[tauri::command(rename_all = "snake_case")]
pub fn list_rules(state: State<'_, AppState>, account_id: i64) -> Result<Vec<Rule>, String> {
    state.store.list_rules(account_id).map_err(e)
}

/// 新建规则。条件/动作的形状就是 `rules` 模块那套 JSON（前端直接拼）。
///
/// 守卫在这层：条件、动作至少各一个 —— 空条件的规则在匹配那边是「永不
/// 命中」（见 `rules::Rule::conditions` 的注释），让用户建一条永远不跑的
/// 规则只会让他以为功能坏了。
#[tauri::command(rename_all = "snake_case")]
pub fn create_rule(
    state: State<'_, AppState>,
    account_id: i64,
    name: String,
    conditions: Vec<Condition>,
    actions: Vec<Action>,
) -> Result<i64, String> {
    if conditions.is_empty() {
        return Err("规则至少要一个条件".into());
    }
    if actions.is_empty() {
        return Err("规则至少要一个动作".into());
    }
    state
        .store
        .insert_rule(account_id, name.trim(), &conditions, &actions)
        .map_err(e)
}

/// 开关一条规则。停用留着不删 —— 「先关掉试试」是常事。
#[tauri::command(rename_all = "snake_case")]
pub fn set_rule_enabled(
    state: State<'_, AppState>,
    rule_id: i64,
    enabled: bool,
) -> Result<(), String> {
    state.store.set_rule_enabled(rule_id, enabled).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn delete_rule(state: State<'_, AppState>, rule_id: i64) -> Result<(), String> {
    state.store.delete_rule(rule_id).map_err(e)
}

/// 改标志（已读 / 星标）。**本地先落库，随后在后台推回服务器。**
///
/// 推送必须放后台：一次 `UID STORE` 是一个网络来回，卡在 IPC 调用里会让
/// 点「已读」转圈好几秒。
///
/// 推失败只记日志，不回滚本地 —— 界面以本地为准，下一轮 `refresh_flags`
/// 会和服务器对齐。
///
/// ⚠️ 已知竞态（M1 接受）：如果推送还没到服务器、这边先来了一轮
/// `refresh_flags`，本地会被服务器的旧值盖掉。窗口约等于一个网络来回。
/// 彻底解决要上「本地改动脏标记」，推到 M2。
#[tauri::command(rename_all = "snake_case")]
pub fn set_message_flags(
    state: State<'_, AppState>,
    message_id: i64,
    flags: Flags,
) -> Result<(), String> {
    let stored = state
        .store
        .get_message_raw(message_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这封邮件"))?;
    let old = stored.summary.flags.clone();
    state.store.set_message_flags(message_id, &flags).map_err(e)?;
    push_flags_in_background(&state, message_id, stored.summary.uid, stored.summary.folder_id, old, flags);
    Ok(())
}

/// 置顶。**纯本地** —— IMAP 没有这个概念，所以没有「推回服务器」那半边，
/// 也没有 `set_message_flags` 那个推送竞态。
#[tauri::command(rename_all = "snake_case")]
pub fn set_message_pinned(
    state: State<'_, AppState>,
    message_id: i64,
    pinned: bool,
) -> Result<(), String> {
    state.store.set_message_pinned(message_id, pinned).map_err(e)
}

/// 标签，整份替换（前端手里就是整份名单）。同样纯本地。
#[tauri::command(rename_all = "snake_case")]
pub fn set_message_labels(
    state: State<'_, AppState>,
    message_id: i64,
    labels: Vec<String>,
) -> Result<(), String> {
    state.store.set_message_labels(message_id, &labels).map_err(e)
}

// ================================================================= 删信 / 全标已读

/// 整箱标已读。本地一条 UPDATE，推服务器放后台 —— 跟 [`set_message_flags`]
/// 一样的分工和理由（一个 `UID STORE` 是一个网络来回，卡在 IPC 里会让界面
/// 转圈）。返回改过的封数，前端好把未读计数归零。
///
/// 只推本地里**本来没读**的那些 uid，不会把还没收下来的新信顺手标已读。
#[tauri::command(rename_all = "snake_case")]
pub fn mark_folder_read(state: State<'_, AppState>, folder_id: i64) -> Result<u32, String> {
    let uids = state.store.mark_folder_read(folder_id).map_err(e)?;
    let n = uids.len() as u32;
    if !uids.is_empty() {
        push_seen_in_background(&state, folder_id, uids);
    }
    Ok(n)
}

fn push_seen_in_background(state: &State<'_, AppState>, folder_id: i64, uids: Vec<u32>) {
    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    let spawned = std::thread::Builder::new()
        .name(format!("mailway-seen-{folder_id}"))
        .spawn(move || {
            if let Err(err) = push_seen(&store, &pool, folder_id, &uids) {
                tracing::warn!(folder_id, "整箱标已读推服务器失败: {}", err.user_message());
            }
        });
    if let Err(err) = spawned {
        tracing::warn!("起整箱标已读线程失败: {err}");
    }
}

/// 一批信一条 `UID STORE … \Seen` 推完 —— 不按封推，一个来回的事。
fn push_seen(store: &Store, pool: &ConnPool<Conn>, folder_id: i64, uids: &[u32]) -> CoreResult<()> {
    let folder = store
        .get_folder(folder_id)?
        .ok_or_else(|| Error::Config("文件夹已不存在".into()))?;
    let account = store
        .get_account(folder.account_id)?
        .ok_or_else(|| Error::Config("账号已不存在".into()))?;
    if account.protocol == Protocol::Pop3 {
        return Ok(()); // 同 push_flags：POP3 标志纯本地
    }
    pool.with(account.id, |conn| {
        SyncEngine::new(store).push_seen(conn, &folder, uids)
    })
}

/// 删除一封信。
///
/// `permanent = false`：**挪去废纸篓**（服务器上真的 `UID MOVE`，别的客户端
/// 也看得见）。账号没有废纸篓箱、或者这封信本来就在废纸篓里，都退化成彻底
/// 删除 —— 信总得有个去处，没箱子可去就只能删。
///
/// `permanent = true`：服务器 EXPUNGE + 本地删行，哪儿都不留。
///
/// 本地行**先删**，服务器那半边放后台（跟推标志一个理由：不能卡 IPC）。挪
/// 废纸篓的信过一会儿会作为废纸篓里的信回来（后台顺手追平了废纸篓）—— 那
/// 不是「删丢了」，是它真的在废纸篓里。后台失败只记日志，下一轮同步会把真
/// 相带回来。
#[tauri::command(rename_all = "snake_case")]
pub fn delete_message(
    state: State<'_, AppState>,
    message_id: i64,
    permanent: bool,
) -> Result<(), String> {
    let stored = state
        .store
        .get_message_raw(message_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这封邮件"))?;
    let folder_id = stored.summary.folder_id;
    let uid = stored.summary.uid;
    let folder = state
        .store
        .get_folder(folder_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这个文件夹"))?;

    // POP3：删信就是删本地行 —— 服务器上「只拉不删」，DELE 一律不用
    if let Ok(Some(account)) = state.store.get_account(folder.account_id) {
        if account.protocol == Protocol::Pop3 {
            return state.store.delete_message(message_id).map_err(e);
        }
    }

    let trash_id = if permanent {
        None
    } else {
        state
            .store
            .list_folders(folder.account_id)
            .map_err(e)?
            .into_iter()
            .find(|f| f.kind == FolderKind::Trash && f.id != folder_id)
            .map(|f| f.id)
    };

    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    let spawned = match trash_id {
        Some(trash_id) => std::thread::Builder::new()
            .name(format!("mailway-move-{message_id}"))
            .spawn(move || {
                if let Err(err) = move_message_remote(&store, &pool, folder_id, trash_id, uid) {
                    tracing::warn!(message_id, folder_id, uid, "挪废纸篓失败: {}", err.user_message());
                }
            }),
        None => std::thread::Builder::new()
            .name(format!("mailway-del-{message_id}"))
            .spawn(move || {
                if let Err(err) = delete_message_remote(&store, &pool, folder_id, uid) {
                    tracing::warn!(message_id, folder_id, uid, "彻底删除推服务器失败: {}", err.user_message());
                }
            }),
    };
    if let Err(err) = spawned {
        tracing::warn!("起删信线程失败: {err}");
    }

    state.store.delete_message(message_id).map_err(e)
}

/// 「整理」= 把这封信挪到另一个文件夹。服务器端 `UID MOVE`（后台线程），
/// 本地先删行（目标箱靠后台追平重新出现），跟「挪废纸篓」一套路。
#[tauri::command(rename_all = "snake_case")]
pub fn move_message(
    state: State<'_, AppState>,
    message_id: i64,
    to_folder_id: i64,
) -> Result<(), String> {
    let stored = state
        .store
        .get_message_raw(message_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这封邮件"))?;
    let from_id = stored.summary.folder_id;
    let uid = stored.summary.uid;
    if from_id == to_folder_id {
        return Ok(());
    }
    let to_folder = state
        .store
        .get_folder(to_folder_id)
        .map_err(e)?
        .ok_or_else(|| not_found("目标文件夹"))?;
    // POP3：没有服务器文件夹，挪箱是纯本地的
    if let Ok(Some(account)) = state.store.get_account(to_folder.account_id) {
        if account.protocol == Protocol::Pop3 {
            return state.store.move_message_local(message_id, to_folder_id).map_err(e);
        }
    }

    let store = Arc::clone(&state.store);
    let pool = Arc::clone(&state.pool);
    std::thread::Builder::new()
        .name(format!("mailway-move-{message_id}"))
        .spawn(move || {
            if let Err(err) = move_message_remote(&store, &pool, from_id, to_folder_id, uid) {
                tracing::warn!(message_id, from_id, to_folder_id, uid, "挪箱失败: {}", err.user_message());
            }
        })
        .map_err(|err| format!("起挪箱线程失败: {err}"))?;

    state.store.delete_message(message_id).map_err(e)
}

fn move_message_remote(
    store: &Store,
    pool: &ConnPool<Conn>,
    from_id: i64,
    to_id: i64,
    uid: u32,
) -> CoreResult<()> {
    let from = store
        .get_folder(from_id)?
        .ok_or_else(|| Error::Config("源文件夹已不存在".into()))?;
    let to = store
        .get_folder(to_id)?
        .ok_or_else(|| Error::Config("目标文件夹已不存在".into()))?;
    let account = store
        .get_account(from.account_id)?
        .ok_or_else(|| Error::Config("账号已不存在".into()))?;
    // 挪箱 + 追平目标箱共用一条连接（挪完还要 SELECT 目标箱收一轮）
    pool.with(account.id, |conn| {
        let engine = SyncEngine::new(store);
        engine.move_message(conn, &from, uid, &to)?;
        // 挪完立刻把废纸篓追平 —— 用户点完删除切过去就该看得见，而不是
        // 等下一轮收信。失败不掩盖挪箱的结果，只是废纸篓晚点才出现。
        if let Err(err) = engine.sync_folder(conn, account.id, &to) {
            tracing::warn!(folder_id = to.id, "挪箱后追平目标箱失败: {}", err.user_message());
        }
        Ok(())
    })
}

fn delete_message_remote(store: &Store, pool: &ConnPool<Conn>, folder_id: i64, uid: u32) -> CoreResult<()> {
    let folder = store
        .get_folder(folder_id)?
        .ok_or_else(|| Error::Config("文件夹已不存在".into()))?;
    let account = store
        .get_account(folder.account_id)?
        .ok_or_else(|| Error::Config("账号已不存在".into()))?;
    pool.with(account.id, |conn| {
        SyncEngine::new(store).delete_message(conn, &folder, uid)
    })
}

// ================================================================= 阅读页

#[tauri::command(rename_all = "snake_case")]
pub fn allow_remote_images(state: State<'_, AppState>, message_id: i64) -> Result<(), String> {
    state
        .allowed_remote
        .lock()
        .map_err(|_| "内部状态已损坏".to_string())?
        .insert(message_id);
    Ok(())
}

/// 这一封现在显示的是什么图片策略。
#[tauri::command(rename_all = "snake_case")]
pub fn remote_image_policy(state: State<'_, AppState>, message_id: i64) -> RemoteImagePolicy {
    if state.remote_allowed(message_id) {
        RemoteImagePolicy::AllowOne
    } else {
        RemoteImagePolicy::Block
    }
}

/// 阅读页要的一封信。
///
/// 比 [`Message`] 多两个**界面策略**字段。放在这里而不是塞进 core 的领域
/// 模型，是因为「要不要显示远程图片」是界面决策，不是邮件的事实。
#[derive(serde::Serialize)]
pub struct OpenedMessage {
    #[serde(flatten)]
    pub message: Message,
    /// 被拦下的远程图片数。>0 就该出「显示图片」横幅。
    pub remote_image_count: usize,
    /// 当前策略（回显给前端，免得前端自己记一份）。
    pub remote_policy: RemoteImagePolicy,
}

/// 打开一封邮件：读原文 → 解析 → 净化 → 组装成前端要的 [`Message`]。
///
/// 三处刻意为之的地方：
///
/// 1. **净化发生在服务端**，不在前端。前端拿到的 `body_html` 已经可以直接
///    注入 webview，少一条「前端忘了净化」的路。
/// 2. **`cid:` → `data:` 的改写在 ammonia 管线内部**做（见
///    [`sanitize::sanitize_body`]），不留事后字符串替换的口子。
/// 3. **`has_attachments` 用解析后的真值**覆盖列表页那个头部猜测。列表页
///    只有 `BODY[HEADER]`，猜得对不对不重要；阅读页有原文，就该给准的。
#[tauri::command(rename_all = "snake_case")]
pub fn open_message(state: State<'_, AppState>, message_id: i64) -> Result<OpenedMessage, String> {
    let stored = state
        .store
        .get_message_raw(message_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这封邮件"))?;

    let raw = match &stored.raw_path {
        Some(p) => state.store.read_raw(p).map_err(e)?,
        None => Vec::new(),
    };

    let parsed = mime::parse_message(&raw).map_err(e)?;
    // 逐封豁免（看过一次的）或全局「总是显示远程图片」都算放行。
    let allow = state.remote_allowed(message_id)
        || state
            .store
            .get_setting("show_remote_images")
            .map(|v| v.as_deref() == Some("on"))
            .unwrap_or(false);

    // `cid` 借着 `parsed.attachments`，所以必须在把 attachments 挪走之前用完。
    let sanitized: SanitizedBody = {
        let cid = parsed.cid_map();
        match parsed.body_html.as_deref() {
            Some(html) => sanitize::sanitize_body(html, allow, &cid),
            None => SanitizedBody {
                html: String::new(),
                remote_image_count: 0,
                remote_allowed: allow,
            },
        }
    };

    let mut summary = stored.summary;
    summary.has_attachments = parsed.has_attachments();

    let attachments: Vec<Attachment> = parsed.attachments.into_iter().map(|a| a.meta).collect();

    let remote_image_count = sanitized.remote_image_count;
    let remote_policy = if sanitized.remote_allowed {
        RemoteImagePolicy::AllowOne
    } else {
        RemoteImagePolicy::Block
    };

    Ok(OpenedMessage {
        message: Message {
            summary,
            cc: parsed.cc,
            bcc: parsed.bcc,
            reply_to: parsed.reply_to,
            body_html: Some(sanitized.html),
            body_text: parsed.body_text,
            body_kind: parsed.body_kind,
            attachments,
            raw_headers: parsed.raw_headers,
        },
        remote_image_count,
        remote_policy,
    })
}

// ================================================================= 草稿

/// 前端送进来的草稿。
///
/// 附件内容用 base64 走（[`DraftAttachmentInput::content_base64`]），不用
/// `Vec<u8>`：Tauri 对二进制参数走哪条传输跟版本和前端写法都有关系，base64
/// 明确、可读，坏了也一眼看得出是编码问题。
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DraftInput {
    /// `None` = 新建。前端**不要**自己编 id。
    pub id: Option<i64>,
    pub account_id: i64,
    /// 自动保存的版本号，单调递增。语义见 [`Store::upsert_draft`]。
    pub rev: i64,
    pub subject: String,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub text: String,
    /// HTML 正文。纯文本信传 `None`。
    ///
    /// **这里不做净化。**这是用户自己写的正文，要原样发出去。净化是给
    /// 「别人发来的 HTML」用的（见 `mailway_core::sanitize`），两者不能混。
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    /// 全量：不在这个列表里的附件会被删掉。
    pub attachments: Vec<DraftAttachmentInput>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DraftAttachmentInput {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub content_id: Option<String>,
    /// base64 的内容。`None` = 和上次一样，别重写（附件动辄几 MB，
    /// 自动保存每次都传一遍纯属浪费）。
    pub content_base64: Option<String>,
}

/// 把撰写窗口里的这份存下来，返回库里那一行。
///
/// 抽出来是因为发信要用同一份：**发出去的和留底的必须是同一份**，
/// 不能「发的时候是这样、草稿里是那样」。
fn persist_draft(store: &Store, draft: &DraftInput) -> Result<Draft, String> {
    // 先把 base64 全解开，攒在 `Vec<Vec<u8>>` 里：`NewDraft` 借的是切片，
    // 这些字节必须比它活得久。
    let blobs: Vec<Vec<u8>> = draft
        .attachments
        .iter()
        .map(|a| match &a.content_base64 {
            Some(b64) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| e(Error::Compose("附件内容的 base64 解不开".into()))),
            None => Ok(Vec::new()),
        })
        .collect::<Result<_, _>>()?;

    let attachments: Vec<NewDraftAttachment<'_>> = draft
        .attachments
        .iter()
        .zip(&blobs)
        .map(|(a, blob)| NewDraftAttachment {
            id: &a.id,
            filename: &a.filename,
            mime_type: &a.mime_type,
            content_id: a.content_id.as_deref(),
            // `None` 就是 `None` —— 不能因为解出来是空的就当成「有内容」
            content: if a.content_base64.is_some() { Some(blob.as_slice()) } else { None },
        })
        .collect();

    let new = NewDraft {
        id: draft.id,
        account_id: draft.account_id,
        rev: draft.rev,
        subject: &draft.subject,
        to: &draft.to,
        cc: &draft.cc,
        bcc: &draft.bcc,
        text: &draft.text,
        html: draft.html.as_deref(),
        in_reply_to: draft.in_reply_to.as_deref(),
        references: &draft.references,
        attachments: &attachments,
    };

    let id = store.upsert_draft(&new).map_err(e)?;
    store.get_draft(id).map_err(e)?.ok_or_else(|| not_found("这封草稿"))
}

#[tauri::command(rename_all = "snake_case")]
pub fn save_draft(state: State<'_, AppState>, draft: DraftInput) -> Result<Draft, String> {
    persist_draft(&state.store, &draft)
}

#[tauri::command(rename_all = "snake_case")]
pub fn get_draft(state: State<'_, AppState>, draft_id: i64) -> Result<Option<Draft>, String> {
    state.store.get_draft(draft_id).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_drafts(
    state: State<'_, AppState>,
    account_id: i64,
) -> Result<Vec<DraftSummary>, String> {
    state.store.list_drafts(account_id).map_err(e)
}

#[tauri::command(rename_all = "snake_case")]
pub fn delete_draft(state: State<'_, AppState>, draft_id: i64) -> Result<(), String> {
    state.store.delete_draft(draft_id).map_err(e)
}

/// 读附件内容，base64。
///
/// 撰写窗口重开草稿时，正文里的内嵌图靠这个还原成 `data:`。附件内容不在
/// [`Draft`] 里 —— 那个是给列表页和自动保存用的，不该捎几 MB 上来。
#[tauri::command(rename_all = "snake_case")]
pub fn read_draft_attachment(
    state: State<'_, AppState>,
    draft_id: i64,
    attachment_id: String,
) -> Result<String, String> {
    let bytes = state
        .store
        .read_draft_attachment(draft_id, &attachment_id)
        .map_err(e)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// 改签名。签名是账号级设置，撰写窗口里就能改。
#[tauri::command(rename_all = "snake_case")]
pub fn set_account_signature(
    state: State<'_, AppState>,
    account_id: i64,
    signature: String,
) -> Result<Account, String> {
    state.store.set_account_signature(account_id, &signature).map_err(e)?;
    state.store.get_account(account_id).map_err(e)?.ok_or_else(|| not_found("这个账号"))
}

/// 改发件人姓名（= 显示名）。
#[tauri::command(rename_all = "snake_case")]
pub fn set_account_name(
    state: State<'_, AppState>,
    account_id: i64,
    name: String,
) -> Result<Account, String> {
    state.store.set_account_name(account_id, &name).map_err(e)?;
    state.store.get_account(account_id).map_err(e)?.ok_or_else(|| not_found("这个账号"))
}

/// 启/停用某个邮箱（停用 = 不参与收信）。
#[tauri::command(rename_all = "snake_case")]
pub fn set_account_enabled(
    state: State<'_, AppState>,
    account_id: i64,
    enabled: bool,
) -> Result<Account, String> {
    state.store.set_account_enabled(account_id, enabled).map_err(e)?;
    state.store.get_account(account_id).map_err(e)?.ok_or_else(|| not_found("这个账号"))
}

/// 在系统默认浏览器里打开链接（邮件正文里点 `<a>` 用）。
///
/// 正文是**不可信输入** —— scheme 白名单在这里再把一道（净化层已经拦过
/// `javascript:`/`data:`，纵深防御）：只放行 http/https/mailto。
#[tauri::command(rename_all = "snake_case")]
pub fn open_external_url(url: String) -> Result<(), String> {
    if !allowed_external_scheme(&url) {
        return Err("只在浏览器里打开 http/https 链接".to_string());
    }
    std::process::Command::new("xdg-open")
        .arg(&url)
        .spawn()
        .map_err(|err| format!("打开浏览器失败：{err}"))?;
    Ok(())
}

/// 外部打开只认这几个 scheme（防 `javascript:` / `data:` / `file:` 等）。
fn allowed_external_scheme(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_scheme_whitelist() {
        assert!(allowed_external_scheme("https://example.com/a"));
        assert!(allowed_external_scheme("HTTP://example.com"));
        assert!(allowed_external_scheme("mailto:a@b.com"));
        assert!(!allowed_external_scheme("javascript:alert(1)"));
        assert!(!allowed_external_scheme("data:text/html,<script>"));
        assert!(!allowed_external_scheme("file:///etc/passwd"));
        assert!(!allowed_external_scheme("vbscript:x"));
    }
}

/// 换授权码 / 重新写入 OAuth 令牌包（「重新登录 Google」用）。
/// 值只进钥匙串，库里只记位置（见 [`crate::secrets`]）。
#[tauri::command(rename_all = "snake_case")]
pub fn set_account_secret(
    state: State<'_, AppState>,
    account_id: i64,
    secret: String,
) -> Result<(), String> {
    let account = state
        .store
        .get_account(account_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这个账号"))?;
    secrets::set(&state.store, &account, &secret).map_err(e)
}

// ================================================================= 账号录入

/// 新建账号要填的东西。
///
/// **授权码只在这里过手**：进钥匙串，库里一个字都不留（见 [`crate::secrets`]）。
/// IMAP 和 SMTP 共用一个用户名 —— 两家服务器上的账号本来就是同一个邮箱。
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NewAccountInput {
    /// 显示名，也是发信时 `From:` 上那个名字
    pub name: String,
    pub email: String,
    /// 收信服务器（IMAP 或 POP3，看 `protocol`）
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
    /// IMAP / SMTP 共用的用户名
    pub username: String,
    /// 授权码（或 OAuth 令牌，看 `auth_type`）
    pub password: String,
    /// 登录方式：`password`（默认）或 `xoauth2`。
    pub auth_type: Option<String>,
    /// 收信协议：`imap`（默认）或 `pop3`。POP3 的收信服务器也填在
    /// `imap_host/port/security` 那一组里 —— 表单就一套收信字段。
    pub protocol: Option<String>,
}

/// 添加前的**真实服务器**登录测试：收信（IMAP 或 POP3）和发信（SMTP）都真的
/// 连一遍登录，不存任何东西。哪一步失败就报哪一步 —— 这就是「接上真实邮件
/// 服务器」的当场验收，不用等后台同步去撞。
#[tauri::command(rename_all = "snake_case")]
pub async fn test_account_login(input: NewAccountInput) -> Result<String, String> {
    // 真实网络登录（收发都试）—— 丢阻塞线程池，理由同 create_folder
    tauri::async_runtime::spawn_blocking(move || test_account_login_blocking(input))
        .await
        .map_err(|err| err.to_string())?
}

fn test_account_login_blocking(input: NewAccountInput) -> Result<String, String> {
    let is_oauth = input.auth_type.as_deref() == Some("xoauth2");

    // ---- 收信 -------------------------------------------------------
    let recv = match input.protocol.as_deref() {
        Some("pop3") => {
            let cfg = mailway_core::pop3::Config {
                host: input.imap_host.clone(),
                port: input.imap_port,
                security: input.imap_security,
                username: input.username.clone(),
            };
            let mut c = mailway_core::pop3::Conn::connect(&cfg, &input.password, is_oauth)
                .map_err(|err| format!("收信（POP3）失败：{}", err.user_message()))?;
            c.quit().ok();
            "POP3 收信登录成功"
        }
        _ => {
            let cfg = mailway_core::imap::Config {
                host: input.imap_host.clone(),
                port: input.imap_port,
                security: input.imap_security,
                username: input.username.clone(),
                default_folder: "INBOX".into(),
            };
            let mut c = Conn::connect(&cfg, &input.password, is_oauth)
                .map_err(|err| format!("收信（IMAP）失败：{}", err.user_message()))?;
            c.logout().ok();
            "IMAP 收信登录成功"
        }
    };

    // ---- 发信 -------------------------------------------------------
    let scfg = mailway_core::smtp::Config {
        host: input.smtp_host.clone(),
        port: input.smtp_port,
        security: input.smtp_security,
        username: input.username.clone(),
    };
    let mut s = mailway_core::smtp::Conn::connect(&scfg, &input.password, is_oauth)
        .map_err(|err| format!("发信（SMTP）失败：{}", err.user_message()))?;
    s.quit().ok();

    Ok(format!("{recv}；SMTP 发信登录成功"))
}

#[tauri::command(rename_all = "snake_case")]
pub fn create_account(
    state: State<'_, AppState>,
    input: NewAccountInput,
) -> Result<Account, String> {
    let id = state
        .store
        .insert_account(&NewAccount {
            name: &input.name,
            email: &input.email,
            protocol: match input.protocol.as_deref() {
                Some("pop3") => Protocol::Pop3,
                _ => Protocol::Imap,
            },
            imap_host: &input.imap_host,
            imap_port: input.imap_port,
            imap_security: input.imap_security,
            imap_username: &input.username,
            smtp_host: &input.smtp_host,
            smtp_port: input.smtp_port,
            smtp_security: input.smtp_security,
            smtp_username: &input.username,
            signature: "",
            enabled: true,
            auth_type: input.auth_type.as_deref().unwrap_or("password"),
        })
        .map_err(e)?;
    let account = state
        .store
        .get_account(id)
        .map_err(e)?
        .ok_or_else(|| not_found("刚建的账号"))?;

    // 授权码**最后**存：库里那行得先在，`keyring_key` 才有地方指。反过来
    // （先钥匙串后库里）一旦第二步失败，那条密码就成了没人认领的孤儿。
    if let Err(err) = secrets::set(&state.store, &account, &input.password) {
        // 存不进去就别留半个账号 —— 留着它用户会以为能用，收信时报的却是
        // 「还没有授权码」，还以为是自己忘了填。
        let _ = state.store.delete_account(id);
        return Err(e(err));
    }
    Ok(account)
}

// ================================================================= 发信

/// 发一封信的结果。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SendResult {
    /// 发出去那封的 Message-ID（不含尖括号）。排错时拿它对服务器的记录。
    pub message_id: String,
    /// 存进「已发送」没有。`false` = 信**已经发出去了**，只是自己没留副本。
    pub saved_to_sent: bool,
    /// 草稿删掉了没有。**只有自己也留了副本才删** —— 没留副本的时候草稿
    /// 就是那唯一的副本，删了这封信就只剩对方那边有。
    pub draft_deleted: bool,
}

/// 发一封信。
///
/// 先把草稿存一遍再发：**发出去的和留底的必须是同一份**，不能发完才发现
/// 草稿里还是十分钟前的版本。收件人、正文、附件都从库里那一行读。
#[tauri::command(rename_all = "snake_case")]
pub async fn send_message(state: State<'_, AppState>, draft: DraftInput) -> Result<SendResult, String> {
    let store = Arc::clone(&state.store);
    // 发信 = SMTP + APPEND，秒级网络操作 —— 丢阻塞线程池，理由同 create_folder
    tauri::async_runtime::spawn_blocking(move || send_message_blocking(&store, draft))
        .await
        .map_err(|err| err.to_string())?
}

fn send_message_blocking(store: &Store, draft: DraftInput) -> Result<SendResult, String> {
    let draft = persist_draft(store, &draft)?;

    let account = store
        .get_account(draft.account_id)
        .map_err(e)?
        .ok_or_else(|| not_found("这个账号"))?;
    let password = tokens::effective_secret(store, &account)
        .map_err(e)?
        .ok_or_else(|| "还没有这个账号的授权码，去账号设置里填一下".to_string())?;

    // 「已发送」的 **IMAP 名字**（可能是 modified UTF-7），不是显示名。
    // 服务器上没这个文件夹时是 `None`，发信照发，只是不留副本。
    let sent_folder = store
        .list_folders(account.id)
        .map_err(e)?
        .into_iter()
        .find(|f| f.kind == FolderKind::Sent)
        .map(|f| f.imap_name);

    let composer = composer_from_draft(store, &account, &draft).map_err(e)?;
    let report =
        mailway_core::send::send_and_file(&account, &password, composer, sent_folder.as_deref())
            .map_err(e)?;

    // 只有自己也留了副本才删草稿。理由见 [`SendResult::draft_deleted`]。
    let draft_deleted = if report.saved_to_sent {
        match store.delete_draft(draft.id) {
            Ok(()) => true,
            Err(err) => {
                // 删不掉就留着：已发送里已经有副本了，多一份不碍事
                tracing::warn!(draft_id = draft.id, "信发完了，但草稿没删掉: {}", e(err));
                false
            }
        }
    } else {
        false
    };

    Ok(SendResult {
        message_id: report.message_id,
        saved_to_sent: report.saved_to_sent,
        draft_deleted,
    })
}

/// 草稿 → [`Composer`]。
///
/// 两件事只在发信这一刻做，草稿里平时不做：
///   - 正文里的 `data:` 内嵌图换成 `cid:` + 独立的 MIME 段
///     （[`compose::extract_inline_images`]）
///   - 签名拼到正文最后（[`Composer::build`] 自己做，这里只把它递过去）
fn composer_from_draft(store: &Store, account: &Account, draft: &Draft) -> CoreResult<Composer> {
    // 内嵌图只以 `data:` 的形式待在正文里（见 `compose.js` 的图片插入），
    // 不进附件列表 —— 所以下面那个循环不会和它重复。
    let (html, inline) = match &draft.html {
        Some(h) => {
            let (rewritten, imgs) = compose::extract_inline_images(h);
            (Some(rewritten), imgs)
        }
        None => (None, Vec::new()),
    };

    let mut attachments: Vec<OutAttachment> = inline;
    for a in &draft.attachments {
        attachments.push(OutAttachment {
            filename: a.filename.clone(),
            mime_type: a.mime_type.clone(),
            content: store.read_draft_attachment(draft.id, &a.id)?,
            content_id: a.content_id.clone(),
        });
    }

    let mut c = Composer::new(Mailbox {
        // 「名称」就是发信时 `From:` 上那个名字
        display: (!account.name.is_empty()).then(|| account.name.clone()),
        address: account.email.clone(),
    });
    c.to = draft.to.clone();
    c.cc = draft.cc.clone();
    c.bcc = draft.bcc.clone();
    c.subject = draft.subject.clone();
    c.in_reply_to = draft.in_reply_to.clone();
    c.references = draft.references.clone();
    c.text = draft.text.clone();
    c.html = html;
    c.signature = (!account.signature.is_empty()).then(|| account.signature.clone());
    c.attachments = attachments;
    Ok(c)
}

// ================================================================= 自检

/// 前端启动时先 ping 一下，确认 IPC 真的通了。
#[tauri::command(rename_all = "snake_case")]
pub fn core_ping() -> String {
    "pong".into()
}

#[tauri::command(rename_all = "snake_case")]
pub fn app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "mailway",
        "version": env!("CARGO_PKG_VERSION"),
    })
}
