//! mailway —— Tauri 壳
//!
//! 这一层只做三件事：起窗口、把 IPC 命令转发给 `mailway-core`、把事件推给前端。
//! 业务逻辑一律放在 core，让它们能脱离 GUI 单测。
//!
//! 窗口约定（M0 实测得出，见 ../m0/M0-实测记录.md 第 4 节）：
//!   - `productName` = "mailway"，也就是 Wayland 的 app_id，必须稳定
//!   - 每个窗口的标题必须可预测、能正则匹配，**不能带动态内容**
//!   - GTK3 不发 `xdg_wm_dialog_v1`，弹窗区分只能靠标题

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod updater;
mod demo;
mod google_oauth;
mod secrets;
mod tokens;
mod pool;
mod worker;

use std::sync::Arc;

use tauri::Manager;

use commands::AppState;

/// 系统托盘（M5）：图标 + 「显示主窗口 / 退出」菜单。参考原版 `:/dark/tray/*.svg`
/// （收信 / 锁 / 退出 / 设置 / 显示主窗口）；这里先做最关键的「显示 / 退出」。
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let icon = match app.default_window_icon().cloned() {
        Some(i) => i,
        None => {
            tracing::warn!("缺默认托盘图标，跳过托盘");
            return Ok(());
        }
    };

    TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("Mailway")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mailway=info".into()),
        )
        .init();

    tauri::Builder::default()
        .setup(|app| {
            // 数据库放 app 数据目录，和窗口/配置分开：换主题不该动到邮件
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            tracing::info!("本地数据目录: {}", dir.display());

            let store = Arc::new(mailway_core::Store::open(&dir)?);
            // 代理装配：设置页「代理设置」存的配置，启动即生效（IMAP/POP3/SMTP 全走它）
            commands::apply_proxy_from_settings(&store);
            // 开发脚手架：MAILWAY_DEV_FAKE_IMAP=<端口> 时把账号指向本地假服务器。
            // 它会先建出账号，于是下面的 `seed` 那道「库里没账号才播种」的闸就关上了。
            demo::seed_fake_imap_account(&store)?;
            // 演示数据也是**开发脚手架**，得显式要（MAILWAY_DEV_DEMO=1）。默认就播
            // 的话，真用户第一次打开应用会凭空多出一个「示例邮箱」和五封写死的信，
            // 还以为自己收到了邮件 —— 那不是演示，那是骗人。
            if std::env::var_os("MAILWAY_DEV_DEMO").is_some() {
                demo::seed(&store)?;
            }

            // `AppState` 和后台线程共享同一个 Store（`Arc`），免得两边各开一个连接
            app.manage(AppState::new(Arc::clone(&store)));
            worker::spawn(app.handle().clone(), store);

            // 系统托盘（M5）：图标 + 「显示主窗口 / 退出」。关窗走托盘（见 on_window_event）。
            setup_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关窗 = 隐藏到托盘（M5）；设置里关了就直接退出。
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let to_tray = window
                    .app_handle()
                    .state::<commands::AppState>()
                    .store
                    .get_setting("close_to_tray")
                    .ok()
                    .flatten();
                if to_tray.as_deref() == Some("off") {
                    window.app_handle().exit(0);
                    return;
                }
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::core_ping,
            commands::list_accounts,
            commands::create_account,
            commands::set_account_secret,
            commands::save_attachment,
            commands::batch_set_flags,
            commands::batch_delete,
            commands::batch_move,
            commands::export_message,
            commands::app_version,
            commands::check_update,
            commands::download_update,
            commands::apply_update,
            commands::get_proxy_settings,
            commands::save_proxy_settings,
            commands::test_proxy,
            commands::send_test_notification,
            commands::get_translate_settings,
            commands::save_translate_settings,
            commands::translate_text,
            commands::list_system_fonts,
            commands::set_folder_remind,
            commands::set_folder_quick,
            commands::clear_folder_mails,
            commands::apply_rules_to_folder,
            commands::set_autostart,
            commands::autostart_status,
            commands::open_external_url,
            commands::test_account_login,
            commands::list_folders,
            commands::create_folder,
            commands::rename_folder,
            commands::delete_folder,
            commands::sync_account,
            commands::sync_folder,
            commands::refresh_folder_flags,
            commands::set_account_password,
            commands::set_account_signature,
            commands::set_account_name,
            commands::set_account_enabled,
            commands::delete_account,
            commands::save_draft,
            commands::get_draft,
            commands::list_drafts,
            commands::delete_draft,
            commands::read_draft_attachment,
            commands::send_message,
            commands::list_messages,
            commands::message_count,
            commands::list_smart,
            commands::smart_counts,
            commands::list_all_folders,
            commands::thread_messages,
            commands::list_contacts,
            commands::save_contact,
            commands::delete_contact,
            commands::list_events,
            commands::save_event,
            commands::delete_event,
            commands::autoconfig,
            commands::list_templates,
            commands::save_template,
            commands::delete_template,
            commands::get_setting,
            commands::set_setting,
            commands::get_settings,
            commands::google_oauth_login,
            commands::search_messages,
            commands::list_rules,
            commands::create_rule,
            commands::set_rule_enabled,
            commands::delete_rule,
            commands::set_message_flags,
            commands::set_message_pinned,
            commands::set_message_labels,
            commands::mark_folder_read,
            commands::delete_message,
            commands::move_message,
            commands::open_message,
            commands::allow_remote_images,
            commands::remote_image_policy,
        ])
        .run(tauri::generate_context!())
        .expect("error while running mailway");
}
