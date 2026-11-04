//! IMAP 层的集成测试
//!
//! 服务端实现在 `tests/support/mod.rs`，和 `tests/sync.rs` 共用。
//! 这里只测协议原语本身：登录、列目录、选箱、取信、改标志、IDLE。

#[macro_use]
mod support;

use std::thread;
use std::time::Duration;

use mailway_core::imap::{Config, Conn};
use mailway_core::types::Security;
use support::*;

fn cfg(addr: std::net::SocketAddr) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: addr.port(),
        security: Security::Plain,
        username: "me@example.com".into(),
        default_folder: "INBOX".into(),
    }
}

fn connect_ok(server: &FakeServer) -> Conn {
    Conn::connect(&cfg(server.addr), "good", false).expect("connect+login 应该成功")
}

// ================================================================= 测试

#[test]
fn login_ok_and_bad_password_maps_to_auth_error() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    assert!(conn.noop().is_ok());
    conn.logout().ok();

    let err = match Conn::connect(&cfg(s.addr), "wrong", false) {
        Err(e) => e,
        Ok(_) => panic!("错误密码不该登录成功"),
    };
    assert!(
        matches!(err, mailway_core::Error::ImapAuth(_)),
        "密码错必须是 ImapAuth，好让前端提示「检查账号和密码」，实际: {err:?}"
    );
}

/// 登出要干净收尾。
///
/// `* BYE` 后面没正文是不合语法的（RFC 3501 的 `text = 1*TEXT-CHAR`），
/// `imap-proto` 会报 `Invalid`，客户端就拿到「Unable to parse status
/// response」。假服务器一度就是这样，害得 `send::file_into_sent` 以为存副本
/// 失败了 —— 所以这里把「登出成功」钉住。
#[test]
fn logout_completes_cleanly() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.logout().expect("LOGOUT 该干净收尾");
}

#[test]
fn list_folders_decodes_modified_utf7_and_attributes() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);

    let folders = conn.list_folders().unwrap();
    assert_eq!(folders.len(), 3);

    assert_eq!(folders[0].imap_name, "INBOX");
    assert_eq!(folders[0].display_name, "INBOX");
    assert_eq!(folders[0].delimiter, Some('/'));
    assert!(!folders[0].noselect());

    // 不解码就是一串 base64 垃圾
    assert_eq!(folders[1].imap_name, "&XfJT0ZAB-");
    assert_eq!(folders[1].display_name, "已发送");

    assert_eq!(folders[2].display_name, "Archive");
    assert!(folders[2].noselect(), "\\Noselect 要认出来");
}

#[test]
fn select_reports_uidvalidity_and_rejects_missing_folder() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);

    let st = conn.select("INBOX").unwrap();
    assert_eq!(st.uid_validity, 1000);
    assert_eq!(st.uid_next, 4);
    assert_eq!(st.total, 3);
    // RFC 3501：UNSEEN 是**第一封未读信的序号**，不是未读总数。
    // `default_mails` 里第 1 封带 `\Seen`，第 2 封没有 —— 序号是 2。
    assert_eq!(st.unseen, Some(2), "UNSEEN 给的是序号，不是计数");

    let err = conn.select("nope").unwrap_err();
    assert!(matches!(err, mailway_core::Error::Imap(_)), "不存在的箱子: {err:?}");
}

#[test]
fn uid_fetch_meta_returns_headers_flags_and_dates() {
    let s = FakeServer::start();
    let mails = default_mails();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    let metas = conn.uid_fetch_meta("1:3").unwrap();
    assert_eq!(metas.len(), 3);

    assert_eq!(metas[0].uid, 1);
    assert!(metas[0].flags.seen);
    assert_eq!(metas[0].size.unwrap() as usize, mails[0].raw.len());
    assert_eq!(metas[0].internal_date.unwrap().timestamp(), 1475417182);

    // header 块能被 mime 层当一封信解析出来
    let parsed = mailway_core::mime::parse_message(&metas[0].raw_headers).unwrap();
    assert_eq!(parsed.subject, "第一封");
    assert_eq!(parsed.from[0].display.as_deref(), Some("张三"));

    // 只看头时给的是「可能有附件」的提示，够列表页画回形针
    assert!(!metas[0].has_attachments, "纯文本信不该有附件标记");
    assert!(metas[1].has_attachments, "multipart/mixed 该有附件标记");
    assert_eq!(
        mailway_core::mime::parse_message(&metas[1].raw_headers).unwrap().subject,
        "Report"
    );

    assert!(metas[2].flags.flagged);
    assert!(!metas[2].flags.seen);
}

#[test]
fn uid_fetch_raw_returns_full_message_without_marking_seen() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    let raw = conn.uid_fetch_raw(2).unwrap();
    let parsed = mailway_core::mime::parse_message(&raw).unwrap();
    assert_eq!(parsed.subject, "Report");
    assert_eq!(parsed.attachments[0].meta.filename, "a.pdf");
    assert!(parsed.has_attachments());

    // 取原文不该改已读 —— 检查发出去的命令是 BODY.PEEK[]
    let cmds = s.commands();
    assert!(
        cmds.iter().any(|c| c.contains("BODY.PEEK[]")),
        "必须用 BODY.PEEK[]，否则会误置 \\Seen: {cmds:?}"
    );
}

#[test]
fn uid_fetch_full_returns_body_and_meta_together() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    let full = conn.uid_fetch_full("1:3").unwrap();
    assert_eq!(full.len(), 3);

    let p = mailway_core::mime::parse_message(&full[1].raw).unwrap();
    assert_eq!(p.subject, "Report", "raw 应该是完整原文，不只是头");
    assert!(full[1].flags.seen == false);
    assert!(full[0].flags.seen);
    assert_eq!(full[2].flags.flagged, true);
}

#[test]
fn uid_fetch_flags_does_not_drag_bodies_along() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    let flags = conn.uid_fetch_flags("1:3").unwrap();
    assert_eq!(flags.len(), 3);
    assert!(flags[0].1.seen);
    assert!(!flags[1].1.seen);
    assert!(flags[2].1.flagged);

    // 只要标志就别把几百 KB 的正文也发过来
    let cmds = s.commands();
    let flag_cmd = cmds
        .iter()
        .find(|c| c.contains("UID FETCH") && c.contains("FLAGS") && !c.contains("BODY"))
        .unwrap_or_else(|| panic!("该有一条只取 FLAGS 的 FETCH: {cmds:?}"));
    assert!(!flag_cmd.contains("HEADER"), "{flag_cmd}");
}

#[test]
fn uid_store_flags_emits_plus_and_minus() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    conn.uid_store_flags("2", &["\\Seen"], &["\\Flagged"]).unwrap();

    let cmds = s.commands();
    assert!(
        cmds.iter().any(|c| c.contains("+FLAGS.SILENT (\\Seen)")),
        "置已读要发 +FLAGS: {cmds:?}"
    );
    assert!(
        cmds.iter().any(|c| c.contains("-FLAGS.SILENT (\\Flagged)")),
        "取消星标要发 -FLAGS: {cmds:?}"
    );
}

#[test]
fn idle_wait_reports_change_and_times_out_when_quiet() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    // 先确认安静时不误报
    assert!(!conn.idle_wait(Duration::from_millis(150)).unwrap(), "没变化就该超时返回 false");

    // 再确认能被 EXISTS 唤醒。conn 要搬进线程（idle_wait 借着 session），
    // 所以先 move 进去，测试线程只负责推送。
    let h = thread::spawn(move || conn.idle_wait(Duration::from_secs(5)));
    thread::sleep(Duration::from_millis(150));
    s.push_exists(4);
    assert!(h.join().unwrap().unwrap(), "有 EXISTS 就该返回 true");
}

#[test]
fn idle_flushes_exists_that_arrived_before_idle() {
    // EXISTS 先于 IDLE 到达也是常见的（同步引擎刚 SELECT 完就 idle）。
    // 服务端会缓存，进 IDLE 后立刻补发。
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    s.push_exists(9);
    thread::sleep(Duration::from_millis(50));
    assert!(conn.idle_wait(Duration::from_secs(5)).unwrap(), "补发的 EXISTS 也要能唤醒");
}

#[test]
fn concurrency_check_send_recv_is_sound() {
    // 这条只是占位，提醒后续加并发测试时保持 Send 边界
    fn assert_send<T: Send>() {}
    assert_send::<Conn>();
}

// ================================================================= 文件夹管理

/// 建 → 改名 → 删，一条路走到底。
///
/// 中文名要特意走过一轮 modified UTF-7：`Conn` 收人看的名字、自己编 wire，
/// LIST 回来再解回来 —— 这个来回不对，中文文件夹在界面上就是一串 base64。
#[test]
fn create_rename_delete_folder_round_trip() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);

    conn.create_folder("工作").expect("CREATE 该成功");
    let folders = conn.list_folders().unwrap();
    let created = folders.iter().find(|f| f.display_name == "工作").expect("LIST 里该有「工作」");
    assert_eq!(created.imap_name, mailway_core::imap::utf7::encode("工作"));
    assert!(!created.noselect(), "新建的箱子该能选");

    // 新箱子能选，而且是空的
    let st = conn.select(&created.imap_name).expect("SELECT 新箱子");
    assert_eq!(st.total, 0);

    conn.rename_folder("工作", "档案").expect("RENAME 该成功");
    let folders = conn.list_folders().unwrap();
    assert!(folders.iter().all(|f| f.display_name != "工作"), "旧名不该还在");
    assert!(folders.iter().any(|f| f.display_name == "档案"), "新名该出现");

    conn.delete_folder("档案").expect("DELETE 该成功");
    let folders = conn.list_folders().unwrap();
    assert!(folders.iter().all(|f| f.display_name != "档案"), "删完不该还在");

    // 箱子没了，SELECT 要报错，不能装作成功
    let err = conn.select(&mailway_core::imap::utf7::encode("档案")).unwrap_err();
    assert!(matches!(err, mailway_core::Error::Imap(_)), "选一个没了的箱子该报错: {err:?}");
    conn.logout().ok();
}

/// 改名之后信要跟着箱子走 —— 不跟的话「改个名信就丢了」，比改名失败吓人多了。
#[test]
fn renaming_a_folder_moves_the_mail_with_it() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);

    conn.create_folder("备忘").unwrap();
    conn
        .append(
            &mailway_core::imap::utf7::encode("备忘"),
            &[],
            "Subject: 一封\r\n\r\n正文\r\n",
        )
        .unwrap();
    conn.rename_folder("备忘", "备忘录").expect("RENAME 该成功");

    let st = conn.select(&mailway_core::imap::utf7::encode("备忘录")).expect("改名后的箱子还在");
    assert_eq!(st.total, 1, "信要跟着箱子走");
    let metas = conn.uid_fetch_meta("1:*").unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].uid, 1);
    conn.logout().ok();
}

/// 错误路径：已存在的建不了、没有的删/改不了、目标名被占了改不过去。
#[test]
fn folder_management_error_paths() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);

    assert!(conn.create_folder("INBOX").is_err(), "已存在的箱子不该建成功");
    assert!(conn.delete_folder("无中生有").is_err(), "没有的箱子不该删成功");
    assert!(conn.rename_folder("无中生有", "甲").is_err(), "没有的箱子不该改名成功");
    assert!(conn.rename_folder("Archive", "INBOX").is_err(), "改到已存在的名字该被拒");
    conn.logout().ok();
}

/// INBOX 不许改名、不许删。
///
/// 删是 RFC 3501 §6.3.4 明文禁止的；改名是「搬到新箱子、INBOX 清空」的特殊
/// 语义 —— 我们的客户端没有这个交互，发出去只会让人莫名其妙丢箱子。
#[test]
fn inbox_is_not_renamable_or_deletable() {
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);

    assert!(conn.rename_folder("INBOX", "收件箱备份").is_err());
    assert!(conn.delete_folder("INBOX").is_err());

    let folders = conn.list_folders().unwrap();
    assert!(folders.iter().any(|f| f.imap_name == "INBOX"), "INBOX 要安然无恙");
    conn.logout().ok();
}
