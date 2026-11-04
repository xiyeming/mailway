//! 同步引擎的集成测试
//!
//! 和 `tests/imap.rs` 共用 `tests/support/mod.rs` 里的假服务器。这里测的是
//! 「什么时候同步、同步哪些、写进哪个表」，不是协议本身：
//!
//!   * 首次同步收全 + 记水位线
//!   * 增量同步只收新信，不重下全文
//!   * RFC 3501 的 `n:*` 规则不会让最后一封被重复收
//!   * UIDVALIDITY 变了整箱重建
//!   * 坏信占位入库，不卡住整个文件夹
//!   * 标志双向同步（拉回 / 推出）
//!   * `\NoSelect` 的箱子跳过，语义猜测
//!   * 来信分类（挪箱 / 打标志 / 贴标签，只管收件箱）

#[macro_use]
mod support;

use std::net::SocketAddr;

use chrono::Utc;
use mailway_core::imap::{Config, Conn};
use mailway_core::rules::{Action, Condition, Field, Op};
use mailway_core::store::{NewAccount, NewFolder, NewMessage, Store};
use mailway_core::sync::{guess_folder_kind, reindex_bodies, SyncEngine};
use mailway_core::types::{Flags, Folder, FolderKind, Protocol, Security};
use support::*;

// ================================================================= 夹具

fn cfg(addr: SocketAddr) -> Config {
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

/// 一个空库。**不用 `open_in_memory`**：它的原文根目录是
/// `$TMPDIR/mailway-test-<pid>`，同一个测试进程里的多个用例共用它，
/// 而 account_id / folder_id 在每个内存库里都是 1 —— 原文路径会互相覆盖。
/// 用 `tempfile` 一人一个目录，才能真验「原文落盘」。
fn temp_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("建临时目录");
    let store = Store::open(dir.path()).expect("开库");
    (dir, store)
}

fn seed_account(store: &Store) -> i64 {
    store
        .insert_account(&NewAccount {
            name: "测试",
            email: "me@example.com",
            protocol: Protocol::Imap,
            imap_host: "127.0.0.1",
            imap_port: 143,
            imap_security: Security::Plain,
            imap_username: "me@example.com",
            smtp_host: "",
            smtp_port: 587,
            smtp_security: Security::StartTls,
            smtp_username: "",
            signature: "",
            enabled: true,
            auth_type: "password",
        })
        .expect("建账号")
}

/// 建一个**还没同步过**的文件夹（uid_validity / last_synced_uid 都是 NULL）。
///
/// 返回的 `Folder` 之后**故意不刷新**：调用方手里那份快照就是旧的，是真实
/// 使用的样子（前端 state 里存着一份，反复拿去同步）。`sync_folder` 必须
/// 自己回库里读水位线，不然增量算错。这条踩过。
fn seed_folder(store: &Store, account_id: i64, imap_name: &str, kind: FolderKind) -> Folder {
    let id = store
        .upsert_folder(&NewFolder {
            account_id,
            imap_name,
            display_name: imap_name,
            kind,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .expect("建文件夹");
    store.get_folder(id).expect("查文件夹").expect("刚建的该查得到")
}

/// 一封能正常解析的新信。
fn new_raw(n: u32) -> &'static str {
    match n {
        4 => "From: c@example.com\r\n\
              To: me@example.com\r\n\
              Subject: 新来的\r\n\
              Date: Mon, 05 Oct 2016 12:00:00 +0000\r\n\
              Message-ID: <m4@example.com>\r\n\
              Content-Type: text/plain; charset=utf-8\r\n\
              \r\n\
              第四封\r\n",
        5 => "From: d@example.com\r\n\
              To: me@example.com\r\n\
              Subject: 又一封\r\n\
              Date: Tue, 06 Oct 2016 12:00:00 +0000\r\n\
              Message-ID: <m5@example.com>\r\n\
              Content-Type: text/plain; charset=utf-8\r\n\
              \r\n\
              第五封\r\n",
        _ => panic!("没准备 UID {n} 的夹具"),
    }
}

// ================================================================= 收信

#[test]
fn first_sync_pulls_everything_and_leaves_a_watermark() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);

    let out = SyncEngine::new(&store)
        .sync_folder(&mut conn, account_id, &folder)
        .unwrap();

    assert_eq!(out.fetched, 3, "三封信都该收到: {out:?}");
    assert_eq!(out.broken, 0);
    assert!(!out.rebuilt, "第一次同步不是重建");
    assert_eq!(out.total, 3);
    assert_eq!(store.count_messages(folder.id).unwrap(), 3);

    // 入库的是**解析后**的摘要，不是原文
    let m = store.get_message_by_uid(folder.id, 2).unwrap().unwrap();
    assert_eq!(m.summary.subject, "Report");
    assert!(m.summary.has_attachments, "multipart/mixed 该有附件标记");
    assert_eq!(m.summary.from[0].address, "boss@example.com");
    assert!(m.raw_path.is_some(), "原文必须落盘，解析坏了还能重算");

    // 水位线记到 3
    let f = store.get_folder(folder.id).unwrap().unwrap();
    assert_eq!(f.uid_validity, Some(1000));
    assert_eq!(f.uid_next, Some(4));
    assert_eq!(f.last_synced_uid, Some(3));
}

#[test]
fn second_sync_is_incremental_and_never_redownloads() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);
    let eng = SyncEngine::new(&store);

    assert_eq!(eng.sync_folder(&mut conn, account_id, &folder).unwrap().fetched, 3);

    s.push_mail(4, "", new_raw(4));
    let out = eng.sync_folder(&mut conn, account_id, &folder).unwrap();

    assert_eq!(out.fetched, 1, "只该收新的一封: {out:?}");
    assert_eq!(store.count_messages(folder.id).unwrap(), 4);
    assert_eq!(
        store.get_message_by_uid(folder.id, 4).unwrap().unwrap().summary.subject,
        "新来的"
    );

    // 增量的证据在命令里：UID 集从 4 开始，不是从 1
    let cmds = s.commands();
    let full = cmds
        .iter()
        .filter(|c| c.contains("UID FETCH") && c.contains("BODY.PEEK[]"))
        .collect::<Vec<_>>();
    assert_eq!(full.len(), 2, "两轮各取一次: {cmds:?}");
    assert!(
        full[1].contains("4:*"),
        "第二轮该从 UID 4 开始，实际: {}",
        full[1]
    );
}

#[test]
fn n_star_always_returns_the_last_message_but_sync_does_not_reingest_it() {
    // RFC 3501 §6.4.8：`n:*` **总是**包含信箱里 UID 最大的那一封，哪怕 `n`
    // 比它还大。所以第二轮同步的 `4:*` 会把 UID 3 也带回来 —— 引擎必须按
    // uid 过滤掉，否则每次同步都把最后一封重算一遍。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);
    let eng = SyncEngine::new(&store);

    assert_eq!(eng.sync_folder(&mut conn, account_id, &folder).unwrap().fetched, 3);
    let out = eng.sync_folder(&mut conn, account_id, &folder).unwrap();

    assert_eq!(out.fetched, 0, "没有新信就不该收: {out:?}");
    assert_eq!(out.broken, 0);
    assert_eq!(store.count_messages(folder.id).unwrap(), 3, "更不该出现重复行");
}

#[test]
fn fake_server_emulates_the_n_star_rule() {
    // 上一条能过，可能是「服务端压根没把 UID 3 发回来」。这条把夹具本身钉住：
    // 服务端确实发了，过滤是引擎的功劳。
    let s = FakeServer::start();
    let mut conn = connect_ok(&s);
    conn.select("INBOX").unwrap();

    let got = conn.uid_fetch_full("4:*").unwrap();
    assert_eq!(got.len(), 1, "RFC 3501：4:* 必须包含最后一封，实际 {got:?}");
    assert_eq!(got[0].uid, 3);
}

#[test]
fn uidvalidity_change_purges_and_rebuilds_the_folder() {
    // UIDVALIDITY 一变，旧的 UID↔本地行映射全部作废。不重建就会张冠李戴：
    // 新信箱里的 UID 2 可能是完全不同的一封信。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);
    let eng = SyncEngine::new(&store);

    eng.sync_folder(&mut conn, account_id, &folder).unwrap();
    let old_row = store.get_message_by_uid(folder.id, 1).unwrap().unwrap();
    assert_eq!(old_row.summary.subject, "第一封");

    s.set_uid_validity(2000);
    let out = eng.sync_folder(&mut conn, account_id, &folder).unwrap();

    assert!(out.rebuilt, "UIDVALIDITY 变了必须重建: {out:?}");
    assert_eq!(out.fetched, 3, "重建后整箱重新收");
    assert_eq!(store.count_messages(folder.id).unwrap(), 3, "不是加到 6");

    // 旧行必须真的被删掉了，不是「原地覆盖」—— 那样测不出 purge
    let new_row = store.get_message_by_uid(folder.id, 1).unwrap().unwrap();
    assert_ne!(
        new_row.summary.id, old_row.summary.id,
        "旧行该被删掉重建（AUTOINCREMENT 不复用 id）"
    );

    let f = store.get_folder(folder.id).unwrap().unwrap();
    assert_eq!(f.uid_validity, Some(2000));
    assert_eq!(f.last_synced_uid, Some(3));
}

// ================================================================= 坏信

#[test]
fn a_message_that_fails_to_parse_still_gets_a_row() {
    // 一封坏信不该让整个文件夹同步失败 —— 用户宁可看到一行「无法解析」，
    // 也不要整个收件箱空着。
    const BROKEN: &str = "\rX"; // 行首孤立 CR，mailparse 直接拒绝

    let s = FakeServer::start_with(
        vec![
            Canned {
                uid: 1,
                flags: "".into(),
                internal_date: "05-Oct-2016 12:00:00 +0000",
                raw: "From: a@example.com\r\nSubject: 好的\r\n\r\n正文\r\n",
            },
            Canned {
                uid: 2,
                flags: "".into(),
                internal_date: "05-Oct-2016 12:00:01 +0000",
                raw: BROKEN,
            },
            Canned {
                uid: 3,
                flags: "".into(),
                internal_date: "05-Oct-2016 12:00:02 +0000",
                raw: "From: c@example.com\r\nSubject: 后面的\r\n\r\n正文\r\n",
            },
        ],
        FakeCfg::default(),
    );
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);

    // 先确认夹具真的解析不了 —— 否则下面这条分支压根没跑到，
    // 测试会「绿」在一个没测到的东西上。
    assert!(
        mailway_core::mime::parse_message(BROKEN.as_bytes()).is_err(),
        "夹具必须是解析不了的，否则这条测试是空的"
    );

    let out = SyncEngine::new(&store)
        .sync_folder(&mut conn, account_id, &folder)
        .unwrap();

    assert_eq!(out.fetched, 3, "三封都入库: {out:?}");
    assert_eq!(out.broken, 1, "坏信要被数出来");
    assert_eq!(store.count_messages(folder.id).unwrap(), 3);

    let bad = store.get_message_by_uid(folder.id, 2).unwrap().unwrap();
    assert_eq!(bad.summary.subject, "（无法解析的邮件）");
    assert!(
        bad.raw_path.is_some(),
        "坏信的原文也要留着，将来修好解析器能重算"
    );

    // 好信没被坏信拖累
    assert_eq!(store.get_message_by_uid(folder.id, 3).unwrap().unwrap().summary.subject, "后面的");

    // 水位线也推过去了，不然下一轮又把坏信重收一遍
    let f = store.get_folder(folder.id).unwrap().unwrap();
    assert_eq!(f.last_synced_uid, Some(3));
}

// ================================================================= 标志

#[test]
fn refresh_flags_pulls_read_state_back_without_touching_the_watermark() {
    // 「在手机上标了已读，电脑上还是未读」就靠这个。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);
    let eng = SyncEngine::new(&store);
    eng.sync_folder(&mut conn, account_id, &folder).unwrap();

    s.set_flags(2, "\\Seen");
    s.set_flags(3, "");
    let changed = eng.refresh_flags(&mut conn, &folder).unwrap();

    assert_eq!(changed, 2, "两封的标志都变了");
    assert!(store.get_message_by_uid(folder.id, 2).unwrap().unwrap().summary.flags.seen);
    assert!(!store.get_message_by_uid(folder.id, 3).unwrap().unwrap().summary.flags.flagged);

    // 只是刷标志，不该动水位线 —— 那是「收到哪了」，不是「看到哪了」
    let f = store.get_folder(folder.id).unwrap().unwrap();
    assert_eq!(f.last_synced_uid, Some(3));

    // 更不该把正文拉下来
    let cmds = s.commands();
    let flag_fetch = cmds
        .iter()
        .rev()
        .find(|c| c.contains("UID FETCH"))
        .unwrap_or_else(|| panic!("该有一条 FETCH: {cmds:?}"));
    assert!(!flag_fetch.contains("BODY"), "刷标志不该拖正文: {flag_fetch}");
}

#[test]
fn push_flags_emits_only_the_diff_and_selects_the_folder_first() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);
    let eng = SyncEngine::new(&store);

    let old = Flags::default();
    let new = Flags {
        seen: true,
        flagged: true,
        ..Flags::default()
    };
    eng.push_flags(&mut conn, &folder, 2, &old, &new).unwrap();

    let cmds = s.commands();
    assert!(
        cmds.iter().any(|c| c.contains("+FLAGS.SILENT (\\Seen \\Flagged)")),
        "要发 +FLAGS，且只发变了的两个: {cmds:?}"
    );
    assert!(
        !cmds.iter().any(|c| c.contains("-FLAGS.SILENT")),
        "没被取消的标志不该发 -FLAGS: {cmds:?}"
    );

    // UID 只在**当前选中的箱子**里有意义，得先 SELECT，否则会写到别的文件夹去
    let sel = cmds
        .iter()
        .position(|c| c.contains("SELECT"))
        .unwrap_or_else(|| panic!("该先 SELECT: {cmds:?}"));
    let store_at = cmds
        .iter()
        .position(|c| c.contains("+FLAGS"))
        .expect("该有 STORE");
    assert!(sel < store_at, "SELECT 必须在 STORE 之前: {cmds:?}");
}

#[test]
fn push_flags_sends_nothing_when_nothing_changed() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);

    let flags = Flags { seen: true, ..Flags::default() };
    SyncEngine::new(&store)
        .push_flags(&mut conn, &folder, 2, &flags, &flags)
        .unwrap();

    let cmds = s.commands();
    assert!(
        !cmds.iter().any(|c| c.contains("FLAGS.SILENT")),
        "没有差异就一个字都别发: {cmds:?}"
    );
}

// ================================================================= 文件夹

#[test]
fn sync_account_creates_folders_and_skips_noselect() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let mut conn = connect_ok(&s);

    let outs = SyncEngine::new(&store).sync_account(&mut conn, account_id).unwrap();

    // Archive 带 \Noselect —— 只是层级容器，SELECT 会被服务器拒绝
    let folders = store.list_folders(account_id).unwrap();
    let names: Vec<&str> = folders.iter().map(|f| f.imap_name.as_str()).collect();
    assert_eq!(names, vec!["&XfJT0ZAB-", "INBOX"], "按 imap_name 排: {names:?}");
    assert!(!names.contains(&"Archive"), "\\NoSelect 的不该建出来");
    assert_eq!(outs.len(), 2, "两个可选箱子: {outs:?}");

    // 信箱之间互不相干：夹具那三封只在 INBOX，「已发送」是空的。
    // 一开始夹具把同一份信报给每个信箱，于是「已发送」里出现三封和收件箱
    // 一模一样的信 —— 看演示的人会以为同步串了信箱。
    let fetched_of = |name: &str| {
        outs.iter()
            .find(|o| o.imap_name == name)
            .unwrap_or_else(|| panic!("缺同步结果 {name}"))
            .fetched
    };
    assert_eq!(fetched_of("INBOX"), 3, "夹具三封都在 INBOX");
    assert_eq!(fetched_of("&XfJT0ZAB-"), 0, "别的信箱是空的，别把夹具倒进去");

    // 语义是猜出来的，侧栏排序靠它
    let kind_of = |name: &str| {
        folders
            .iter()
            .find(|f| f.imap_name == name)
            .unwrap_or_else(|| panic!("缺文件夹 {name}"))
            .kind
    };
    assert_eq!(kind_of("INBOX"), FolderKind::Inbox);
    assert_eq!(kind_of("&XfJT0ZAB-"), FolderKind::Sent, "modified UTF-7 解出来的「已发送」");
}

// ================================================================= 语义猜测

#[test]
fn folder_kind_is_guessed_not_parsed() {
    assert_eq!(guess_folder_kind("INBOX", "INBOX"), FolderKind::Inbox);
    assert_eq!(guess_folder_kind("&XfJT0ZAB-", "已发送"), FolderKind::Sent);
    assert_eq!(guess_folder_kind("[Gmail]/已发送", "已发送"), FolderKind::Sent);
    assert_eq!(guess_folder_kind("[Gmail]/Trash", "Trash"), FolderKind::Trash);
    assert_eq!(guess_folder_kind("Junk Mail", "Junk Mail"), FolderKind::Junk);
    assert_eq!(guess_folder_kind("Projects", "Projects"), FolderKind::Normal);

    // display_name 缺失时退回 imap_name —— LIST 只给一个名字是常见的
    assert_eq!(guess_folder_kind("Sent Items", ""), FolderKind::Sent);
    assert_eq!(guess_folder_kind("草稿箱", ""), FolderKind::Drafts);
}

// ================================================================= 文件夹管理

/// 建 → 装信 → 改名 → 删，全程「先服务器后本地」的一条路。
///
/// 钉住的是**两半的一致性**：服务器上做了什么、库里跟着是什么。改名必须
/// 走到同一行（不是裂成两行），删必须连信一起走（级联）。
#[test]
fn folder_management_round_trip() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let acc = seed_account(&store);
    let mut conn = connect_ok(&s);
    let engine = SyncEngine::new(&store);

    // 建：库里的行是 LIST 回读出来的，kind 按名字猜（「工作」→ 普通）
    let created = engine.create_folder(&mut conn, acc, "工作").expect("建箱子");
    assert_eq!(created.display_name, "工作");
    assert_eq!(created.kind, FolderKind::Normal);

    // 装封信进去再同步，改名才验得了「信跟着走」
    conn.append(
        &mailway_core::imap::utf7::encode("工作"),
        &[],
        "Subject: 一封\r\n\r\n正文\r\n",
    )
    .unwrap();
    engine.sync_folder(&mut conn, acc, &created).unwrap();
    assert_eq!(store.count_messages(created.id).unwrap(), 1);

    // 改名：还是同一行，名字换了，信还在
    engine.rename_folder(&mut conn, &created, "档案").expect("改名");
    let got = store.get_folder(created.id).unwrap().unwrap();
    assert_eq!(got.display_name, "档案");
    assert_eq!(got.imap_name, mailway_core::imap::utf7::encode("档案"));
    assert_eq!(store.count_messages(got.id).unwrap(), 1, "信不动 —— 换的是箱子名，不是箱子 id");
    let names: Vec<_> = store.list_folders(acc).unwrap().iter().map(|f| f.display_name.clone()).collect();
    assert!(!names.contains(&"工作".to_string()), "旧名不该还在库里");

    // 删：行和信一起走
    engine.delete_folder(&mut conn, &got).expect("删箱子");
    assert!(store.get_folder(created.id).unwrap().is_none());
    assert_eq!(store.count_messages(created.id).unwrap(), 0, "级联删，箱里的信一起走");
    conn.logout().ok();
}

// ================================================================= 搜索索引

#[test]
fn synced_bodies_are_searchable_right_away() {
    // 收信和建索引是同一趟活（ingest 直接把 body_text 写进库），
    // 不该出现「收完了还得等补索引才搜得着正文」的窗口。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);

    let eng = SyncEngine::new(&store);
    eng.sync_folder(&mut conn, account_id, &folder).unwrap();
    s.push_mail(4, "", new_raw(4));
    eng.sync_folder(&mut conn, account_id, &folder).unwrap();
    conn.logout().ok();

    // new_raw(4) 的正文是「第四封」——只有正文里有这个词
    let hits = store.search_messages(account_id, "第四封", 50).unwrap();
    assert_eq!(hits.len(), 1, "正文该进搜索索引: {hits:?}");
    assert_eq!(hits[0].subject, "新来的");

    // 补索引也别把已经好的重复补
    assert_eq!(reindex_bodies(&store).unwrap(), 0, "都建过索引了，没有要补的");
}

#[test]
fn reindex_bodies_backfills_old_messages_and_skips_lost_raws() {
    // 场景：v3 的库升到 v4 —— 信早收下来了，body_text 那一列是 NULL。
    // 不补的话升级前的信永远搜不着正文（增量同步不会重取旧信）。
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let folder = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);

    let raw = "Subject: 旧信\r\n\
               Content-Type: text/plain; charset=utf-8\r\n\
               \r\n\
               正文里有恐龙蛋这个词\r\n";
    let rel = store.write_raw(account_id, folder.id, 1, raw.as_bytes()).unwrap();
    store
        .upsert_message(&NewMessage {
            account_id,
            folder_id: folder.id,
            uid: 1,
            message_id: "",
            subject: "旧信",
            from: vec![],
            to: vec![],
            date: None,
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: Some(&rel),
        })
        .unwrap();

    // 原文已经丢了的信：补不了，但不能卡住别人、也不能瞎写个「没正文」
    store
        .upsert_message(&NewMessage {
            account_id,
            folder_id: folder.id,
            uid: 2,
            message_id: "",
            subject: "丢了原文",
            from: vec![],
            to: vec![],
            date: None,
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: Some(std::path::Path::new("raw/9/9/2.eml")),
        })
        .unwrap();

    assert!(store.search_messages(account_id, "恐龙蛋", 50).unwrap().is_empty(), "补之前搜不着正文");

    assert_eq!(reindex_bodies(&store).unwrap(), 1, "只有原文在的那封补得成");

    let hits = store.search_messages(account_id, "恐龙蛋", 50).unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].subject, "旧信");
    // 主题那一列一直在，不受补索引影响
    assert_eq!(store.search_messages(account_id, "旧信", 50).unwrap().len(), 1);

    // 再跑一遍：补成 0 条（剩下的都是原文丢了、补不了的），不报错、不重复
    assert_eq!(reindex_bodies(&store).unwrap(), 0);
    assert_eq!(store.search_messages(account_id, "恐龙蛋", 50).unwrap().len(), 1);
}

// ================================================================= 来信分类

#[test]
fn rule_moves_matching_mail_and_target_folder_picks_it_up() {
    // 「老板的信自动进『老板』箱」：收件箱这边不留行，目标箱子当场接回来。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let target = seed_folder(&store, account_id, "&XfJT0ZAB-", FolderKind::Normal);
    store
        .insert_rule(
            account_id,
            "老板的信进老板箱",
            &[Condition { field: Field::From, op: Op::Contains, value: "boss@example.com".into() }],
            &[Action::Move { folder_id: target.id }],
        )
        .unwrap();

    let mut conn = connect_ok(&s);
    let out = SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();

    // 三封里只挪走 boss 那封（uid 2），另外两封照常入库
    assert_eq!(out.moved, 1, "boss 那封该被挪走");
    assert_eq!(out.fetched, 2, "挪走的不算收进来的");
    assert_eq!(store.count_messages(inbox.id).unwrap(), 2);
    assert!(store.get_message_by_uid(inbox.id, 2).unwrap().is_none(), "收件箱不该留行");

    // 走的是服务器端 UID MOVE（RFC 6851），目标得是 wire 名 —— 只改本地
    // 的话下一轮同步又把信拉回收件箱，裂成两份
    let cmds = s.commands();
    assert!(
        cmds.iter().any(|c| c.contains("UID MOVE 2 \"&XfJT0ZAB-\"")),
        "该发 UID MOVE 去 wire 名的目标箱: {cmds:?}"
    );

    // 目标箱子在 sync 第 4 步当场接回来。服务器按目标箱的 UIDNEXT 重发
    // UID —— 这封到了新箱就是 uid 1
    assert_eq!(store.count_messages(target.id).unwrap(), 1);
    let moved = store.get_message_by_uid(target.id, 1).unwrap().unwrap();
    assert_eq!(moved.summary.subject, "Report");
    conn.logout().ok();
}

#[test]
fn moved_mail_below_target_watermark_still_lands() {
    // 目标箱在**服务器上是空的**、本地水位线却停在前面（假服务器重启过、
    // 本地还留着旧状态就是这个样子）：挪过去的信在新箱里是 uid 1，比水位线
    // 小。`n:*` 的尾巴照样把它送回来，可收信循环不能当「已经收过的」跳过
    // —— 跳过的话挪走的信就永远接不回来。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let target = seed_folder(&store, account_id, "&XfJT0ZAB-", FolderKind::Normal);
    store
        .insert_rule(
            account_id,
            "boss 的信进目标箱",
            &[Condition { field: Field::From, op: Op::Contains, value: "boss@example.com".into() }],
            &[Action::Move { folder_id: target.id }],
        )
        .unwrap();
    // uid_validity 和假服务器一致（1000），只把水位线架空到 1
    store
        .record_folder_sync_state(target.id, 1000, Some(2), Some(1))
        .unwrap();

    let mut conn = connect_ok(&s);
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    conn.logout().ok();

    assert_eq!(store.count_messages(target.id).unwrap(), 1);
    let moved = store
        .get_message_by_uid(target.id, 1)
        .unwrap()
        .expect("水位线之下的新信也得落库");
    assert_eq!(moved.summary.subject, "Report");
}

#[test]
fn reused_uid_with_different_message_id_replaces_the_stale_row() {
    // 更狠的一种：服务器丢了状态又没换 UIDVALIDITY（假服务器重启就是这个
    // 样子），挪过去的信占了 uid 1，本地 uid 1 却还躺着**另一封**（上次
    // 服务器时代的行）。只比 uid 会把新信当「已经收过的」丢掉 —— 演示里
    // 「挪走的信接不回来」就是这么来的。拿 Message-ID 认信，认不上的就地
    // 换成服务器上那封。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let target = seed_folder(&store, account_id, "&XfJT0ZAB-", FolderKind::Normal);
    store
        .insert_rule(
            account_id,
            "boss 的信进目标箱",
            &[Condition { field: Field::From, op: Op::Contains, value: "boss@example.com".into() }],
            &[Action::Move { folder_id: target.id }],
        )
        .unwrap();
    // 本地 uid 1 躺着一封上个时代的信（假服务器重启前收的）
    store
        .upsert_message(&NewMessage {
            account_id,
            folder_id: target.id,
            uid: 1,
            message_id: "stale@example.com",
            subject: "上个时代的信",
            from: vec![],
            to: vec![],
            date: None,
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: Some(""),
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();
    store
        .record_folder_sync_state(target.id, 1000, Some(2), Some(1))
        .unwrap();

    let mut conn = connect_ok(&s);
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    conn.logout().ok();

    let got = store.get_message_by_uid(target.id, 1).unwrap().expect("uid 1 还在");
    assert_eq!(got.summary.subject, "Report", "占着 uid 的旧行该被换成服务器上那封");
    assert_ne!(got.summary.message_id, "stale@example.com");
}

#[test]
fn rule_marks_and_labels_at_ingest_and_pushes_flags_to_the_server() {
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    store
        .insert_rule(
            account_id,
            "报告标已读",
            &[Condition { field: Field::Subject, op: Op::Contains, value: "Report".into() }],
            &[
                Action::MarkRead,
                Action::AddLabels { labels: vec!["工作".into(), "待办".into()] },
            ],
        )
        .unwrap();

    let mut conn = connect_ok(&s);
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    conn.logout().ok();

    let got = store.get_message_by_uid(inbox.id, 2).unwrap().unwrap();
    assert!(got.summary.flags.seen, "规则说标已读");
    assert_eq!(got.summary.labels, vec!["工作".to_string(), "待办".to_string()], "标签纯本地");

    // 只改本地的话下一轮 refresh_flags 就把未读刷回来了 —— 得推回服务器
    let cmds = s.commands();
    assert!(
        cmds.iter().any(|c| c.contains("+FLAGS.SILENT (\\Seen)")),
        "标志得推回服务器: {cmds:?}"
    );

    // 不匹配的信一根手指都不碰：uid 3 保持加星、未读、没标签
    let other = store.get_message_by_uid(inbox.id, 3).unwrap().unwrap();
    assert!(other.summary.flags.flagged);
    assert!(!other.summary.flags.seen);
    assert!(other.summary.labels.is_empty());
}

#[test]
fn rule_pushes_flag_actions_before_the_move_so_they_travel_with_the_mail() {
    // 「老板的信挪进老板箱 + 标已读」一条规则搞定。标志得赶在 MOVE **之前**
    // 推：MOVE 把服务器上的标志一起带走，挪完这个 uid 就没了，再推找不着人。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let target = seed_folder(&store, account_id, "&XfJT0ZAB-", FolderKind::Normal);
    store
        .insert_rule(
            account_id,
            "老板的信进老板箱并标已读",
            &[Condition { field: Field::From, op: Op::Contains, value: "boss@example.com".into() }],
            &[Action::Move { folder_id: target.id }, Action::MarkRead],
        )
        .unwrap();

    let mut conn = connect_ok(&s);
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    conn.logout().ok();

    let cmds = s.commands();
    let pushed = cmds
        .iter()
        .position(|c| c.contains("+FLAGS.SILENT (\\Seen)"))
        .unwrap_or_else(|| panic!("标志该推回服务器: {cmds:?}"));
    let moved = cmds
        .iter()
        .position(|c| c.contains("UID MOVE 2"))
        .unwrap_or_else(|| panic!("该发 UID MOVE: {cmds:?}"));
    assert!(pushed < moved, "先推标志再挪箱: {cmds:?}");

    // \Seen 跟着信走 —— 新箱里的信是已读
    let got = store.get_message_by_uid(target.id, 1).unwrap().unwrap();
    assert!(got.summary.flags.seen, "标志该跟着信走");
}

#[test]
fn rules_do_not_touch_non_inbox_folders() {
    // 分类只管收件箱的**新信**：已发送是自己发出去的，再「分」一遍是搅乱
    // （rules 模块头注释）。这条钉的是 sync_folder 只在 Inbox kind 上载入规则。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let sent = seed_folder(&store, account_id, "&XfJT0ZAB-", FolderKind::Sent);
    store
        .insert_rule(
            account_id,
            "见 boss 就标已读",
            &[Condition { field: Field::From, op: Op::Contains, value: "boss@example.com".into() }],
            &[Action::MarkRead, Action::AddLabels { labels: vec!["不该有".into()] }],
        )
        .unwrap();

    let mut conn = connect_ok(&s);
    // 一封信直接 APPEND 进「已发送」—— 假服务器只给 INBOX 放夹具
    conn.append("&XfJT0ZAB-", &[], "From: boss@example.com\r\nSubject: 周报\r\n\r\n正文\r\n")
        .unwrap();
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &sent).unwrap();
    conn.logout().ok();

    let got = store.get_message_by_uid(sent.id, 1).unwrap().unwrap();
    assert!(!got.summary.flags.seen, "非收件箱不该吃规则");
    assert!(got.summary.labels.is_empty(), "标签也不该贴");
    let cmds = s.commands();
    assert!(
        !cmds.iter().any(|c| c.contains("FLAGS.SILENT")),
        "标志一个字都不该推: {cmds:?}"
    );
}

// ================================================================= 删信 / 挪箱

#[test]
fn user_move_puts_the_mail_on_the_server_and_the_target_picks_it_up() {
    // 界面上点「删除」= 挪去废纸篓。信要在**服务器上**真的换了箱（别的
    // 客户端也看得见），然后目标箱追平 —— 来信分类挪箱那套原语的用户操
    // 作版，区别只在谁触发、谁删本地行。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let trash = seed_folder(&store, account_id, "Trash", FolderKind::Trash);
    let mut conn = connect_ok(&s);
    // 废纸篓得先在服务器上存在（假服务器只播种 INBOX / 已发送 / Archive）
    conn.create_folder("Trash").unwrap();

    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    let doomed = store.get_message_by_uid(inbox.id, 2).unwrap().unwrap();

    SyncEngine::new(&store).move_message(&mut conn, &inbox, 2, &trash).unwrap();
    // 本地行的删除是 commands 的活儿（它还要管界面），这里照做
    store.delete_message(doomed.summary.id).unwrap();
    // 挪完追平废纸篓 —— 点完删除切过去就该看得见
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &trash).unwrap();

    let cmds = s.commands();
    assert!(
        cmds.iter().any(|c| c.contains("UID MOVE 2 \"Trash\"")),
        "该发 UID MOVE 去废纸篓: {cmds:?}"
    );
    assert_eq!(store.count_messages(trash.id).unwrap(), 1);
    let moved = store.get_message_by_uid(trash.id, 1).unwrap().unwrap();
    assert_eq!(moved.summary.subject, "Report", "到废纸篓的是 boss 那封");

    // 服务器上已经不在收件箱了 —— 再同步一轮不会诈尸
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    conn.logout().ok();
    assert_eq!(store.count_messages(inbox.id).unwrap(), 2, "删掉的不该回来");
}

#[test]
fn delete_message_expunges_it_on_the_server() {
    // 彻底删除：打 \Deleted 再 EXPUNGE，收件箱这边下一轮同步不再见它。
    let s = FakeServer::start();
    let (_dir, store) = temp_store();
    let account_id = seed_account(&store);
    let inbox = seed_folder(&store, account_id, "INBOX", FolderKind::Inbox);
    let mut conn = connect_ok(&s);

    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    let doomed = store.get_message_by_uid(inbox.id, 2).unwrap().unwrap();

    SyncEngine::new(&store).delete_message(&mut conn, &inbox, 2).unwrap();
    store.delete_message(doomed.summary.id).unwrap();

    let cmds = s.commands();
    let flagged = cmds
        .iter()
        .position(|c| c.contains("+FLAGS.SILENT (\\Deleted)"))
        .unwrap_or_else(|| panic!("该先打 \\Deleted: {cmds:?}"));
    let expunged = cmds
        .iter()
        .position(|c| c.contains("UID EXPUNGE 2"))
        .unwrap_or_else(|| panic!("该发 UID EXPUNGE: {cmds:?}"));
    assert!(flagged < expunged, "先标记再 EXPUNGE: {cmds:?}");

    // 下一轮同步不许诈尸
    SyncEngine::new(&store).sync_folder(&mut conn, account_id, &inbox).unwrap();
    conn.logout().ok();
    assert_eq!(store.count_messages(inbox.id).unwrap(), 2);
    assert!(store.get_message_by_uid(inbox.id, 2).unwrap().is_none());
}
