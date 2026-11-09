//! store 层测试
//!
//! 全部跑在内存库上，不碰磁盘（除了 raw 落盘那一组，用 tempdir）。

use chrono::Utc;
use mailway_core::rules::{Action, Condition, Field, Op};
use mailway_core::store::{
    NewAccount, NewDraft, NewDraftAttachment, NewFolder, NewMessage, Store,
};
use mailway_core::types::*;

fn sample_account() -> NewAccount<'static> {
    NewAccount {
        name: "工作",
        alias: "",
        email: "someone@example.com",
        protocol: Protocol::Imap,
        imap_host: "imap.example.com",
        imap_port: 993,
        imap_security: Security::Ssl,
        imap_username: "someone@example.com",
        smtp_host: "smtp.example.com",
        smtp_port: 587,
        smtp_security: Security::StartTls,
        smtp_username: "someone@example.com",
        signature: "—— 张三",
        enabled: true,
        auth_type: "password",
    }
}

#[test]
fn schema_init_is_idempotent() {
    let s = Store::open_in_memory().unwrap();
    // 再开一次同一个内存库不会重复建表（这里是新库，但 migrate 必须可重入）
    let conn = s.list_accounts().unwrap();
    assert!(conn.is_empty());
}

#[test]
fn account_crud() {
    let s = Store::open_in_memory().unwrap();
    let id = s.insert_account(&sample_account()).unwrap();
    assert!(id > 0);

    let all = s.list_accounts().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].email, "someone@example.com");
    assert_eq!(all[0].imap_security, Security::Ssl);
    assert_eq!(all[0].smtp_security, Security::StartTls);
    assert!(all[0].enabled);

    let one = s.get_account(id).unwrap().unwrap();
    assert_eq!(one.name, "工作");

    s.set_account_enabled(id, false).unwrap();
    assert!(!s.get_account(id).unwrap().unwrap().enabled);

    s.delete_account(id).unwrap();
    assert!(s.list_accounts().unwrap().is_empty());
}

#[test]
fn account_email_is_unique() {
    let s = Store::open_in_memory().unwrap();
    s.insert_account(&sample_account()).unwrap();
    assert!(s.insert_account(&sample_account()).is_err());
}

#[test]
fn secret_ref_roundtrip() {
    let s = Store::open_in_memory().unwrap();
    let id = s.insert_account(&sample_account()).unwrap();

    assert!(s.secret_ref(id).unwrap().is_none());
    s.set_secret_ref(id, "mailway/imap/someone@example.com").unwrap();
    assert_eq!(
        s.secret_ref(id).unwrap().as_deref(),
        Some("mailway/imap/someone@example.com")
    );

    // 覆盖写
    s.set_secret_ref(id, "changed").unwrap();
    assert_eq!(s.secret_ref(id).unwrap().as_deref(), Some("changed"));
}

#[test]
fn folder_upsert_is_idempotent_and_keeps_sync_state() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();

    let f = NewFolder {
        account_id: acc,
        imap_name: "INBOX",
        display_name: "收件箱",
        kind: FolderKind::Inbox,
        parent_id: None,
        delimiter: Some('/'),
        subscribed: true,
    };
    let id1 = s.upsert_folder(&f).unwrap();
    let id2 = s.upsert_folder(&f).unwrap();
    assert_eq!(id1, id2, "同一个 (account_id, imap_name) 必须幂等");

    // 记一次同步状态
    s.record_folder_sync_state(id1, 111, Some(50), Some(42)).unwrap();
    let got = s.get_folder(id1).unwrap().unwrap();
    assert_eq!(got.uid_validity, Some(111));
    assert_eq!(got.last_synced_uid, Some(42));

    // 再次 upsert（LIST 响应里没有这些字段）不能把同步状态抹掉
    s.upsert_folder(&f).unwrap();
    let got = s.get_folder(id1).unwrap().unwrap();
    assert_eq!(got.uid_validity, Some(111), "upsert 不得覆盖同步状态");
    assert_eq!(got.last_synced_uid, Some(42));
}

#[test]
fn renaming_a_folder_moves_the_row() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let id = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "Work",
            display_name: "工作",
            kind: FolderKind::Normal,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();
    s.record_folder_sync_state(id, 111, Some(5), Some(5)).unwrap();

    s.rename_folder(id, "Keep", "留档").unwrap();

    let got = s.get_folder(id).unwrap().unwrap();
    assert_eq!(got.imap_name, "Keep");
    assert_eq!(got.display_name, "留档");
    assert_eq!(got.uid_validity, Some(111), "改名不该动同步状态");

    // 改完名还是一行，不是两行：按新名字 upsert 必须落回同一行
    let id2 = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "Keep",
            display_name: "留档",
            kind: FolderKind::Normal,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();
    assert_eq!(id2, id);
    assert_eq!(s.list_folders(acc).unwrap().len(), 1, "一个箱子不能裂成两个");
}

#[test]
fn deleting_a_folder_takes_its_messages_with_it() {
    // `messages.folder_id` 是 ON DELETE CASCADE：服务器上箱子没了，本地缓存
    // 的信留着也只是幽灵 —— 列表里点得开、搜得着，却再也不可能更新。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "Temp",
            display_name: "临时",
            kind: FolderKind::Normal,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    fn mk<'a>(acc: i64, fid: i64) -> NewMessage<'a> {
        NewMessage {
            account_id: acc,
            folder_id: fid,
            uid: 1,
            message_id: "temp@example.com",
            subject: "在临时箱里",
            from: vec![],
            to: vec![],
            date: Some(Utc::now()),
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        }
    }
    s.upsert_message(&mk(acc, fid)).unwrap();
    assert_eq!(s.count_messages(fid).unwrap(), 1);

    s.delete_folder(fid).unwrap();

    assert!(s.get_folder(fid).unwrap().is_none(), "箱子该没了");
    assert_eq!(s.count_messages(fid).unwrap(), 0, "箱里的信该跟着走");
    assert!(s.get_message_by_uid(fid, 1).unwrap().is_none());
}

#[test]
fn uid_validity_change_requires_purge() {
    // 这是 IMAP 协议规定的：UIDVALIDITY 变了，旧 UID 不再唯一，
    // 继续用会张冠李戴。SyncEngine 判定后必须 purge。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    for uid in 1..=3 {
        s.upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid,
            message_id: &format!("m{uid}@example.com"),
            subject: &format!("邮件 {uid}"),
            from: vec![Mailbox { display: Some("张三".into()), address: "a@b.com".into() }],
            to: vec![],
            date: Some(Utc::now()),
            size: Some(100),
            flags: Flags::default(),
            has_attachments: false,
            preview: "预览",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();
    }
    assert_eq!(s.count_messages(fid).unwrap(), 3);

    let n = s.purge_folder_messages(fid).unwrap();
    assert_eq!(n, 3);
    assert_eq!(s.count_messages(fid).unwrap(), 0);
}

#[test]
fn message_upsert_is_idempotent_by_uid() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    // 闭包的返回类型带生命周期参数，编译器推不出来；写成具名函数更直白。
    fn mk<'a>(acc: i64, fid: i64, uid: u32, subject: &'a str, seen: bool) -> NewMessage<'a> {
        NewMessage {
            account_id: acc,
            folder_id: fid,
            uid,
            message_id: "same@example.com",
            subject,
            from: vec![],
            to: vec![],
            date: Some(Utc::now()),
            size: Some(1),
            flags: Flags { seen, ..Default::default() },
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        }
    }

    let id1 = s.upsert_message(&mk(acc, fid, 10, "第一版", false)).unwrap();
    let id2 = s.upsert_message(&mk(acc, fid, 10, "第二版", true)).unwrap();
    assert_eq!(id1, id2, "同一 UID 必须只有一行");
    assert_eq!(s.count_messages(fid).unwrap(), 1);

    let got = s.get_message_by_uid(fid, 10).unwrap().unwrap();
    assert_eq!(got.summary.subject, "第二版");
    assert!(got.summary.flags.seen);
}

#[test]
fn message_list_sorts_by_date_desc() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    // 故意乱序插入
    let days = [(3u32, 3i64), (1, 1), (2, 2)];
    for (uid, day) in days {
        s.upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid,
            message_id: &format!("m{uid}@x"),
            subject: &format!("第{day}天"),
            from: vec![],
            to: vec![],
            date: Some(Utc::now() - chrono::Duration::days(10 - day)),
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();
    }

    let list = s.list_messages(fid, 10, 0).unwrap();
    let subjects: Vec<_> = list.iter().map(|m| m.subject.as_str()).collect();
    assert_eq!(subjects, vec!["第3天", "第2天", "第1天"], "最新的在前");
}

#[test]
fn message_flags_update() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    let id = s
        .upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid: 1,
            message_id: "a@b",
            subject: "标题",
            from: vec![],
            to: vec![],
            date: None,
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();

    let f = Flags {
        seen: true,
        flagged: true,
        keywords: vec!["$Forwarded".into(), "Junk".into()],
        ..Default::default()
    };
    s.set_message_flags(id, &f).unwrap();

    let got = s.get_message_raw(id).unwrap().unwrap();
    assert!(got.summary.flags.seen);
    assert!(got.summary.flags.flagged);
    assert_eq!(got.summary.flags.keywords, vec!["$Forwarded", "Junk"]);
}

#[test]
fn a_pin_and_labels_survive_a_resync() {
    // 同步会对同一 (folder, uid) 反复 upsert。置顶和标签是**本地**状态，
    // 被服务器来的内容冲掉的话，用户钉一次顶丢一次顶 —— 所以
    // `upsert_message` 刻意不碰这两列，这条钉住那个决定。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    fn mk<'a>(acc: i64, fid: i64, uid: u32, subject: &'a str, seen: bool) -> NewMessage<'a> {
        NewMessage {
            account_id: acc,
            folder_id: fid,
            uid,
            message_id: "same@example.com",
            subject,
            from: vec![],
            to: vec![],
            date: Some(Utc::now()),
            size: Some(1),
            flags: Flags { seen, ..Default::default() },
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        }
    }

    let id = s.upsert_message(&mk(acc, fid, 7, "第一版", false)).unwrap();
    s.set_message_pinned(id, true).unwrap();
    s.set_message_labels(id, &["工作".into(), "重要".into()]).unwrap();

    // 同步又把这封取了一遍：服务器那头的内容有更新
    let id2 = s.upsert_message(&mk(acc, fid, 7, "第二版", true)).unwrap();
    assert_eq!(id, id2, "同一 UID 必须还是同一行");

    let got = s.get_message_raw(id).unwrap().unwrap();
    assert_eq!(got.summary.subject, "第二版", "服务器来的新内容要收下");
    assert!(got.summary.flags.seen, "标志也是服务器说了算");
    assert!(got.summary.pinned, "但置顶是本地的，不能被冲掉");
    assert_eq!(got.summary.labels, vec!["工作", "重要"], "标签也不能被冲掉");
}

#[test]
fn pinned_messages_come_first() {
    // 置顶的意义就是「一直在最上面」：一封上个月的信钉了顶，
    // 也得压过今天的 —— 所以排序是 pinned 优先，日期在后。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    for (uid, day) in [(1u32, 1i64), (2, 2), (3, 3)] {
        s.upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid,
            message_id: &format!("m{uid}@x"),
            subject: &format!("第{day}天"),
            from: vec![],
            to: vec![],
            date: Some(Utc::now() - chrono::Duration::days(10 - day)),
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();
    }

    let oldest = s.list_messages(fid, 10, 0).unwrap().last().unwrap().id;
    s.set_message_pinned(oldest, true).unwrap();

    let list = s.list_messages(fid, 10, 0).unwrap();
    assert_eq!(list[0].id, oldest, "钉了顶的排第一");
    assert!(list[0].pinned);

    // 取消置顶就回到按日期排
    s.set_message_pinned(oldest, false).unwrap();
    let list = s.list_messages(fid, 10, 0).unwrap();
    assert_eq!(list.last().unwrap().id, oldest, "取消置顶后回到时间线里");
}

#[test]
fn labels_are_replaced_not_merged() {
    // 和 `flags_keywords` 一样是整份替换：前端手里就是整份名单，
    // 「往里加」和「删一个」都得由它算好再存，不然两边会各算各的。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    let id = s
        .upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid: 1,
            message_id: "a@b",
            subject: "标题",
            from: vec![],
            to: vec![],
            date: None,
            size: None,
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();

    s.set_message_labels(id, &["工作".into(), "重要".into()]).unwrap();
    let got = s.get_message_raw(id).unwrap().unwrap();
    assert_eq!(got.summary.labels, vec!["工作", "重要"]);

    s.set_message_labels(id, &["重要".into()]).unwrap();
    let got = s.get_message_raw(id).unwrap().unwrap();
    assert_eq!(got.summary.labels, vec!["重要"], "整份替换，不是往里加");

    s.set_message_labels(id, &[]).unwrap();
    let got = s.get_message_raw(id).unwrap().unwrap();
    assert!(got.summary.labels.is_empty(), "清空也是一次替换");
}

#[test]
fn raw_write_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    let raw = b"From: a@b\r\nSubject: hi\r\n\r\nbody";
    let rel = s.write_raw(acc, fid, 7, raw).unwrap();
    assert!(!rel.is_absolute(), "库里存的是相对路径，换机器搬家才不会失效");

    let back = s.read_raw(&rel).unwrap();
    assert_eq!(back, raw);

    // 关联到邮件
    let id = s
        .upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid: 7,
            message_id: "x@y",
            subject: "hi",
            from: vec![],
            to: vec![],
            date: None,
            size: Some(raw.len() as u64),
            flags: Flags::default(),
            has_attachments: false,
            preview: "body",
            body_text: None,
            received_at: Utc::now(),
            raw_path: Some(&rel),
        })
        .unwrap();
    let got = s.get_message_raw(id).unwrap().unwrap();
    assert_eq!(got.raw_path.as_deref(), Some(rel.as_path()));
}

#[test]
fn mailboxes_json_roundtrip() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    let from = vec![
        Mailbox { display: Some("张三".into()), address: "a@b.com".into() },
        Mailbox { display: None, address: "c@d.com".into() },
    ];
    s.upsert_message(&NewMessage {
        account_id: acc,
        folder_id: fid,
        uid: 1,
        message_id: "m@x",
        subject: "",
        from: from.clone(),
        to: vec![],
        date: None,
        size: None,
        flags: Flags::default(),
        has_attachments: false,
        preview: "",
        body_text: None,
        received_at: Utc::now(),
        raw_path: None,
    })
    .unwrap();

    let got = s.get_message_by_uid(fid, 1).unwrap().unwrap();
    assert_eq!(got.summary.from, from);
    assert_eq!(got.summary.from[0].to_string(), "张三 <a@b.com>");
    assert_eq!(got.summary.from[1].to_string(), "c@d.com");
}

#[test]
fn security_flag_mapping_matches_server_cfg() {
    // 原版 data/server.cfg 用 flag 1/2/3。这里保证映射一致，
    // 以后做「按域名自动配置」时直接复用。
    assert_eq!(Security::from_server_cfg_flag(1), Some(Security::Plain));
    assert_eq!(Security::from_server_cfg_flag(2), Some(Security::Ssl));
    assert_eq!(Security::from_server_cfg_flag(3), Some(Security::StartTls));
    assert_eq!(Security::from_server_cfg_flag(9), None);
}

// ================================================================= 草稿

/// 草稿会往磁盘写附件，所以**不能用 `open_in_memory`**：它的根目录是
/// `$TMPDIR/mailway-test-<pid>`，同一个进程里几个用例共用，附件会互相覆盖
/// （这个坑 `tests/sync.rs` 踩过一次）。
fn temp_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

fn draft<'a>(account_id: i64, rev: i64, subject: &'a str, text: &'a str) -> NewDraft<'a> {
    NewDraft {
        id: None,
        account_id,
        rev,
        subject,
        to: &[],
        cc: &[],
        bcc: &[],
        text,
        html: None,
        in_reply_to: None,
        references: &[],
        attachments: &[],
    }
}

fn att<'a>(id: &'a str, content: Option<&'a [u8]>) -> NewDraftAttachment<'a> {
    NewDraftAttachment {
        id,
        filename: "报告.pdf",
        mime_type: "application/pdf",
        content_id: None,
        content,
    }
}

#[test]
fn draft_roundtrips_the_whole_composer_state() {
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let to = vec![Mailbox { display: Some("李四".into()), address: "lisi@x".into() }];
    let cc = vec![Mailbox { display: None, address: "cc@x".into() }];
    let bcc = vec![Mailbox { display: None, address: "bcc@x".into() }];
    let refs = vec!["m1@x".to_string(), "m2@x".to_string()];
    let mut d = draft(acc, 1, "标题", "正文");
    d.to = &to;
    d.cc = &cc;
    d.bcc = &bcc;
    d.references = &refs;
    d.html = Some("<p>正文</p>");
    d.in_reply_to = Some("m0@x");

    let id = s.upsert_draft(&d).unwrap();
    let got = s.get_draft(id).unwrap().unwrap();

    assert_eq!(got.subject, "标题");
    assert_eq!(got.text, "正文");
    assert_eq!(got.html.as_deref(), Some("<p>正文</p>"));
    assert_eq!(got.to, to);
    assert_eq!(got.cc, cc);
    assert_eq!(got.bcc, bcc, "密送也要存回来，不然重开草稿就少一个人");
    assert_eq!(got.references, refs);
    assert_eq!(got.in_reply_to.as_deref(), Some("m0@x"));
    assert_eq!(got.rev, 1);
    assert_eq!(got.account_id, acc);
    assert!(got.attachments.is_empty());
}

#[test]
fn an_older_autosave_never_clobbers_a_newer_one() {
    // 自动保存是「打字停下来就存一次」。两次保存可能在路上错开 —— 慢的那次
    // 后到。抹掉的是用户刚打的字，而这种 bug 复现不了，查起来极其难。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let id = s.upsert_draft(&draft(acc, 2, "新的", "刚打的")).unwrap();

    // 旧那份（rev 1）晚到了
    let mut old = draft(acc, 1, "旧的", "早先的");
    old.id = Some(id);
    let back = s.upsert_draft(&old).unwrap();

    assert_eq!(back, id, "返回的还是同一条草稿");
    let got = s.get_draft(id).unwrap().unwrap();
    assert_eq!(got.subject, "新的", "旧的保存不许盖掉新的");
    assert_eq!(got.text, "刚打的");
    assert_eq!(got.rev, 2, "版本号也不该被拉回去");
}

#[test]
fn a_newer_autosave_still_wins() {
    // 上一条的反面：rev 确实大了就得写进去，别把守卫写成「什么都不写」
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();
    let id = s.upsert_draft(&draft(acc, 1, "一稿", "一稿正文")).unwrap();

    let mut d = draft(acc, 2, "二稿", "二稿正文");
    d.id = Some(id);
    s.upsert_draft(&d).unwrap();

    let got = s.get_draft(id).unwrap().unwrap();
    assert_eq!(got.subject, "二稿");
    assert_eq!(got.rev, 2);
}

#[test]
fn attachment_content_is_not_resent_on_every_autosave() {
    // 附件动辄几 MB，自动保存每秒一次，每次都重写纯属浪费。前端只在**新拖
    // 进来**的时候给内容，之后传 `None`。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let first = vec![att("a1", Some(b"%PDF-1.4 original"))];
    let mut d = draft(acc, 1, "带附件", "正文");
    d.attachments = &first;
    let id = s.upsert_draft(&d).unwrap();

    // 又改了几个字，附件没动
    let again = vec![att("a1", None)];
    let mut d2 = draft(acc, 2, "带附件", "改过的正文");
    d2.id = Some(id);
    d2.attachments = &again;
    s.upsert_draft(&d2).unwrap();

    let got = s.get_draft(id).unwrap().unwrap();
    assert_eq!(got.text, "改过的正文");
    assert_eq!(got.attachments.len(), 1);
    assert_eq!(got.attachments[0].filename, "报告.pdf");
    assert_eq!(
        s.read_draft_attachment(id, "a1").unwrap(),
        b"%PDF-1.4 original".to_vec(),
        "内容没变就不该重写，更不该写成空的"
    );
}

#[test]
fn an_attachment_with_no_content_and_no_file_is_an_error() {
    // `content: None` 说的是「和上次一样」。磁盘上却没有 —— 那是状态坏了。
    // 静悄悄存一个空附件，用户发出去才发现，是最坏的结局。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let atts = vec![att("ghost", None)];
    let mut d = draft(acc, 1, "s", "t");
    d.attachments = &atts;
    assert!(s.upsert_draft(&d).is_err(), "该报错，不该存个空的");
    assert!(
        s.list_drafts(acc).unwrap().is_empty(),
        "保存失败就不该留半截草稿"
    );
}

#[test]
fn dropping_an_attachment_removes_its_file() {
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let two = vec![att("keep", Some(b"K")), att("drop", Some(b"D"))];
    let mut d = draft(acc, 1, "s", "t");
    d.attachments = &two;
    let id = s.upsert_draft(&d).unwrap();

    // 下一次保存只带 keep
    let one = vec![att("keep", None)];
    let mut d2 = draft(acc, 2, "s", "t2");
    d2.id = Some(id);
    d2.attachments = &one;
    s.upsert_draft(&d2).unwrap();

    let got = s.get_draft(id).unwrap().unwrap();
    assert_eq!(got.attachments.len(), 1);
    assert_eq!(got.attachments[0].id, "keep");
    assert_eq!(s.read_draft_attachment(id, "keep").unwrap(), b"K".to_vec());
    assert!(s.read_draft_attachment(id, "drop").is_err(), "删掉的附件不该还能读到");
}

#[test]
fn delete_draft_removes_the_files_too() {
    // 光删行会留孤儿文件。草稿删了磁盘就该干净。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let atts = vec![att("a1", Some(b"bytes"))];
    let mut d = draft(acc, 1, "s", "t");
    d.attachments = &atts;
    let id = s.upsert_draft(&d).unwrap();
    let dir = s.root().join("drafts").join(id.to_string());
    assert!(dir.exists(), "附件目录该在: {dir:?}");

    s.delete_draft(id).unwrap();

    assert!(s.get_draft(id).unwrap().is_none());
    assert!(!dir.exists(), "目录该跟着走: {dir:?}");
    assert!(s.list_drafts(acc).unwrap().is_empty());
}

#[test]
fn attachment_id_must_be_a_safe_filename() {
    // 附件 id 会变成磁盘上的文件名。放行 `../` 就是目录穿越 ——
    // 前端发过来的字符串直接拼进路径，是经典漏洞。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();
    let long = "x".repeat(65);

    for bad in ["../escape", "a/b", "a\\b", "", "a b", long.as_str(), "..", "."] {
        let atts = vec![att(bad, Some(b"x"))];
        let mut d = draft(acc, 1, "s", "t");
        d.attachments = &atts;
        assert!(s.upsert_draft(&d).is_err(), "{bad:?} 该被拒");
    }

    // 合法的照收
    for good in ["a1", "A-Z_09", &long[..64]] {
        let atts = vec![att(good, Some(b"x"))];
        let mut d = draft(acc, 1, "s", "t");
        d.attachments = &atts;
        assert!(s.upsert_draft(&d).is_ok(), "{good:?} 该被接受");
    }
}

#[test]
fn a_rejected_save_stores_nothing_at_all() {
    // 验 id 要在**动任何东西之前**做完。存到一半才发现某个附件 id 是 `../`，
    // 等于「这条草稿存了，但附件少了俩」。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let atts = vec![att("fine", Some(b"x")), att("../bad", Some(b"y"))];
    let mut d = draft(acc, 1, "s", "t");
    d.attachments = &atts;
    assert!(s.upsert_draft(&d).is_err());
    assert!(s.list_drafts(acc).unwrap().is_empty(), "半个都不该留下");
}

#[test]
fn saving_into_a_deleted_draft_recreates_it_instead_of_dropping_the_text() {
    // 草稿被删了，但自动保存还在跑（撰写窗口还开着）。把这一份丢掉等于丢用户
    // 刚打的字 —— 宁可让草稿「复活」。
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let mut d = draft(acc, 1, "s", "刚打的");
    d.id = Some(999);
    let id = s.upsert_draft(&d).unwrap();

    assert_eq!(id, 999, "还是那条，前端手里的 id 不用换");
    assert_eq!(s.get_draft(999).unwrap().unwrap().text, "刚打的");
}

#[test]
fn draft_listing_summarizes_without_bodies() {
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();

    let atts = vec![att("a1", Some(b"x"))];
    let long_body = "很长很长的正文".repeat(100);
    let mut d = draft(acc, 1, "带附件的", &long_body);
    d.attachments = &atts;
    let with_att = s.upsert_draft(&d).unwrap();
    s.upsert_draft(&draft(acc, 1, "空的", "")).unwrap();

    let list = s.list_drafts(acc).unwrap();
    assert_eq!(list.len(), 2);
    let a = list.iter().find(|x| x.id == with_att).unwrap();
    assert_eq!(a.subject, "带附件的");
    assert_eq!(a.attachment_count, 1);

    // 摘要就是摘要，别把正文捎上
    let json = serde_json::to_string(&list).unwrap();
    assert!(!json.contains("很长很长"), "列表别把正文带上: {json}");
}

#[test]
fn drafts_are_scoped_to_one_account() {
    let (_dir, s) = temp_store();
    let a = s.insert_account(&sample_account()).unwrap();
    let b = s
        .insert_account(&NewAccount {
            name: "另一个",
            alias: "",
            email: "other@example.com",
            ..sample_account()
        })
        .unwrap();

    s.upsert_draft(&draft(a, 1, "甲的", "")).unwrap();
    s.upsert_draft(&draft(b, 1, "乙的", "")).unwrap();

    let mine = s.list_drafts(a).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].subject, "甲的");
    assert_eq!(s.list_drafts(b).unwrap()[0].subject, "乙的");
}

#[test]
fn an_empty_draft_is_still_a_draft() {
    // 刚打开撰写窗口就崩掉，重开应该能看到那条空草稿，而不是什么都没有
    let (_dir, s) = temp_store();
    let acc = s.insert_account(&sample_account()).unwrap();
    let id = s.upsert_draft(&draft(acc, 1, "", "")).unwrap();
    let got = s.get_draft(id).unwrap().unwrap();
    assert_eq!(got.subject, "");
    assert_eq!(got.text, "");
    assert_eq!(got.html, None);
}

// ================================================================= 迁移

#[test]
fn opening_a_v1_database_upgrades_it_in_place() {
    // v1 的库里 accounts 没有 `signature` 列。用户升级程序打开老库，这一列
    // 必须自己长出来，而且**数据不能丢**。
    //
    // 这条测试存在的理由：迁移代码写完没人跑过一次真的老库，就只是一段
    // 看起来对的 SQL。改表是升级路径上最容易炸的地方，得有个真的老库压着。
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("mailway.db");

    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES ('version', '1');

            CREATE TABLE accounts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                email         TEXT    NOT NULL UNIQUE,
                protocol      TEXT    NOT NULL DEFAULT 'imap',
                imap_host     TEXT    NOT NULL,
                imap_port     INTEGER NOT NULL,
                imap_security TEXT    NOT NULL,
                imap_username TEXT    NOT NULL,
                smtp_host     TEXT    NOT NULL DEFAULT '',
                smtp_port     INTEGER NOT NULL DEFAULT 587,
                smtp_security TEXT    NOT NULL DEFAULT 'start_tls',
                smtp_username TEXT    NOT NULL DEFAULT '',
                enabled       INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT    NOT NULL
            );
            INSERT INTO accounts (name, email, protocol, imap_host, imap_port,
                                  imap_security, imap_username, created_at)
            VALUES ('老账号', 'old@example.com', 'imap', 'imap.old', 993,
                    'ssl', 'old@example.com', '2024-01-01T00:00:00Z');
            "#,
        )
        .unwrap();
    }

    let s = Store::open(dir.path()).unwrap();

    let all = s.list_accounts().unwrap();
    assert_eq!(all.len(), 1, "老账号得还在");
    assert_eq!(all[0].email, "old@example.com");
    assert_eq!(all[0].signature, "", "新列要有默认值，不是 NULL");

    // 迁移是幂等的：再开一次不能炸
    drop(s);
    let again = Store::open(dir.path()).unwrap();
    assert_eq!(again.list_accounts().unwrap().len(), 1);
}

// ================================================================= 搜索

/// 搜索测试用的一封信。`body` 是 `body_text` 那一列，`None` = 还没建索引。
fn search_msg<'a>(
    acc: i64,
    fid: i64,
    uid: u32,
    subject: &'a str,
    addr: &'a str,
    body: Option<&'a str>,
) -> NewMessage<'a> {
    NewMessage {
        account_id: acc,
        folder_id: fid,
        uid,
        message_id: "",
        subject,
        from: vec![Mailbox { display: None, address: addr.into() }],
        to: vec![],
        date: Some(Utc::now()),
        size: None,
        flags: Flags::default(),
        has_attachments: false,
        preview: "",
        body_text: body,
        received_at: Utc::now(),
        raw_path: None,
    }
}

fn search_uids(s: &Store, acc: i64, q: &str) -> Vec<u32> {
    let mut v: Vec<u32> = s
        .search_messages(acc, q, 50)
        .unwrap()
        .iter()
        .map(|m| m.uid)
        .collect();
    v.sort();
    v
}

#[test]
fn search_hits_subject_sender_and_body() {
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    s.upsert_message(&search_msg(acc, fid, 1, "季度报告", "boss@example.com",
        Some("附件里是上个季度的数字"))).unwrap();
    s.upsert_message(&search_msg(acc, fid, 2, "午饭", "colleague@example.com",
        Some("今天下午三点开会讨论"))).unwrap();
    s.upsert_message(&search_msg(acc, fid, 3, "自动通知", "noreply@example.com", None)).unwrap();

    assert_eq!(search_uids(&s, acc, "季度报告"), vec![1], "主题");
    assert_eq!(search_uids(&s, acc, "boss"), vec![1], "发件人地址");
    assert_eq!(search_uids(&s, acc, "开会"), vec![2], "正文里的中文子串");
    assert_eq!(search_uids(&s, acc, "上个季度"), vec![1], "正文");
    // 「季度」在 1 的主题和正文都出现 —— 一封信只进一次结果
    assert_eq!(search_uids(&s, acc, "季度"), vec![1]);
    assert!(search_uids(&s, acc, "不存在的词").is_empty());

    // body_text 是 NULL 的信：搜正文搜不着（没索引），主题/发件人照常
    assert_eq!(search_uids(&s, acc, "自动通知"), vec![3]);
    assert!(search_uids(&s, acc, "没有正文索引").is_empty());
}

#[test]
fn search_is_scoped_to_account_and_spans_folders() {
    let s = Store::open_in_memory().unwrap();
    let acc1 = s.insert_account(&sample_account()).unwrap();
    let acc2 = s
        .insert_account(&NewAccount { email: "other@example.com", ..sample_account() })
        .unwrap();

    let mk_folder = |acc: i64, name: &str| -> i64 {
        s.upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: name,
            display_name: name,
            kind: FolderKind::Normal,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap()
    };
    let f1 = mk_folder(acc1, "A箱");
    let f2 = mk_folder(acc1, "B箱");
    let g = mk_folder(acc2, "A箱");

    s.upsert_message(&search_msg(acc1, f1, 1, "同一封的样子", "x@example.com", Some("共享关键词"))).unwrap();
    s.upsert_message(&search_msg(acc1, f2, 2, "别的箱", "y@example.com", Some("共享关键词"))).unwrap();
    s.upsert_message(&search_msg(acc2, g, 1, "另一个账号", "z@example.com", Some("共享关键词"))).unwrap();

    // 跨文件夹：搜的是「这个账号收到过的」，不是「当前文件夹」
    assert_eq!(search_uids(&s, acc1, "共享关键词"), vec![1, 2]);
    // 不串账号：同名文件夹、同一个词，也只回自己的
    assert_eq!(search_uids(&s, acc2, "共享关键词"), vec![1]);
    assert_eq!(search_uids(&s, acc2, "别的箱").len(), 0);
}

#[test]
fn search_treats_like_wildcards_as_literals() {
    // 用户搜「100%」就是要找那两个字符，不是「100 后面跟什么都行」。
    // 不转义的话 `_` 尤其阴险：搜 `a_b` 会把 `axb` 也带出来。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    s.upsert_message(&search_msg(acc, fid, 1, "进度 100% 完成", "x@example.com", None)).unwrap();
    s.upsert_message(&search_msg(acc, fid, 2, "进度 100块完成", "x@example.com", None)).unwrap();
    s.upsert_message(&search_msg(acc, fid, 3, "a_b", "x@example.com", None)).unwrap();
    s.upsert_message(&search_msg(acc, fid, 4, "axb", "x@example.com", Some("路径 C:\\temp"))).unwrap();
    // 不转义反斜杠的话，搜 `a\b` 的 pattern 会把 `\b` 当「转义的 b」，命中这封
    s.upsert_message(&search_msg(acc, fid, 5, "ab", "x@example.com", None)).unwrap();

    assert_eq!(search_uids(&s, acc, "100%"), vec![1], "% 是字面量");
    assert_eq!(search_uids(&s, acc, "100_"), Vec::<u32>::new(), "_ 不当通配符");
    assert_eq!(search_uids(&s, acc, "a_b"), vec![3], "_ 是字面量");
    assert_eq!(search_uids(&s, acc, "a\\b"), Vec::<u32>::new(), "反斜杠不吞掉后面的字");
    assert_eq!(search_uids(&s, acc, "C:\\temp"), vec![4], "反斜杠本身是字面量");
}

// ================================================================= 来信分类

#[test]
fn rules_crud_round_trips_conditions_and_actions() {
    // 条件/动作存的是 JSON 列。坏 JSON 在 row_to_rule 里降级成空列表
    // （坏规则不做事，站安全的一边），所以这里验的是**好 JSON 得原样回来**。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();

    let id = s
        .insert_rule(
            acc,
            "老板来信",
            &[Condition {
                field: Field::From,
                op: Op::Contains,
                value: "boss@example.com".into(),
            }],
            &[
                Action::MarkRead,
                Action::MarkFlagged,
                Action::AddLabels { labels: vec!["工作".into(), "老板".into()] },
            ],
        )
        .unwrap();

    let rules = s.list_rules(acc).unwrap();
    assert_eq!(rules.len(), 1);
    let r = &rules[0];
    assert_eq!(r.id, id);
    assert_eq!(r.account_id, acc);
    assert_eq!(r.name, "老板来信");
    assert!(r.enabled, "新建的规则默认开");
    assert_eq!(
        r.conditions,
        vec![Condition {
            field: Field::From,
            op: Op::Contains,
            value: "boss@example.com".into()
        }]
    );
    assert_eq!(
        r.actions,
        vec![
            Action::MarkRead,
            Action::MarkFlagged,
            Action::AddLabels { labels: vec!["工作".into(), "老板".into()] },
        ]
    );

    // 停用开关来回切
    s.set_rule_enabled(id, false).unwrap();
    assert!(!s.list_rules(acc).unwrap()[0].enabled);
    s.set_rule_enabled(id, true).unwrap();
    assert!(s.list_rules(acc).unwrap()[0].enabled);

    // 按 ord 排：先建的在前；规则不串账号
    let other = s
        .insert_account(&NewAccount { email: "other@example.com", ..sample_account() })
        .unwrap();
    let id2 = s
        .insert_rule(
            acc,
            "第二条",
            &[Condition { field: Field::Subject, op: Op::Equals, value: "周报".into() }],
            &[Action::MarkRead],
        )
        .unwrap();
    let ids: Vec<i64> = s.list_rules(acc).unwrap().iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![id, id2]);
    assert!(s.list_rules(other).unwrap().is_empty(), "规则不串账号");

    // 删除只删这一条
    s.delete_rule(id).unwrap();
    let left = s.list_rules(acc).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, id2);
}

#[test]
fn mark_folder_read_only_touches_unread_and_reports_which() {
    // 「全标已读」的本地半边：一条 UPDATE，只碰没读过的，还把改过的 uid
    // 报出来给调用方推服务器 —— 推的范围就是改的范围，多推会把还没收下来
    // 的新信顺手标已读。
    let s = Store::open_in_memory().unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    for (uid, mid, subj, seen) in [
        (1u32, "m1@example.com", "邮件 1", true),
        (2, "m2@example.com", "邮件 2", false),
        (3, "m3@example.com", "邮件 3", false),
    ] {
        s.upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid,
            message_id: mid,
            subject: subj,
            from: vec![],
            to: vec![],
            date: Some(Utc::now()),
            size: Some(1),
            flags: Flags { seen, ..Flags::default() },
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: None,
        })
        .unwrap();
    }

    let uids = s.mark_folder_read(fid).unwrap();
    assert_eq!(uids, vec![2, 3], "只报原本没读的");
    assert!(s.mark_folder_read(fid).unwrap().is_empty(), "第二遍没得改");
    assert!(s.get_message_by_uid(fid, 2).unwrap().unwrap().summary.flags.seen);
    assert!(s.get_message_by_uid(fid, 3).unwrap().unwrap().summary.flags.seen);
}

#[test]
fn delete_message_drops_the_row_and_the_raw_file() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let acc = s.insert_account(&sample_account()).unwrap();
    let fid = s
        .upsert_folder(&NewFolder {
            account_id: acc,
            imap_name: "INBOX",
            display_name: "收件箱",
            kind: FolderKind::Inbox,
            parent_id: None,
            delimiter: Some('/'),
            subscribed: true,
        })
        .unwrap();

    // 原文文件是真实存在的（write_raw 的口径：raw_path 存相对 root 的路径）
    let rel = std::path::Path::new("mbox/1.eml");
    let abs = dir.path().join(rel);
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(&abs, b"From: a@b.com\r\n\r\nhi").unwrap();
    let id = s
        .upsert_message(&NewMessage {
            account_id: acc,
            folder_id: fid,
            uid: 1,
            message_id: "m1@example.com",
            subject: "要删的",
            from: vec![],
            to: vec![],
            date: Some(Utc::now()),
            size: Some(1),
            flags: Flags::default(),
            has_attachments: false,
            preview: "",
            body_text: None,
            received_at: Utc::now(),
            raw_path: Some(rel),
        })
        .unwrap();

    s.delete_message(id).unwrap();
    assert!(s.get_message_by_uid(fid, 1).unwrap().is_none(), "行该没了");
    assert!(!abs.exists(), "原文文件也该清掉");
}
