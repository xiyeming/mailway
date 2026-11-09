//! 真实邮件服务器端到端测试。**默认跳过**（`#[ignore]`）——要凭据、要联网。
//!
//! 用法（凭据只从环境变量读，不落库、不落日志、不进版本库）：
//!
//! ```bash
//! MAILWAY_TEST_EMAIL=you@163.com MAILWAY_TEST_PASS=授权码 \
//!   cargo test -p mailway-core --test real_server -- --ignored --nocapture
//! ```
//!
//! 覆盖三件事：
//!   1. IMAP 真实登录 + 同步进内存库；
//!   2. POP3 真实登录 + UIDL 增量（第二轮不该重复收）；
//!   3. SMTP 发一封信给自己，轮询到它真的到了收件箱（完整收发闭环）。
//!
//! 收发服务器按 163/QQ 的公开配置写死在这里（测试就是测这两家），
//! 账号的用户名 = 邮箱地址。

use std::env;
use std::thread;
use std::time::Duration;

use mailway_core::compose::Composer;
use mailway_core::imap;
use mailway_core::pop3;
use mailway_core::smtp::{self, Envelope};
use mailway_core::store::{NewAccount, Store};
use mailway_core::sync::SyncEngine;
use mailway_core::types::{Mailbox, Protocol, Security};

fn creds() -> (String, String) {
    let email = env::var("MAILWAY_TEST_EMAIL").expect("需要 MAILWAY_TEST_EMAIL");
    let pass = env::var("MAILWAY_TEST_PASS").expect("需要 MAILWAY_TEST_PASS");
    (email, pass)
}

/// 按协议建一个账号行（收信服务器由参数给）。
fn insert(store: &Store, email: &str, protocol: Protocol, recv_host: &str, recv_port: u16) -> i64 {
    store
        .insert_account(&NewAccount {
            name: "真实测试",
            alias: "",
            email,
            protocol,
            imap_host: recv_host,
            imap_port: recv_port,
            imap_security: Security::Ssl,
            imap_username: email,
            smtp_host: "smtp.163.com",
            smtp_port: 465,
            smtp_security: Security::Ssl,
            smtp_username: email,
            signature: "",
            enabled: true,
            auth_type: "password",
        })
        .expect("建账号")
}

#[test]
#[ignore]
fn real_imap_sync() {
    let (email, pass) = creds();
    let store = Store::open_in_memory().unwrap();
    let account_id = insert(&store, &email, Protocol::Imap, "imap.163.com", 993);
    let account = store.get_account(account_id).unwrap().unwrap();

    let mut conn = imap::Conn::for_account(&account, &pass).expect("IMAP 登录应该成功");
    let outs = SyncEngine::new(&store)
        .sync_account(&mut conn, account_id)
        .expect("IMAP 同步");
    conn.logout().ok();

    let total: u32 = outs.iter().map(|o| o.total).sum();
    let fetched: u32 = outs.iter().map(|o| o.fetched).sum();
    println!("IMAP：同步了 {} 个文件夹，服务器信总数 {total}，本轮新收 {fetched}", outs.len());
    assert!(!outs.is_empty(), "至少该有收件箱");
}

#[test]
#[ignore]
fn real_pop3_sync_and_dedupe() {
    let (email, pass) = creds();
    let store = Store::open_in_memory().unwrap();
    let account_id = insert(&store, &email, Protocol::Pop3, "pop.163.com", 995);
    let account = store.get_account(account_id).unwrap().unwrap();

    let cfg = pop3::Config {
        host: "pop.163.com".into(),
        port: 995,
        security: Security::Ssl,
        username: email.clone(),
    };

    // 第一轮：把收件箱收下来
    let mut pop = pop3::Conn::connect(&cfg, &pass, false).expect("POP3 登录应该成功");
    let out1 = SyncEngine::new(&store).sync_pop3(&mut pop, account_id).expect("POP3 同步");
    pop.quit().ok();
    println!(
        "POP3 第一轮：服务器 {total} 封，新收 {fetched}，坏信 {broken}",
        total = out1.total,
        fetched = out1.fetched,
        broken = out1.broken
    );

    // 第二轮：UIDL 去重 —— 一封都不该重复收
    let mut pop = pop3::Conn::connect(&cfg, &pass, false).unwrap();
    let out2 = SyncEngine::new(&store).sync_pop3(&mut pop, account_id).unwrap();
    pop.quit().ok();
    println!("POP3 第二轮：新收 {}（UIDL 增量该是 0）", out2.fetched);
    assert_eq!(out2.fetched, 0, "第二轮重复收信，UIDL 增量失效");
    assert!(out1.total > 0, "收件箱不该是空的（先给自己发一封信）");
    let _ = account;
}

#[test]
#[ignore]
fn real_smtp_send_to_self_arrives() {
    let (email, pass) = creds();
    let marker = format!("Mailway 真实收发测试 {}", chrono::Utc::now().timestamp());

    // ---- 发：SMTP 发给自己 --------------------------------------------
    let mut conn = smtp::Conn::connect(
        &smtp::Config {
            host: "smtp.163.com".into(),
            port: 465,
            security: Security::Ssl,
            username: email.clone(),
        },
        &pass,
        false,
    )
    .expect("SMTP 登录应该成功");
    let mut composer = Composer::new(Mailbox {
        display: Some("Mailway 测试".into()),
        address: email.clone(),
    });
    composer.to.push(Mailbox {
        display: None,
        address: email.clone(),
    });
    composer.subject = marker.clone();
    composer.text = "这是一封 Mailway 真实服务器端到端测试信，收到即验证通过。".into();
    let raw = composer.build().expect("拼信");
    conn.send(
        &Envelope {
            from: email.clone(),
            to: vec![email.clone()],
        },
        &raw,
    )
    .expect("SMTP 发信");
    conn.quit().ok();
    println!("已发出：{marker}");

    // ---- 收：轮询 IMAP 直到它到（自投递一般几秒内）---------------------
    let store = Store::open_in_memory().unwrap();
    let account_id = insert(&store, &email, Protocol::Imap, "imap.163.com", 993);
    let account = store.get_account(account_id).unwrap().unwrap();
    for attempt in 0..24 {
        let mut conn = imap::Conn::for_account(&account, &pass).unwrap();
        let outs = SyncEngine::new(&store).sync_account(&mut conn, account_id).unwrap();
        conn.logout().ok();
        let fetched: u32 = outs.iter().map(|o| o.fetched).sum();
        // 在库里找带标记的那封
        // 在**所有文件夹**里找带标记的那封（163 给自己的信可能落在非收件箱）
        let folders = store.list_folders(account_id).unwrap();
        let mut found = false;
        if attempt == 0 {
            for f in &folders {
                let msgs = store.list_messages(f.id, 3, 0).unwrap();
                let subs: Vec<&str> = msgs.iter().map(|m| m.subject.as_str()).collect();
                println!("  [{}] n=? 最新3封: {:?}", f.display_name, subs);
            }
        }
        for f in &folders {
            let hits: Vec<String> = store
                .list_messages(f.id, 5000, 0)
                .unwrap()
                .iter()
                .filter(|m| m.subject.contains("Mailway") || m.subject.contains(&marker))
                .map(|m| m.subject.clone())
                .collect();
            if !hits.is_empty() {
                println!("  [{}] 命中: {:?}", f.display_name, hits);
                found = found || hits.iter().any(|s| s.contains(&marker));
            }
        }
        println!(
            "第 {} 轮：新收 {fetched}，已见标记信: {found}（共 {} 箱）",
            attempt + 1,
            folders.len()
        );
        if found {
            return;
        }
        thread::sleep(Duration::from_secs(5));
    }
    panic!("发出后 2 分钟还没在收件箱见到：{marker}");
}
