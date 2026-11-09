//! 发信编排的端到端测试
//!
//! [`mailway_core::send::send_and_file`] 做两件事：SMTP 送出去，再 APPEND 进
//! 「已发送」。这里用**两个假服务器**（[`FakeSmtp`] + [`FakeServer`]）把两步都
//! 接住，然后比字节 —— 「已发送」里落的原文必须和对方收到的一字不差。存进去
//! 的信还得**取**得回来：假服务器把它当信箱里的一封存着，不是记一笔流水账。
//!
//! 最要紧的一条不在成功路径上：**APPEND 失败不能算发送失败**。谎报的后果是
//! 用户再点一次「发送」，对方收到两封 —— 比自己少个副本严重得多。所以
//! [`SendReport::saved_to_sent`] 必须是 `Ok` 里的一个布尔，不是一个错误。

mod support;

use std::net::SocketAddr;

use mailway_core::compose::Composer;
use mailway_core::imap::Conn;
use mailway_core::send::send_and_file;
use mailway_core::store::{NewAccount, Store};
use mailway_core::types::{Account, Mailbox, Protocol, Security};
use support::*;

/// 一个指向两个假服务器的账号。
///
/// 从库里建而不是直接写 [`Account`] 结构体：账号字段会涨，直接建就没人提醒
/// 了；库里建出来的是真实形状。
fn account(smtp: SocketAddr, imap: SocketAddr) -> Account {
    let store = Store::open_in_memory().expect("开内存库");
    let id = store
        .insert_account(&NewAccount {
            name: "测试",
            alias: "",
            email: "me@example.com",
            protocol: Protocol::Imap,
            imap_host: &imap.ip().to_string(),
            imap_port: imap.port(),
            imap_security: Security::Plain,
            imap_username: "me@example.com",
            smtp_host: &smtp.ip().to_string(),
            smtp_port: smtp.port(),
            smtp_security: Security::Plain,
            smtp_username: "me@example.com",
            signature: "",
            enabled: true,
            auth_type: "password",
        })
        .expect("建账号");
    store.get_account(id).expect("读账号").expect("刚建的那行")
}

fn mb(addr: &str) -> Mailbox {
    Mailbox { display: None, address: addr.into() }
}

fn letter() -> Composer {
    let mut c = Composer::new(Mailbox {
        display: Some("我".into()),
        address: "me@example.com".into(),
    });
    c.to.push(mb("bob@example.com"));
    c.cc.push(mb("carol@example.com"));
    // Bcc 要进信封、不进原文（见 `compose.rs` 模块头）
    c.bcc.push(mb("dave@example.com"));
    c.subject = "端到端".into();
    c.text = "正文\n第二行\n".into();
    c.html = Some("<p>正文</p>".into());
    c
}

/// 「已发送」里落的字节 == 对方收到的字节。
#[test]
fn the_sent_folder_gets_exactly_what_the_recipient_got() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    let report = send_and_file(&acct, "good", letter(), Some("&XfJT0ZAB-")).expect("发信不该失败");

    assert!(
        report.saved_to_sent,
        "存进「已发送」失败会报 false。IMAP 命令：{:?}",
        imap.commands()
    );
    assert!(!report.message_id.is_empty(), "发完要报出 Message-ID");

    // ---- 对方收到了什么 ----
    let got = smtp.deliveries();
    assert_eq!(got.len(), 1, "只该投一封");
    assert_eq!(got[0].from, "me@example.com");
    // Bcc 在信封上（对方的 MTA 要知道往哪送），三个收件人都算
    assert_eq!(
        got[0].to,
        vec!["bob@example.com", "carol@example.com", "dave@example.com"],
    );

    // ---- 自己留了什么 ----
    let filed = imap.appends();
    assert_eq!(filed.len(), 1, "「已发送」里该有一封");
    assert_eq!(filed[0].mailbox, "&XfJT0ZAB-");
    assert!(
        filed[0].flags.contains("\\Seen"),
        "自己发的信存下来顺手标已读，省得已发送里全是未读：{}",
        filed[0].flags
    );
    // **一字不差**：留副本不是重写一遍，是把同一份原文放上去
    assert_eq!(
        filed[0].raw,
        got[0].raw.as_bytes(),
        "已发送里的原文必须和对方收到的完全相同"
    );

    // ---- 信头里的 Message-ID 和报出去的是同一个 ----
    let want = format!("Message-ID: <{}>\r\n", report.message_id);
    assert!(
        got[0].raw.contains(&want),
        "原文里该有同一个 Message-ID\nwant: {want}\ngot:\n{}",
        got[0].raw
    );

    // ---- Bcc 不进原文 ----
    assert!(
        !got[0].raw.contains("dave@example.com"),
        "Bcc 写进原文就等于当众念出来"
    );
}

/// 存进「已发送」的那封，回头**取**得出来。
///
/// APPEND 的意义是「下次打开已发送还看得见」，不是在服务器日志里留个记号。
/// 所以这条不像上面那条只查流水账，而是**再连一次**、像收信那样把它取回来：
/// 原文必须和对方收到的一字不差，标志是已读，INTERNALDATE 得是个解析得出来
/// 的时间（那是服务器编的，格式写错这里就是 `None`）。
#[test]
fn the_copy_i_filed_can_be_read_back() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    let report = send_and_file(&acct, "good", letter(), Some("&XfJT0ZAB-")).expect("发信不该失败");
    assert!(report.saved_to_sent, "IMAP 命令：{:?}", imap.commands());

    let delivered = smtp.deliveries();
    assert_eq!(delivered.len(), 1, "只该投一封");

    // ---- 再连一次，像个邮件客户端那样把「已发送」打开 ----
    let mut conn = Conn::for_account(&acct, "good").expect("连回假服务器");
    let status = conn.select("&XfJT0ZAB-").expect("选中「已发送」");
    assert_eq!(status.total, 1, "APPEND 进去的信，下一次 SELECT 就该看得见");
    let back = conn.uid_fetch_full("1:*").expect("取回副本");
    let _ = conn.logout();

    assert_eq!(back.len(), 1, "「已发送」里该有一封");
    assert_eq!(
        back[0].uid, 1,
        "「已发送」的第一封就是 UID 1 —— UID 只在信箱内唯一，不是全局计数"
    );
    assert!(back[0].flags.seen, "自己发的信存下来就是已读");
    assert!(
        back[0].internal_date.is_some(),
        "INTERNALDATE 由服务器给，格式写错就解析不出来"
    );
    assert_eq!(
        back[0].raw,
        delivered[0].raw.as_bytes(),
        "取回来的必须和对方收到的一字不差"
    );
}

/// APPEND 失败**不是**发送失败。
#[test]
fn a_failing_append_is_not_a_failing_send() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    // 「已发送」这个箱子在假服务器上不存在 → APPEND 得到 NO [TRYCREATE]。
    // 这条路是真实的：IMAP 不会替你建箱子，很多服务器就是没这个文件夹。
    let report = send_and_file(&acct, "good", letter(), Some("NoSuchBox"))
        .expect("APPEND 失败不该上抛成 Err");

    assert!(!report.saved_to_sent, "没留副本就得说实话");
    assert_eq!(smtp.deliveries().len(), 1, "但信必须已经发出去了");
    assert!(imap.appends().is_empty(), "没留下副本");
}

/// 连「已发送」叫什么都不知道的时候，信也要发得出去。
#[test]
fn without_a_sent_folder_the_mail_still_goes_out() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    let report = send_and_file(&acct, "good", letter(), None).expect("没箱子也不该失败");

    assert!(!report.saved_to_sent);
    assert_eq!(smtp.deliveries().len(), 1);
    assert!(imap.appends().is_empty());
    // 一个字都没往 IMAP 发 —— 没有箱子就没必要连
    assert!(
        !imap.commands().iter().any(|c| c.contains("APPEND")),
        "不该去试一个没人要它试的箱子：{:?}",
        imap.commands()
    );
}

/// SMTP 那几条命令本身也要看得见：信封和原文是两回事。
#[test]
fn the_envelope_is_not_the_message() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    send_and_file(&acct, "good", letter(), None).expect("发信不该失败");

    let cmds = smtp.commands();
    let has = |s: &str| cmds.iter().any(|c| c.starts_with(s));
    assert!(has("EHLO"), "{cmds:?}");
    assert!(has("MAIL FROM:<me@example.com>"), "{cmds:?}");
    assert!(has("RCPT TO:<bob@example.com>"), "{cmds:?}");
    assert!(has("RCPT TO:<carol@example.com>"), "{cmds:?}");
    assert!(has("RCPT TO:<dave@example.com>"), "{cmds:?}");
    // 原文是一个整体走 DATA，不是一封信一条命令
    assert!(has("DATA"), "{cmds:?}");
    assert!(has("QUIT"), "{cmds:?}");
    // 认证载荷是 base64 的密码，一个字都不能进日志
    assert!(!cmds.iter().any(|c| c.contains("AHBhc3M")), "AUTH 载荷泄漏进日志了：{cmds:?}");
}

/// Message-ID 在「发出去」和「报给调用方」两处必须是同一个。
///
/// 两处各生成一个的话，排错时拿报出去的 id 去服务器上查会查不到。
#[test]
fn the_reported_id_is_the_one_in_the_headers() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    let mut c = letter();
    c.message_id = Some("pinned@example.com".into());
    let report = send_and_file(&acct, "good", c, Some("&XfJT0ZAB-")).expect("发信不该失败");

    assert_eq!(report.message_id, "pinned@example.com");
    let got = smtp.deliveries();
    assert!(got[0].raw.contains("Message-ID: <pinned@example.com>\r\n"));
    let filed = imap.appends();
    assert!(
        String::from_utf8_lossy(&filed[0].raw).contains("Message-ID: <pinned@example.com>\r\n"),
        "已发送里也得是同一个"
    );
}

/// 副本已经存上之后，收尾失败不能算「没存上」。
///
/// 登出是最容易出岔子的一步（服务器在 APPEND 之后掉线、中间盒子乱改响应）。
/// 拿它当失败报出去，用户会以为发送失败、再点一次 —— 对方收到两封。
#[test]
fn a_broken_logout_does_not_unfile_the_copy() {
    let smtp = FakeSmtp::start();
    let imap = FakeServer::start();
    let acct = account(smtp.addr, imap.addr);

    imap.set_logout_broken(true);
    let report = send_and_file(&acct, "good", letter(), Some("&XfJT0ZAB-"))
        .expect("收尾失败不该上抛成 Err");

    assert!(report.saved_to_sent, "副本已经存上了，收尾失败不能推翻它");
    assert_eq!(imap.appends().len(), 1, "副本确实落了");
}
