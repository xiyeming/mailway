//! 发信链路的集成测试
//!
//! 和 `tests/imap.rs` / `tests/sync.rs` 共用 `tests/support/mod.rs` 里的假服务器。
//! 这里测的是「一封信到底怎么发出去的」：信封里有谁、`DATA` 里是哪些字节、
//! 命令按什么顺序发。**断言的是收信方看到什么**，不是我们自己拼出来的中间形态。
//!
//!   * `build()` 的原文一个字节不改地上线
//!   * Bcc 只进信封，不进原文
//!   * 点填充（`.` 开头的行）双向可逆
//!   * AUTH 跟着服务器报的机制走（PLAIN 优先，没有就退回 LOGIN）
//!   * 认证失败是「授权码错了」，不是「服务器拒绝了这封信」
//!   * 收件人被拒就不该再发 DATA
//!   * 要求 STARTTLS 而服务器不支持，宁可不发也不退回明文
//!   * TLS 真握手：隐式 TLS、STARTTLS 升级 + 重新 EHLO、不信任的证书是错不是挂
//!
//! TLS 那几条用**现场造的自签证书**真握手（`rcgen` + 假服务器的
//! [`TlsMode`]），不是「把校验关掉跑过去」—— 关掉校验的测试证明不了任何事。

#[macro_use]
mod support;

use std::net::SocketAddr;

use mailway_core::compose::Composer;
use mailway_core::error::Error;
use mailway_core::smtp::{Config, Conn, Envelope};
use mailway_core::types::{Mailbox, Security};
use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};
use support::*;

// ================================================================= 夹具

fn cfg(addr: SocketAddr, security: Security) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: addr.port(),
        security,
        username: "me@example.com".into(),
    }
}

fn connect_ok(s: &FakeSmtp) -> Conn {
    Conn::connect(&cfg(s.addr, Security::Plain), "good", false).expect("连接+登录应该成功")
}

/// 断言「连不上」。
///
/// 不用 `unwrap_err()`：那要求 `T: Debug`，而 [`Conn`] 里裹着 TLS 流，
/// 派生不出 `Debug`。
fn connect_err(s: &FakeSmtp, security: Security, password: &str) -> Error {
    match Conn::connect(&cfg(s.addr, security), password, false) {
        Err(e) => e,
        Ok(_) => panic!("这次连接本该失败"),
    }
}

fn mb(addr: &str) -> Mailbox {
    Mailbox { display: None, address: addr.into() }
}

/// 一封最简单的纯文本信 + 它的信封。
fn letter() -> (Composer, Envelope) {
    let mut c = Composer::new(mb("me@example.com"));
    c.to = vec![mb("you@example.com")];
    c.subject = "测试".into();
    c.text = "正文".into();
    let env = Envelope {
        from: "me@example.com".into(),
        to: vec!["you@example.com".into()],
    };
    (c, env)
}

// ================================================================= 原文

#[test]
fn build_output_reaches_the_wire_verbatim() {
    // 这是整条发信链路的第一性质：撰写拼出来的字节，就是收件人拆开看到的字节。
    // 中间任何一层「顺手整理一下」都是 bug —— 它会把 compose 的单测结果作废。
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    let (c, env) = letter();
    let raw = c.build().expect("拼信");

    conn.send(&env, &raw).expect("发送");
    conn.quit().ok();

    let got = s.deliveries();
    assert_eq!(got.len(), 1, "该收到一封: {got:?}");
    assert_eq!(got[0].raw, raw, "上线的字节必须就是 build() 的输出");
    assert_eq!(got[0].from, "me@example.com");
    assert_eq!(got[0].to, vec!["you@example.com".to_string()]);
}

#[test]
fn the_command_order_is_the_one_rfc_5321_says() {
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    let (c, env) = letter();
    let raw = c.build().unwrap();
    conn.send(&env, &raw).unwrap();
    conn.quit().unwrap();

    let cmds = s.commands();
    let verbs: Vec<&str> = cmds
        .iter()
        .map(|c| c.split(' ').next().unwrap_or(""))
        .filter(|v| !v.is_empty())
        .collect();
    // EHLO（认证是在连接里做的，排在 EHLO 之后）→ MAIL → RCPT → DATA → QUIT
    let expect = ["EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"];
    let got: Vec<&str> = verbs.iter().copied().filter(|v| expect.contains(v)).collect();
    assert_eq!(got, expect, "命令顺序不对: {cmds:?}");
}

// ================================================================= Bcc

#[test]
fn bcc_only_reaches_the_envelope_not_the_headers() {
    // Bcc 是「寄给谁」，不是「信上写了谁」。写进原文的话，收件人一看就知道
    // 这封信还偷偷抄送了谁 —— 那就不是密送了。
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    let mut c = Composer::new(mb("me@example.com"));
    c.to = vec![mb("you@example.com")];
    c.cc = vec![mb("cc@example.com")];
    c.bcc = vec![mb("secret@example.com")];
    c.subject = "看谁收到了".into();
    c.text = "正文".into();
    let raw = c.build().unwrap();
    let env = Envelope {
        from: "me@example.com".into(),
        to: vec![
            "you@example.com".into(),
            "cc@example.com".into(),
            "secret@example.com".into(),
        ],
    };

    conn.send(&env, &raw).unwrap();

    let got = s.deliveries();
    assert_eq!(
        got[0].to,
        vec!["you@example.com", "cc@example.com", "secret@example.com"],
        "三个人都该投到: {:?}",
        got[0].to
    );

    let lower = got[0].raw.to_ascii_lowercase();
    assert!(!lower.contains("secret@example.com"), "Bcc 泄漏进原文了:\n{}", got[0].raw);
    assert!(!lower.contains("\r\nbcc:"), "不该有 Bcc 头:\n{}", got[0].raw);
    // To / Cc 是该有的
    assert!(lower.contains("\r\nto:"), "To 头要有:\n{}", got[0].raw);
    assert!(lower.contains("\r\ncc:"), "Cc 头要有:\n{}", got[0].raw);
}

// ================================================================= 点填充

#[test]
fn lines_starting_with_a_dot_survive_the_roundtrip() {
    // 不做点填充的话，正文里单独一行的 `.` 会被服务器当成 DATA 结束：信从那里
    // 截断，后半段直接丢掉，**而且服务器还回 250 OK** —— 发信的人根本看不出来。
    //
    // 这里故意用纯 ASCII 正文：中文会被 quoted-printable 编码，看不出点填充了。
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    let mut c = Composer::new(mb("me@example.com"));
    c.to = vec![mb("you@example.com")];
    c.subject = "dot".into();
    c.text = "before\n.\n..after\nend".into();
    let raw = c.build().unwrap();
    let env = Envelope {
        from: "me@example.com".into(),
        to: vec!["you@example.com".into()],
    };

    conn.send(&env, &raw).unwrap();

    let got = s.deliveries();
    assert_eq!(got.len(), 1, "只该收到一封，不该被 `.` 截成两半: {got:?}");

    // 线上**真的**补了点
    let wire: Vec<&str> = got[0].wire.lines().collect();
    assert!(wire.contains(&".."), "单独一行的 . 该被补成 ..: {wire:?}");
    assert!(wire.contains(&"...after"), "本来以 . 开头的该多补一个: {wire:?}");

    // 而且反过来能原样还原
    assert_eq!(got[0].raw, raw, "点填充要可逆");
}

#[test]
fn a_lone_dot_in_the_body_is_not_the_end_of_the_message() {
    // 上一条验的是可逆，这条验的是**没被截断**：正文最后一行必须还在。
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    let mut c = Composer::new(mb("me@example.com"));
    c.to = vec![mb("you@example.com")];
    c.subject = "dot".into();
    c.text = "一\n.\n二\n.\n三".into();
    let raw = c.build().unwrap();
    conn.send(
        &Envelope {
            from: "me@example.com".into(),
            to: vec!["you@example.com".into()],
        },
        &raw,
    )
    .unwrap();

    let got = s.deliveries();
    assert_eq!(got.len(), 1, "三行正文不该变成三封信: {got:?}");
    assert_eq!(got[0].raw, raw);
}

// ================================================================= 认证

#[test]
fn auth_plain_is_used_when_the_server_advertises_it() {
    let s = FakeSmtp::start();
    let _conn = connect_ok(&s);

    let cmds = s.commands();
    assert!(cmds.iter().any(|c| c == "AUTH PLAIN ****"), "该走 PLAIN: {cmds:?}");
}

#[test]
fn auth_login_is_used_when_plain_is_not_available() {
    // 只报 LOGIN 的服务器是真实存在的（一些老的企业邮）。
    let s = FakeSmtp::start();
    s.set_auth_mechs("LOGIN");
    let _conn = connect_ok(&s);

    let cmds = s.commands();
    assert!(cmds.iter().any(|c| c.starts_with("AUTH LOGIN")), "该走 LOGIN: {cmds:?}");
    assert!(!cmds.iter().any(|c| c.contains("PLAIN")), "服务器没报 PLAIN 就不该试: {cmds:?}");
}

#[test]
fn auth_plain_falls_back_to_the_two_step_form() {
    // 有些服务器不吃内联的初始应答：`AUTH PLAIN <载荷>` 也先回 334，要客户端
    // 单独再把载荷发一遍。
    //
    // **这条分支是拿 curl 冒烟时才发现缺的** —— 我们自己那套客户端和假服务器
    // 当初都只挑了内联这一种，两边互相迁就，单靠集成测试测不出差别。
    // 拿一个不相干的客户端打一遍，才看得出我们只实现了一半协议。
    let s = FakeSmtp::start();
    s.set_plain_two_step(true);
    let _conn = connect_ok(&s);

    let cmds = s.commands();
    assert!(cmds.iter().any(|c| c.starts_with("AUTH PLAIN")), "第一次要打招呼: {cmds:?}");
    assert!(
        cmds.iter().filter(|c| c.as_str() == "****").count() >= 1,
        "被 334 之后该把载荷单独补发一遍: {cmds:?}"
    );
}

#[test]
fn auth_login_hides_the_credentials_from_the_command_log() {
    // AUTH 的载荷是 base64 的 `"\0user\0pass"`。记进日志等于在日志里留密码。
    let s = FakeSmtp::start();
    s.set_auth_mechs("LOGIN");
    let _conn = connect_ok(&s);

    for c in s.commands() {
        assert!(!c.contains("me@example.com"), "用户名不该裸奔在命令日志里: {c}");
        assert!(!c.contains("Z29vZA=="), "base64(\"good\") 不该出现: {c}");
    }
}

#[test]
fn wrong_password_is_an_auth_error_and_never_echoes_the_password() {
    let s = FakeSmtp::start();
    let err = connect_err(&s, Security::Plain, "hunter2");

    assert!(matches!(err, Error::SmtpAuth(_)), "该归成认证失败，实际: {err:?}");
    // 这条是安全性质，不是格式要求：错误串会进日志、进 UI
    for leak in ["hunter2", "aHVudGVyMg=="] {
        assert!(!format!("{err}").contains(leak), "错误串里不能有密码: {err}");
        assert!(!err.user_message().contains(leak), "用户提示里也不能有密码");
    }
}

// ================================================================= 错误路径

#[test]
fn a_rejected_recipient_aborts_before_data() {
    // RCPT TO 就被拒了还继续 DATA，服务器会说 250 而信根本没投出去 ——
    // 用户以为发成功了。
    let s = FakeSmtp::start();
    s.reject(Reject::Rcpt);
    let mut conn = connect_ok(&s);
    let (c, env) = letter();
    let raw = c.build().unwrap();

    let err = conn.send(&env, &raw).unwrap_err();
    assert!(matches!(err, Error::Smtp(_)), "{err:?}");

    let cmds = s.commands();
    assert!(!cmds.iter().any(|c| c == "DATA"), "收件人被拒就不该再发 DATA: {cmds:?}");
    assert!(s.deliveries().is_empty(), "更不该留下一封「已发」的信");
}

#[test]
fn empty_recipients_are_rejected_locally_without_touching_the_server() {
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    let (c, _) = letter();
    let raw = c.build().unwrap();

    let err = conn
        .send(&Envelope { from: "me@example.com".into(), to: vec![] }, &raw)
        .unwrap_err();
    assert!(matches!(err, Error::Smtp(_)), "{err:?}");

    let cmds = s.commands();
    assert!(!cmds.iter().any(|c| c.starts_with("MAIL")), "连信封都不该发: {cmds:?}");
}

#[test]
fn auth_failure_surfaces_as_auth_not_as_rejected_mail() {
    let s = FakeSmtp::start();
    s.reject(Reject::Auth);
    let err = connect_err(&s, Security::Plain, "good");

    assert!(matches!(err, Error::SmtpAuth(_)), "{err:?}");
    // 「授权码不对」的下一步是去改授权码，「信被拒」的下一步是去看内容
    assert!(err.user_message().contains("授权码"), "提示要指对方向: {}", err.user_message());
}

// ================================================================= 加密

#[test]
fn starttls_is_refused_when_the_server_does_not_offer_it() {
    // 要求了加密就必须加密。**不能**「服务器不支持就明文发」—— 那等于把授权码
    // 和正文裸奔，而且用户还以为是加密的。
    let s = FakeSmtp::start();
    let err = connect_err(&s, Security::StartTls, "good");

    assert!(matches!(err, Error::Config(_)), "{err:?}");
    assert!(err.user_message().contains("加密"), "提示要说清楚为什么: {}", err.user_message());

    // 没升级成 TLS 就一个字节的授权码都不许出去
    let cmds = s.commands();
    assert!(!cmds.iter().any(|c| c.contains("AUTH")), "没升级成 TLS 就不许认证: {cmds:?}");
    assert!(!cmds.iter().any(|c| c.starts_with("MAIL")), "更不许发信: {cmds:?}");
}

// ================================================================= TLS 握手

/// 现场造一张自签证书：一半给假服务器当身份（[`Identity`]），一半给被测的
/// 客户端当信任根（[`TlsConnector`]）。
///
/// 校验**照走不误** —— 只是把「系统信任的 CA」换成「信任这一张」。生产路径
/// 用的是默认 connector；测试得显式传进 [`Conn::connect_with`] 才连得上自己
/// 的假服务器。证书现场造，不放仓库里：写死的会过期，过期之后每个人的第一次
/// 跑都是红的，还以为是代码坏了。
fn self_signed() -> (Identity, TlsConnector) {
    let rcgen::CertifiedKey { cert, signing_key, .. } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("造自签证书");
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let identity = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()).expect("Identity");
    let ca = Certificate::from_pem(cert_pem.as_bytes()).expect("CA");
    let connector = TlsConnector::builder().add_root_certificate(ca).build().expect("connector");
    (identity, connector)
}

/// TLS 测试的配置。主机写 `localhost` 而不是 `127.0.0.1`：证书的 SAN 是
/// `localhost` 这个**名字**，拿 IP 去做主机名校验走的是另一套规则，对不上。
/// TCP 照样连得到 —— `TcpStream::connect` 对解析出来的地址依次试。
fn tls_cfg(port: u16, security: Security) -> Config {
    Config {
        host: "localhost".into(),
        port,
        security,
        username: "me@example.com".into(),
    }
}

#[test]
fn implicit_tls_delivers_through_the_tunnel() {
    // 465 那条路：连问候语都在隧道里，整场会话外面看不见一个字节。
    let (identity, connector) = self_signed();
    let s = FakeSmtp::start_implicit_tls(TlsAcceptor::new(identity).expect("acceptor"));
    let cfg = tls_cfg(s.addr.port(), Security::Ssl);

    let mut conn = Conn::connect_with(&cfg, "good", &connector, false).expect("隐式 TLS 该连得上");
    let (c, env) = letter();
    let raw = c.build().unwrap();
    conn.send(&env, &raw).expect("隧道里也该发得出去");
    conn.quit().unwrap();

    let got = s.deliveries();
    assert_eq!(got.len(), 1, "信得到得了对岸: {got:?}");
    assert_eq!(got[0].raw, raw, "隧道不改字节");
    // TLS 只是运输方式，命令照旧
    let cmds = s.commands();
    assert!(cmds.iter().any(|c| c == "AUTH PLAIN ****"), "{cmds:?}");
    assert_eq!(cmds.last().map(String::as_str), Some("QUIT"), "{cmds:?}");
}

#[test]
fn start_tls_upgrades_then_re_ehlos() {
    // 587 那条路：明文谈好再升级。升级前拿到的能力清单可能被改过，
    // 所以 RFC 3207 §4.2 要求升级后**重新 EHLO** —— 这条钉在这儿。
    let (identity, connector) = self_signed();
    let s = FakeSmtp::start_starttls(TlsAcceptor::new(identity).expect("acceptor"));
    let cfg = tls_cfg(s.addr.port(), Security::StartTls);

    let mut conn = Conn::connect_with(&cfg, "good", &connector, false).expect("STARTTLS 该升得上去");
    let (c, env) = letter();
    conn.send(&env, &c.build().unwrap()).unwrap();
    conn.quit().unwrap();

    assert_eq!(s.deliveries().len(), 1, "升级之后的信也得投到");

    let cmds = s.commands();
    let ehlo = cmds.iter().position(|c| c.starts_with("EHLO")).expect("先 EHLO");
    let starttls = cmds.iter().position(|c| c == "STARTTLS").expect("谈升级");
    let re_ehlo = cmds.iter().rposition(|c| c.starts_with("EHLO")).expect("升级后重新 EHLO");
    assert!(
        ehlo < starttls && starttls < re_ehlo,
        "顺序该是 EHLO → STARTTLS → EHLO: {cmds:?}"
    );
    // 认证必须在**升级之后** —— 明文阶段连用户名都不许出去
    let auth = cmds.iter().position(|c| c.starts_with("AUTH")).expect("要认证");
    assert!(re_ehlo < auth, "认证得在隧道里: {cmds:?}");
}

#[test]
fn a_certificate_we_do_not_trust_fails_the_handshake() {
    // 不信任的证书必须是**错**，不是「连上了但其实没加密」，也不是挂死。
    // 默认 connector 的信任根里没有这张自签 → 校验当场失败。
    let (identity, _trusted) = self_signed();
    let s = FakeSmtp::start_implicit_tls(TlsAcceptor::new(identity).expect("acceptor"));
    let cfg = tls_cfg(s.addr.port(), Security::Ssl);

    let err = match Conn::connect(&cfg, "good", false) {
        Err(e) => e,
        Ok(_) => panic!("不信任的证书不该连得上"),
    };
    assert!(matches!(err, Error::SmtpConnect(_)), "{err:?}");
    assert!(format!("{err}").contains("TLS 握手失败"), "错误要指得出是握手: {err}");
    // 握手都没过，一个命令都不该有 —— 尤其不该把授权码发出去
    assert!(s.commands().is_empty(), "没握手成功就不该有任何命令: {:?}", s.commands());
}

// ================================================================= 收尾

#[test]
fn quit_ends_the_conversation() {
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);
    conn.quit().unwrap();

    let cmds = s.commands();
    assert_eq!(cmds.last().map(String::as_str), Some("QUIT"), "{cmds:?}");
}

#[test]
fn sending_twice_on_one_connection_works() {
    // 一个账号连着发几封是常态（批量转发、补发）。信封不能串到上一封去。
    let s = FakeSmtp::start();
    let mut conn = connect_ok(&s);

    for (subject, to) in [("第一封", "a@example.com"), ("第二封", "b@example.com")] {
        let mut c = Composer::new(mb("me@example.com"));
        c.to = vec![mb(to)];
        c.subject = subject.into();
        c.text = subject.into();
        conn.send(
            &Envelope { from: "me@example.com".into(), to: vec![to.into()] },
            &c.build().unwrap(),
        )
        .unwrap();
    }

    let got = s.deliveries();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].to, vec!["a@example.com"]);
    assert_eq!(got[1].to, vec!["b@example.com"], "第二封的收件人不该被上一封污染");
}
