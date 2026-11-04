//! POP3 层的集成测试。
//!
//! 服务端是本文件里的小脚本机（线程 + TcpListener）：POP3 协议简单，
//! 自带一个假服务器比共享 support/mod.rs 那台 IMAP 脚本机更直白。
//! 测协议原语本身：登录（含 XOAUTH2）、STAT、UIDL、RETR 的 dot-unstuffing。

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use mailway_core::error::Error;
use mailway_core::pop3::{Config, Conn};
use mailway_core::types::Security;

// ================================================================= 假服务器

/// 起一台假 POP3：`good` 密码放行；UIDL 固定两封；RETR 1 的正文里带一行
/// `..`（dot-stuffing，客户端该还原成 `.`）。
fn start_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定假服务器");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            thread::spawn(move || serve(stream));
        }
    });
    addr
}

/// 好令牌的 AUTH XOAUTH2 行（base64("user=me@example.com\x01auth=Bearer tok\x01\x01")）。
const GOOD_AUTH: &str = "AUTH XOAUTH2 dXNlcj1tZUBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB0b2sBAQ==";

fn serve(stream: TcpStream) {
    let mut r = BufReader::new(stream.try_clone().unwrap());
    let mut w = stream;
    let mut send = |line: &str| {
        w.write_all(line.as_bytes()).ok();
        w.write_all(b"\r\n").ok();
        w.flush().ok();
    };
    send("+OK fake pop3 ready");

    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let cmd = line.trim_end();
        let verb = cmd.split(' ').next().unwrap_or("");
        match verb {
            "USER" => send("+OK name ok"),
            "PASS" => {
                if cmd == "PASS good" {
                    send("+OK logged in");
                } else {
                    send("-ERR wrong password");
                }
            }
            "AUTH" => {
                // 只认精确的那条（好令牌），别的都是 -ERR
                if cmd == GOOD_AUTH {
                    send("+OK authed");
                } else {
                    send("-ERR auth failed");
                }
            }
            "STAT" => send("+OK 2 300"),
            "UIDL" => {
                send("+OK");
                send("1 uid-aaa");
                send("2 uid-bbb");
                send(".");
            }
            "RETR" => {
                send("+OK 120 octets");
                send("From: a@example.com");
                send("Subject: hi");
                send("");
                send("body line");
                send(".."); // dot-stuffing：客户端该还原成一行 `.`
                send(".");
            }
            "QUIT" => {
                send("+OK bye");
                return;
            }
            _ => send("-ERR unknown"),
        }
    }
}

fn cfg(addr: SocketAddr) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: addr.port(),
        security: Security::Plain,
        username: "me@example.com".into(),
    }
}

// ================================================================= 测试

#[test]
fn login_ok_and_bad_password_maps_to_auth_error() {
    let addr = start_server();
    let mut conn = Conn::connect(&cfg(addr), "good", false).expect("connect+login 应该成功");
    conn.quit().ok();

    match Conn::connect(&cfg(addr), "wrong", false) {
        Err(Error::Pop3Auth(_)) => {}
        Err(other) => panic!("错密码该归 Pop3Auth，得到 {}", other.user_message()),
        Ok(_) => panic!("错密码不该登录成功"),
    }
}

#[test]
fn xoauth2_auth() {
    let addr = start_server();
    // base64("user=me@example.com\x01auth=Bearer tok\x01\x01") 里含 dXNlcj0（"user="）
    let mut conn = Conn::connect(&cfg(addr), "tok", true).expect("XOAUTH2 登录应该成功");
    conn.quit().ok();

    // 令牌不对 → 服务器 -ERR → 仍然归 Pop3Auth
    match Conn::connect(&cfg(addr), "", true) {
        Err(Error::Pop3Auth(_)) => {}
        Err(other) => panic!("坏令牌该归 Pop3Auth，得到 {}", other.user_message()),
        Ok(_) => panic!("坏令牌不该登录成功"),
    }
}

#[test]
fn stat_uidl_and_retrieve_unstuffs_dots() {
    let addr = start_server();
    let mut conn = Conn::connect(&cfg(addr), "good", false).unwrap();

    assert_eq!(conn.stat().unwrap(), (2, 300));

    let uidls = conn.uidl_all().unwrap();
    assert_eq!(
        uidls,
        vec![
            (1, "uid-aaa".to_string()),
            (2, "uid-bbb".to_string())
        ]
    );

    let raw = conn.retrieve(1).unwrap();
    let text = String::from_utf8(raw).unwrap();
    assert!(text.contains("Subject: hi"));
    // dot-stuffing：服务器发的 `..` 还原成 `.`，绝不能出现 `..` 行
    assert!(text.contains("\n.\n"), "客户端该把 `..` 还原成 `.`: {text:?}");
    assert!(!text.contains("\n..\n"));

    conn.quit().unwrap();
}

#[test]
fn server_greeting_error_maps_to_connect_error() {
    // 连上一个立刻关门的端口：读问候语失败 → Pop3Connect / Pop3
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // 端口空了，连上就是拒绝
    match Conn::connect(&cfg(addr), "good", false) {
        Err(Error::Pop3Connect(_)) | Err(Error::Pop3(_)) => {}
        Err(other) => panic!("连不上该归 Pop3Connect，得到 {}", other.user_message()),
        Ok(_) => panic!("端口都没了不该登录成功"),
    }
}
