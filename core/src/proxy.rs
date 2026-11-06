//! TCP 代理（SOCKS5 / HTTP CONNECT）——所有出站连接（IMAP/POP3/SMTP）共用。
//!
//! 设置页「代理设置」存配置，应用启动/保存时 [`set_global`]；三处
//! [`connect`] 调用点（imap/pop3/smtp 的 TcpStream::connect）换成这里。
//!
//! 只做**建连**这一段：代理打通的是 TCP 管道，TLS 照旧端到端握手
//! （CONNECT/SOCKS 隧道里跑 TLS），代理看不到明文。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use crate::error::{Error, Result};

/// 建连 + 读写超时（同旧 IO_TIMEOUT 的量级）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// SOCKS5（RFC 1928，可选用户名密码 RFC 1929）
    Socks5,
    /// HTTP CONNECT
    HttpConnect,
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

static PROXY: OnceLock<RwLock<Option<ProxyConfig>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<ProxyConfig>> {
    PROXY.get_or_init(|| RwLock::new(None))
}

/// 设置代理（`None` = 直连）。应用启动与设置保存时调用。
pub fn set_global(cfg: Option<ProxyConfig>) {
    if let Ok(mut g) = slot().write() {
        *g = cfg;
    }
}

/// 当前代理配置（测试按钮/诊断用）。
pub fn global() -> Option<ProxyConfig> {
    slot().read().ok().and_then(|g| g.clone())
}

/// 建到 `host:port` 的 TCP（走代理或直连）。超时统一设置。
pub fn connect(host: &str, port: u16) -> Result<TcpStream> {
    let Some(p) = global() else {
        let s = TcpStream::connect((host, port))
            .map_err(|e| Error::Proxy(format!("连不上 {host}:{port}：{e}")))?;
        s.set_read_timeout(Some(IO_TIMEOUT)).ok();
        s.set_write_timeout(Some(IO_TIMEOUT)).ok();
        return Ok(s);
    };
    let mut s = TcpStream::connect((p.host.as_str(), p.port))
        .map_err(|e| Error::Proxy(format!("连不上代理 {}:{}：{e}", p.host, p.port)))?;
    s.set_read_timeout(Some(IO_TIMEOUT)).ok();
    s.set_write_timeout(Some(IO_TIMEOUT)).ok();
    match p.kind {
        ProxyKind::Socks5 => socks5(&mut s, host, port, &p)?,
        ProxyKind::HttpConnect => http_connect(&mut s, host, port, &p)?,
    }
    Ok(s)
}

// ---------------------------------------------------------------- SOCKS5

fn socks5(s: &mut TcpStream, host: &str, port: u16, p: &ProxyConfig) -> Result<()> {
    // 1. 问候：可选「用户名密码」两种方法
    if p.username.is_some() {
        s.write_all(&[0x05, 0x02, 0x00, 0x02])
    } else {
        s.write_all(&[0x05, 0x01, 0x00])
    }
    .map_err(|e| Error::Proxy(format!("代理问候失败：{e}")))?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello)
        .map_err(|e| Error::Proxy(format!("代理问候无响应：{e}")))?;
    if hello[0] != 0x05 {
        return Err(Error::Proxy("对面不是 SOCKS5 代理".into()));
    }
    match hello[1] {
        0x00 => {}
        0x02 => socks5_auth(s, p)?,
        0xFF => return Err(Error::Proxy("代理要求的认证方式不支持".into())),
        m => return Err(Error::Proxy(format!("代理选择了不支持的认证方式 {m}"))),
    }

    // 2. CONNECT（域名式 ATYP=3，代理自己解析 DNS）
    let hb = host.as_bytes();
    if hb.len() > 255 {
        return Err(Error::Proxy("主机名太长".into()));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)
        .map_err(|e| Error::Proxy(format!("代理 CONNECT 发送失败：{e}")))?;

    // 3. 回复：VER REP RSV ATYP + 绑定地址（按 ATYP 定长吃掉）
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .map_err(|e| Error::Proxy(format!("代理 CONNECT 无响应：{e}")))?;
    if head[1] != 0x00 {
        return Err(Error::Proxy(match head[1] {
            0x01 => "代理：一般性失败".into(),
            0x02 => "代理：规则不允许连接".into(),
            0x03 => "代理：网络不可达".into(),
            0x04 => "代理：主机不可达".into(),
            0x05 => "代理：连接被拒（目标端口没开？）".into(),
            0x06 => "代理：TTL 过期".into(),
            0x07 => "代理：不支持的命令".into(),
            0x08 => "代理：不支持的地址类型".into(),
            c => format!("代理拒绝连接（代码 {c}）"),
        }));
    }
    match head[3] {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).ok();
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).ok();
            let mut b = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut b).ok();
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).ok();
        }
        _ => return Err(Error::Proxy("代理回复的地址类型不对".into())),
    }
    Ok(())
}

/// RFC 1929 用户名密码子协商。
fn socks5_auth(s: &mut TcpStream, p: &ProxyConfig) -> Result<()> {
    let u = p.username.clone().unwrap_or_default();
    let pw = p.password.clone().unwrap_or_default();
    let (u, pw) = (u.as_bytes(), pw.as_bytes());
    if u.len() > 255 || pw.len() > 255 {
        return Err(Error::Proxy("代理用户名/密码太长".into()));
    }
    let mut req = vec![0x01, u.len() as u8];
    req.extend_from_slice(u);
    req.push(pw.len() as u8);
    req.extend_from_slice(pw);
    s.write_all(&req)
        .map_err(|e| Error::Proxy(format!("代理认证发送失败：{e}")))?;
    let mut ar = [0u8; 2];
    s.read_exact(&mut ar)
        .map_err(|e| Error::Proxy(format!("代理认证无响应：{e}")))?;
    if ar[1] != 0x00 {
        return Err(Error::Proxy("代理用户名或密码不对".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------- HTTP CONNECT

fn http_connect(s: &mut TcpStream, host: &str, port: u16, p: &ProxyConfig) -> Result<()> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(u) = &p.username {
        let raw = format!("{u}:{}", p.password.clone().unwrap_or_default());
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(raw.as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())
        .map_err(|e| Error::Proxy(format!("代理 CONNECT 发送失败：{e}")))?;

    // 逐字节读到空行为止 —— 多读一个字节都可能把 TLS 握手字节吃掉
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        let n = s
            .read(&mut b)
            .map_err(|e| Error::Proxy(format!("代理响应读取失败：{e}")))?;
        if n == 0 {
            return Err(Error::Proxy("代理提前断开".into()));
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(Error::Proxy("代理响应太长".into()));
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(Error::Proxy(format!("代理 CONNECT 被拒：HTTP {status}")));
    }
    Ok(())
}

/// 极小 base64（代理 Basic 认证用；不为它引一个依赖）。
fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [
            c[0],
            *c.get(1).unwrap_or(&0),
            *c.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// 全局代理槽是进程级状态，测试并行会互相踩 —— 串起来跑。
    static LOCK: Mutex<()> = Mutex::new(());
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 起一个假 SOCKS5 服务器，跑完一段对话返回它看到的请求。
    fn fake_socks(
        methods_req: &'static [u8],
        method_pick: u8,
        auth_ok: bool,
    ) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut seen = Vec::new();
            let mut n = [0u8; 2];
            s.read_exact(&mut n).unwrap();
            let mut m = vec![0u8; n[1] as usize];
            s.read_exact(&mut m).unwrap();
            seen.extend_from_slice(&n);
            seen.extend_from_slice(&m);
            s.write_all(&[0x05, method_pick]).unwrap();
            if method_pick == 0x02 {
                // RFC 1929：VER(1) ULEN(1) UNAME PLEN(1) PASS
                let mut one = [0u8; 1];
                s.read_exact(&mut one).unwrap();
                seen.extend_from_slice(&one); // VER
                s.read_exact(&mut one).unwrap();
                let mut u = vec![0u8; one[0] as usize];
                seen.push(one[0]);
                s.read_exact(&mut u).unwrap();
                seen.extend_from_slice(&u);
                s.read_exact(&mut one).unwrap();
                let mut pw = vec![0u8; one[0] as usize];
                seen.push(one[0]);
                s.read_exact(&mut pw).unwrap();
                seen.extend_from_slice(&pw);
                s.write_all(&[0x01, if auth_ok { 0x00 } else { 0x01 }]).unwrap();
                if !auth_ok {
                    return seen;
                }
            }
            let mut head = [0u8; 5];
            s.read_exact(&mut head).unwrap();
            let mut name = vec![0u8; head[4] as usize];
            s.read_exact(&mut name).unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).unwrap();
            seen.extend_from_slice(&head);
            seen.extend_from_slice(&name);
            seen.extend_from_slice(&port);
            // 回成功（IPv4 绑定地址）
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            seen
        });
        let _ = methods_req;
        (format!("127.0.0.1:{}", addr.port()), h)
    }

    #[test]
    fn socks5_no_auth_connect() {
        let _g = test_lock();
        let (addr, h) = fake_socks(&[], 0x00, true);
        let (host, port) = addr.split_once(':').unwrap();
        set_global(Some(ProxyConfig {
            kind: ProxyKind::Socks5,
            host: host.into(),
            port: port.parse().unwrap(),
            username: None,
            password: None,
        }));
        let s = connect("imap.example.com", 993);
        set_global(None);
        assert!(s.is_ok(), "{:?}", s.err());
        let seen = h.join().unwrap();
        // 问候 05 01 00；CONNECT 05 01 00 03 + len + host + port
        assert_eq!(&seen[..3], &[0x05, 0x01, 0x00]);
        assert_eq!(seen[3], 0x05);
        assert_eq!(&seen[4..7], &[0x01, 0x00, 0x03]);
        assert_eq!(seen[7] as usize, "imap.example.com".len());
    }

    #[test]
    fn socks5_userpass_auth() {
        let _g = test_lock();
        let (addr, h) = fake_socks(&[], 0x02, true);
        let (host, port) = addr.split_once(':').unwrap();
        set_global(Some(ProxyConfig {
            kind: ProxyKind::Socks5,
            host: host.into(),
            port: port.parse().unwrap(),
            username: Some("u1".into()),
            password: Some("p2".into()),
        }));
        let s = connect("x.io", 443);
        set_global(None);
        assert!(s.is_ok(), "{:?}", s.err());
        let seen = h.join().unwrap();
        // 问候带两种方法 05 02 00 02；认证帧 01 02 u1 02 p2
        assert_eq!(&seen[..4], &[0x05, 0x02, 0x00, 0x02]);
        assert_eq!(&seen[4..9], &[0x01, 0x02, b'u', b'1', 0x02]);
    }

    #[test]
    fn socks5_auth_rejected() {
        let _g = test_lock();
        let (addr, h) = fake_socks(&[], 0x02, false);
        let (host, port) = addr.split_once(':').unwrap();
        set_global(Some(ProxyConfig {
            kind: ProxyKind::Socks5,
            host: host.into(),
            port: port.parse().unwrap(),
            username: Some("u".into()),
            password: Some("bad".into()),
        }));
        let s = connect("x.io", 443);
        set_global(None);
        let err = s.unwrap_err().to_string();
        assert!(err.contains("用户名或密码"), "{err}");
        let _ = h.join();
    }

    #[test]
    fn http_connect_with_auth() {
        let _g = test_lock();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if s.read(&mut b).unwrap() == 0 {
                    break;
                }
                buf.push(b[0]);
            }
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        set_global(Some(ProxyConfig {
            kind: ProxyKind::HttpConnect,
            host: "127.0.0.1".into(),
            port: addr.port(),
            username: Some("me".into()),
            password: Some("pw".into()),
        }));
        let s = connect("mail.example.com", 465);
        set_global(None);
        assert!(s.is_ok(), "{:?}", s.err());
        let req = h.join().unwrap();
        assert!(req.starts_with("CONNECT mail.example.com:465 HTTP/1.1"), "{req}");
        // base64("me:pw") = bWU6cHc=
        assert!(req.contains("Proxy-Authorization: Basic bWU6cHc="), "{req}");
    }

    #[test]
    fn http_connect_rejected() {
        let _g = test_lock();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if s.read(&mut b).unwrap() == 0 {
                    break;
                }
                buf.push(b[0]);
            }
            let _ = s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        });
        set_global(Some(ProxyConfig {
            kind: ProxyKind::HttpConnect,
            host: "127.0.0.1".into(),
            port: addr.port(),
            username: None,
            password: None,
        }));
        let s = connect("x.io", 80);
        set_global(None);
        let err = s.unwrap_err().to_string();
        assert!(err.contains("407"), "{err}");
        h.join().unwrap();
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(base64(b"me:pw"), "bWU6cHc=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"ab"), "YWI=");
    }
}
