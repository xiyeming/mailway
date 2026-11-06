//! POP3 收信（RFC 1939）。
//!
//! 只做收信路径需要的最小命令集：`USER`/`PASS`（或 `AUTH XOAUTH2`）、`STAT`、
//! `UIDL`、`RETR`、`QUIT`，外加 `STLS`（明文口升级）。**只拉不删** ——
//! 邮件保留在服务器上（`DELE` 一律不用），本地按 **UIDL** 增量去重：
//! POP3 的序号会随服务器删信而漂，UIDL 才是那封信的身份。
//!
//! POP3 没有服务器端文件夹和标志（已读/标星是纯本地概念），所以这里没有
//! [`crate::imap::Conn`] 那些 `uid_store_flags` / `uid_move` 对应物。
//!
//! 密码（或授权码/令牌）由调用方从 keyring 取，**不进 [`Config`]、不进日志**：
//! `PASS` 那行只记命令动词，不记参数。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use native_tls::{TlsConnector, TlsStream};

use crate::error::{Error, Result};
use crate::types::{Account, Security};

/// 单条命令的 I/O 超时。和 SMTP 那边一个量级：收一封 20 MB 的信不该让
/// 调用方等到天荒地老，断了就报错重连。
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// 连接配置。**不含密码** —— 见模块头。
pub struct Config {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
}

/// 底层管道：明文或 TLS。STARTTLS 就是在这两个形态之间换。
enum Io {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Read for Io {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Io::Plain(s) => s.read(buf),
            Io::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Io {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Io::Plain(s) => s.write(buf),
            Io::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Io::Plain(s) => s.flush(),
            Io::Tls(s) => s.flush(),
        }
    }
}

/// 一条 POP3 连接。
pub struct Conn {
    r: BufReader<Io>,
}

impl Conn {
    /// 按账号记录连上去。POP3 账号复用 `imap_*` 那几列存「收信服务器」
    /// （表单上就一套收信字段，协议决定讲哪种话）。
    pub fn for_account(account: &Account, secret: &str) -> Result<Self> {
        let is_oauth = account.auth_type == "xoauth2";
        Self::connect(
            &Config {
                host: account.imap_host.clone(),
                port: account.imap_port,
                security: account.imap_security,
                username: account.imap_username.clone(),
            },
            secret,
            is_oauth,
        )
    }

    /// 连上并登录。
    pub fn connect(cfg: &Config, secret: &str, is_oauth: bool) -> Result<Self> {
        let connector = TlsConnector::builder()
            .build()
            .map_err(|e| Error::Pop3Connect(format!("建 TLS 连接器失败: {e}")))?;
        Self::connect_with(cfg, secret, &connector, is_oauth)
    }

    /// 同 [`Conn::connect`]，但 TLS 用调用方给的连接器（自签证书测试用）。
    pub fn connect_with(
        cfg: &Config,
        secret: &str,
        connector: &TlsConnector,
        is_oauth: bool,
    ) -> Result<Self> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let tcp = crate::proxy::connect(&cfg.host, cfg.port)
            .map_err(|e| Error::Pop3Connect(format!("连不上 {addr}: {e}")))?;
        // 超时设在升级 TLS 之前 —— TlsStream 继承底层 socket 的设置
        tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
        tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();

        let mut conn = Conn {
            r: BufReader::new(match cfg.security {
                // POP3S（995）：连接一开始就是加密的
                Security::Ssl => Io::Tls(wrap_tls(tcp, cfg, connector)?),
                _ => Io::Plain(tcp),
            }),
        };

        // 问候语
        let greeting = conn.read_line()?;
        if !greeting.starts_with(b"+OK") {
            return Err(Error::Pop3Connect(format!(
                "问候语不是 +OK: {}",
                String::from_utf8_lossy(&greeting)
            )));
        }

        // STARTTLS（110）：明文连上，谈好了再升级
        if cfg.security == Security::StartTls {
            conn.roundtrip("STLS")
                .map_err(|e| Error::Pop3Connect(format!("STLS 失败: {e}")))?;
            let plain = match conn.r.into_inner() {
                Io::Plain(s) => s,
                Io::Tls(_) => unreachable!("STARTTLS 之前不可能是 TLS"),
            };
            conn.r = BufReader::new(Io::Tls(wrap_tls(plain, cfg, connector)?));
        }

        // 登录。认证失败要和「连不上」分开报 —— 对用户是两件事。
        if is_oauth {
            // XOAUTH2 的 SASL 串和 IMAP/SMTP 同形（RFC 7628）
            let b64 = crate::smtp::xoauth2_sasl(&cfg.username, secret);
            conn.roundtrip(&format!("AUTH XOAUTH2 {b64}"))
                .map_err(|e| Error::Pop3Auth(e.to_string()))?;
        } else {
            conn.roundtrip(&format!("USER {}", cfg.username))
                .map_err(|e| Error::Pop3Auth(e.to_string()))?;
            // **不记这条命令的参数** —— 密码在里面
            conn.roundtrip_sensitive("PASS", secret)
                .map_err(|e| Error::Pop3Auth(e.to_string()))?;
        }
        Ok(conn)
    }

    /// `STAT` → (信数, 总字节)。
    pub fn stat(&mut self) -> Result<(u32, u64)> {
        let line = self.roundtrip("STAT")?;
        let mut it = line.split_whitespace();
        let count = it
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Pop3(format!("STAT 响应认不出信数: {line}")))?;
        let octets = it
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Pop3(format!("STAT 响应认不出字节数: {line}")))?;
        Ok((count, octets))
    }

    /// `UIDL`（全箱）→ `(序号, uidl)` 列表。
    pub fn uidl_all(&mut self) -> Result<Vec<(u32, String)>> {
        let body = self.roundtrip_multiline("UIDL")?;
        let mut out = Vec::new();
        for line in body.split(|b| *b == b'\n') {
            let line = trim_cr(line);
            if line.is_empty() {
                continue;
            }
            let mut it = line.split(|b| *b == b' ');
            let seq = it
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::Pop3(format!("UIDL 行认不出序号: {}", String::from_utf8_lossy(line))))?;
            let uidl = String::from_utf8_lossy(it.collect::<Vec<_>>().join(&b' ').as_slice()).into_owned();
            out.push((seq, uidl));
        }
        Ok(out)
    }

    /// `RETR n` → 原始报文（已去掉 dot-stuffing）。
    pub fn retrieve(&mut self, seq: u32) -> Result<Vec<u8>> {
        self.roundtrip_multiline(&format!("RETR {seq}"))
    }

    /// `QUIT`。收信都是「只拉不删」，所以这里就是纯告别。
    pub fn quit(&mut self) -> Result<()> {
        self.roundtrip("QUIT").map(|_| ())
    }

    // ------------------------------------------------------------ 协议细节

    /// 发一行命令，读一行状态。返回 `+OK` 后面的文本；`-ERR` 归 [`Error::Pop3`]。
    fn roundtrip(&mut self, cmd: &str) -> Result<String> {
        // 只记动词 —— 参数里可能有密码（PASS 走 sensitive 版，但统一这样最稳）
        tracing::debug!(verb = cmd.split(' ').next().unwrap_or(cmd), "> POP3");
        self.write_line(cmd)?;
        let line = self.read_line()?;
        self.status_text(&line)
    }

    /// 同 [`Conn::roundtrip`]，但**永不记录**命令内容（密码在里面）。
    fn roundtrip_sensitive(&mut self, verb: &str, _secret: &str) -> Result<String> {
        tracing::debug!(verb, "> POP3");
        self.write_line(&format!("{verb} {_secret}"))?;
        let line = self.read_line()?;
        self.status_text(&line)
    }

    /// 发一条**多行**命令，收完到 `.` 那行（去掉 dot-stuffing）。
    fn roundtrip_multiline(&mut self, cmd: &str) -> Result<Vec<u8>> {
        tracing::debug!(verb = cmd.split(' ').next().unwrap_or(cmd), "> POP3");
        self.write_line(cmd)?;
        let line = self.read_line()?;
        self.status_text(&line)?;
        let mut out = Vec::new();
        loop {
            let line = self.read_line()?;
            if line == b"." {
                break;
            }
            // dot-stuffing：行首 `..` 还原成 `.`（RFC 1939 §3）
            let line = if line.starts_with(b"..") {
                &line[1..]
            } else {
                &line[..]
            };
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        Ok(out)
    }

    fn status_text(&self, line: &[u8]) -> Result<String> {
        if line.starts_with(b"+OK") {
            Ok(String::from_utf8_lossy(&line[3..]).trim().to_string())
        } else {
            Err(Error::Pop3(String::from_utf8_lossy(line).into_owned()))
        }
    }

    fn write_line(&mut self, cmd: &str) -> Result<()> {
        let io = self.r.get_mut();
        io.write_all(cmd.as_bytes())
            .and_then(|_| io.write_all(b"\r\n"))
            .and_then(|_| io.flush())
            .map_err(|e| Error::Pop3(format!("写命令失败: {e}")))
    }

    /// 读一行（去掉行尾 CRLF）。POP3 的行就是 CRLF 结尾的字节序列。
    fn read_line(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.r
            .read_until(b'\n', &mut buf)
            .map_err(|e| Error::Pop3(format!("读响应失败: {e}")))?;
        if buf.is_empty() {
            return Err(Error::Pop3("连接被服务器关闭".into()));
        }
        Ok(trim_cr(&buf).to_vec())
    }
}

fn trim_cr(line: &[u8]) -> &[u8] {
    let mut l = line;
    if l.ends_with(b"\r\n") {
        l = &l[..l.len() - 2];
    } else if l.ends_with(b"\n") {
        l = &l[..l.len() - 1];
    }
    l
}

fn wrap_tls(tcp: TcpStream, cfg: &Config, connector: &TlsConnector) -> Result<TlsStream<TcpStream>> {
    connector
        .connect(&cfg.host, tcp)
        .map_err(|e| Error::Pop3Connect(format!("TLS 握手失败: {e}")))
}
