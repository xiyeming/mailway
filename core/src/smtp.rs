//! SMTP 发信层 —— 把 `compose::build()` 的原文递到服务器手上
//!
//! 这一层只回答「怎么把一封信交出去」：连上、（可能）升级 TLS、认证、
//! `MAIL FROM` / `RCPT TO` / `DATA`、`QUIT`。信长什么样是 [`crate::compose`] 的事。
//!
//! 为什么自己写而不用 `lettre`：
//!
//! 1. [`crate::compose::Composer::build`] 的输出**就是**要上线的字节。用库的话，
//!    库会自己再拼一遍信封和报文，于是 MIME 有了两处说法，早晚打架。
//! 2. M1 验「能收」的办法是**假服务器把每一条命令都打出来**。发信要能同样验，
//!    假 SMTP 服务器本来就得自己写；两边都在仓库里，测试断言的就是我们想发的
//!    东西，而不是某个库碰巧发的东西。
//! 3. SMTP 的核心（EHLO / AUTH / MAIL / RCPT / DATA / QUIT + 点填充 + STARTTLS）
//!    就这么点，写下来看得见、审得了。
//!
//! 代价说在前面：**没在真实服务器上验过**。真实世界的怪癖（PIPELINING、CHUNKING、
//! 各家对 AUTH 的怪要求）是已知缺口。所以对外只留 [`Conn::send`] 一个口子
//! （配置 + 信封 + 原文），真要换库，只换这一层的内部实现，调用方不用动。
//!
//! 几个不写下来会踩的点：
//!
//! * **行尾是 CRLF**。`writeln!` 只给 LF，服务器会当成半个命令。
//! * **DATA 体要「点填充」**（RFC 5321 §4.5.2）：以 `.` 开头的行前面再补一个 `.`。
//!   不补的话，正文里单独一行的 `.` 会把信从那里截断，后半段直接丢掉 —— 而且
//!   服务器还回 `250 OK`，发信的人根本看不出来。
//! * **收件人在信封里，不在报文里**。`Bcc` 尤其如此：RFC 5322 说 Bcc 不该写进
//!   提交给服务器的报文，它只决定 `RCPT TO` 发几条。
//! * **STARTTLS 之后必须重新 EHLO**（RFC 3207 §4.2）：升级前拿到的能力清单走的是
//!   明文通道，可能被改过，不能继续信。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use base64::Engine;
use native_tls::{TlsConnector, TlsStream};

use crate::error::{Error, Result};
use crate::types::Security;

/// 一次读/写的最长等待。服务器不回话时不该把调用方挂死。
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// EHLO 里报的本机名字。没有真实域名也无所谓，服务器基本不看。
const CLIENT_NAME: &str = "mailway";

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

// ================================================================= 配置

/// 发信配置。**没有密码字段** —— 和 [`crate::imap::Config`] 同规矩：
/// 授权码不进配置、不进日志，每次连接现取现用。
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
}

// ================================================================= 信封

/// 信封：这封信要投给谁。
///
/// **收件人只在这里，不进原文。** `Bcc` 尤其如此 —— 它只决定 `RCPT TO` 发几条，
/// [`crate::compose::Composer::build`] 那边根本不写 Bcc 头。
#[derive(Debug, Clone)]
pub struct Envelope {
    /// 只要地址部分（`me@example.com`），不要显示名。SMTP 的 `MAIL FROM`
    /// 收的是 mailbox，带显示名的写法会被服务器拒。
    pub from: String,
    /// To + Cc + Bcc 全算上。去不去重是调用方的事。
    pub to: Vec<String>,
}

// ================================================================= 传输

/// 连接的两种形态。
///
/// 和 [`crate::imap::Conn`] 一样是枚举而不是 trait object：`Read + Write` 的
/// trait object 跟借用检查打架，而且就两个变体，分发一目了然。
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

/// socket + 读缓冲。
///
/// 读缓冲是必须的：TCP 一次 `read` 不保证给一整行，而 SMTP 的响应**既要按行切，
/// 又要看第四个字符是 `-` 还是空格**才知道续没续行。字节先攒在这里。
struct Pipe {
    io: Io,
    rbuf: Vec<u8>,
}

impl Pipe {
    fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(i) = self.rbuf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.rbuf.drain(..=i).collect();
                let s = String::from_utf8_lossy(&line[..line.len() - 1]);
                return Ok(s.trim_end_matches('\r').to_string());
            }
            let mut chunk = [0u8; 512];
            let n = self.io.read(&mut chunk).map_err(|e| Error::Smtp(format!("读响应失败: {e}")))?;
            if n == 0 {
                // 服务器直接断了。这多半是它不喜欢我们说的某句话，但
                // 已经不打算告诉我们是哪句了 —— 只能把最后一句好的回显出来。
                return Err(Error::Smtp(format!(
                    "服务器提前关闭了连接（缓冲区里还剩 {:?}）",
                    String::from_utf8_lossy(&self.rbuf)
                )));
            }
            self.rbuf.extend_from_slice(&chunk[..n]);
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.io
            .write_all(buf)
            .map_err(|e| Error::Smtp(format!("写命令失败: {e}")))?;
        self.io.flush().map_err(|e| Error::Smtp(format!("flush 失败: {e}")))?;
        Ok(())
    }
}

/// 读一条 SMTP 响应，返回 `(状态码, 文本)`。
///
/// 多行响应是 `250-xxx` 续行、`250 xxx` 收尾（RFC 5321 §4.2）。**第四个字符是
/// 分隔符**，不是内容的一部分。
fn read_reply(pipe: &mut Pipe) -> Result<(u16, String)> {
    let mut code = 0u16;
    let mut text = String::new();
    loop {
        let line = pipe.read_line()?;
        let bytes = line.as_bytes();
        if bytes.len() < 4 {
            return Err(Error::Smtp(format!("响应行太短，读不出状态码: {line:?}")));
        }
        let c: u16 = line[..3]
            .parse()
            .map_err(|_| Error::Smtp(format!("响应码不是三位数字: {line:?}")))?;
        if code == 0 {
            code = c;
        } else if c != code {
            // RFC 5321 说多行响应的码必须一致。不一致就是协议坏了，
            // 猜一个继续走只会让后面的错误更难懂。
            return Err(Error::Smtp(format!("多行响应的状态码前后不一致: {line:?}")));
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(line.get(4..).unwrap_or(""));
        if bytes[3] != b'-' {
            break;
        }
    }
    Ok((code, text))
}

/// 发一条命令并要求状态码落在 `want` 里。
fn expect(pipe: &mut Pipe, cmd: &str, want: &[u16]) -> Result<(u16, String)> {
    expect_inner(pipe, cmd, want, false)
}

/// 发一条**内容本身就是凭据**的行（`AUTH PLAIN` 的载荷、`AUTH LOGIN` 的两条应答）。
///
/// 日志里只留一个记号。密码可能以任何编码出现（base64、十六进制……），
/// 事后想抹是抹不干净的 —— 只能一开始就不写。
fn expect_credential(pipe: &mut Pipe, payload: &str, want: &[u16]) -> Result<(u16, String)> {
    expect_inner(pipe, payload, want, true)
}

fn expect_inner(
    pipe: &mut Pipe,
    cmd: &str,
    want: &[u16],
    credential: bool,
) -> Result<(u16, String)> {
    // `AUTH …` 那条命令的动词留着（测试要断言走的哪条机制），参数不留。
    let printable = if credential {
        "****"
    } else if cmd.starts_with("AUTH ") {
        "AUTH ****"
    } else {
        cmd
    };
    tracing::debug!(smtp = %printable, "→");
    pipe.write_all(format!("{cmd}\r\n").as_bytes())?;
    let (code, text) = read_reply(pipe)?;
    tracing::debug!(smtp.code = code, smtp.text = %text, "←");
    if !want.contains(&code) {
        return Err(Error::Smtp(format!("{printable} 被拒（{code}）: {text}")));
    }
    Ok((code, text))
}

/// EHLO，把能力清单收下来。失败退回 HELO（有些老服务器只认 HELO）。
fn ehlo(pipe: &mut Pipe) -> Result<Vec<String>> {
    pipe.write_all(format!("EHLO {CLIENT_NAME}\r\n").as_bytes())?;
    let (code, text) = read_reply(pipe)?;
    if code != 250 {
        pipe.write_all(format!("HELO {CLIENT_NAME}\r\n").as_bytes())?;
        let (code, text) = read_reply(pipe)?;
        if code != 250 {
            return Err(Error::SmtpConnect(format!("EHLO/HELO 都被拒: {code} {text}")));
        }
        // HELO 不报能力清单，只有一行问候
        return Ok(Vec::new());
    }
    // 多行响应的文本被 `read_reply` 用空格拼起来了，按空格切回单词即可：
    // 我们只关心 `AUTH PLAIN LOGIN`、`STARTTLS` 这种关键词。
    Ok(text.split_whitespace().map(str::to_string).collect())
}

/// 能力清单里有没有某个关键字（不区分大小写）。
fn has_cap(caps: &[String], key: &str) -> bool {
    caps.iter().any(|c| c.eq_ignore_ascii_case(key))
}

/// 能力清单里的认证机制名。
///
/// 两种写法都得认：`250-AUTH PLAIN LOGIN`（机制是后面的几个词）和
/// `250-AUTH=PLAIN LOGIN`（RFC 4954 允许的紧凑写法，机制挤在同一个词里）。
/// 只认前一种的话，碰上后一种会以为服务器不要认证，直接拒发。
fn auth_mechs(caps: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, c) in caps.iter().enumerate() {
        let upper = c.to_ascii_uppercase();
        if upper == "AUTH" {
            out.extend(caps[i + 1..].iter().cloned());
        } else if let Some(rest) = upper.strip_prefix("AUTH=") {
            out.extend(rest.split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string));
        }
    }
    out
}

/// 包一层 TLS。
///
/// 证书校验用 [`TlsConnector`] 的默认策略：**不关掉校验**。测试要连自己的假
/// 服务器，是通过 [`Conn::connect_with`] 把一个「接受自签」的 connector 传进来的
/// —— 生产路径上永远是默认的那个。
fn wrap_tls(tcp: TcpStream, cfg: &Config, connector: &TlsConnector) -> Result<TlsStream<TcpStream>> {
    let host = cfg.host.clone();
    connector
        .connect(&host, tcp)
        .map_err(|e| Error::SmtpConnect(format!("TLS 握手失败（{host}）: {e}")))
}

// ================================================================= 连接

/// 一条 SMTP 会话。
pub struct Conn {
    pipe: Pipe,
    /// EHLO 报出来的能力清单，决定 AUTH 走哪条路
    caps: Vec<String>,
}

impl Conn {
    /// 按账号记录连上去。业务侧一般用这个，和 [`crate::imap::Conn::for_account`]
    /// 对称 —— 主机/端口/加密方式都记在账号里，不该让调用方再拼一遍 [`Config`]。
    pub fn for_account(account: &crate::types::Account, password: &str) -> Result<Self> {
        let is_oauth = account.auth_type == "xoauth2";
        Self::connect(
            &Config {
                host: account.smtp_host.clone(),
                port: account.smtp_port,
                security: account.smtp_security,
                username: account.smtp_username.clone(),
            },
            password,
            is_oauth,
        )
    }

    /// 连上、（按配置）升级 TLS、认证。**密码不进 [`Config`]，每次现取现用。**
    pub fn connect(cfg: &Config, password: &str, is_oauth: bool) -> Result<Self> {
        let connector = TlsConnector::builder()
            .build()
            .map_err(|e| Error::SmtpConnect(format!("建 TLS 连接器失败: {e}")))?;
        Self::connect_with(cfg, password, &connector, is_oauth)
    }

    /// 同 [`Conn::connect`]，但 TLS 用调用方给的连接器。
    ///
    /// 生产代码用不到；这是给测试留的缝 —— 假 SMTP 服务器用自签证书，
    /// 测试得传一个「接受自签」的 connector 进来才能真握手。
    pub fn connect_with(cfg: &Config, password: &str, connector: &TlsConnector, is_oauth: bool) -> Result<Self> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let tcp = TcpStream::connect(&addr)
            .map_err(|e| Error::SmtpConnect(format!("连不上 {addr}: {e}")))?;
        // 超时得设在**升级 TLS 之前**，TlsStream 会继承底层 socket 的设置
        tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
        tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();

        // 隐式 TLS（465）：连接一开始就是加密的
        let mut pipe = Pipe {
            io: match cfg.security {
                Security::Ssl => Io::Tls(wrap_tls(tcp, cfg, connector)?),
                _ => Io::Plain(tcp),
            },
            rbuf: Vec::new(),
        };

        let (code, text) = read_reply(&mut pipe)?;
        if code != 220 {
            return Err(Error::SmtpConnect(format!("问候语不是 220: {code} {text}")));
        }
        let caps = ehlo(&mut pipe)?;

        // STARTTLS（587）：明文连上，谈好了再升级
        let caps = if cfg.security == Security::StartTls {
            if !has_cap(&caps, "STARTTLS") {
                // 要求了升级但服务器不支持 —— 明文发信等于把授权码和正文裸奔，
                // 宁可不发。这是**拒绝**，不是降级。
                //
                // 归到 `Config` 而不是 `SmtpConnect`：这不是「网络连不上」，
                // 是账号设的加密方式和这个服务器对不上，得回去改账号设置。
                // 甩一句「检查网络和服务器地址」会把人支到错的方向。
                return Err(Error::Config(
                    "服务器不支持 STARTTLS，但这个账号要求加密连接".into(),
                ));
            }
            expect(&mut pipe, "STARTTLS", &[220])?;
            // 把 socket 从枚举里摘出来包 TLS。这里用 `mem::replace` 换成一个
            // 临时值是不行的（没有合法的空变体），所以按形态取出来。
            let plain = match pipe.io {
                Io::Plain(s) => s,
                Io::Tls(_) => unreachable!("STARTTLS 之前不可能是 TLS"),
            };
            pipe.io = Io::Tls(wrap_tls(plain, cfg, connector)?);
            // RFC 3207 §4.2：升级后必须重新 EHLO
            ehlo(&mut pipe)?
        } else {
            caps
        };

        // 认证
        if !cfg.username.is_empty() {
            authenticate(&mut pipe, &caps, &cfg.username, password, is_oauth)?;
        }

        Ok(Conn { pipe, caps })
    }

    /// 能力清单。测试和「发信前看看服务器支不支持什么」用。
    pub fn capabilities(&self) -> &[String] {
        &self.caps
    }

    /// 把一封信交出去。
    ///
    /// `raw` 是 [`crate::compose::Composer::build`] 的输出，一个字节都不改地发
    /// （只做 SMTP 层必须的点填充）。收件人全在 `env.to` 里，**包括 Bcc**。
    pub fn send(&mut self, env: &Envelope, raw: &str) -> Result<()> {
        if env.from.is_empty() {
            return Err(Error::Smtp("发件人地址是空的".into()));
        }
        if env.to.is_empty() {
            return Err(Error::Smtp("收件人为空，这封信没有地方可投".into()));
        }

        expect(&mut self.pipe, &format!("MAIL FROM:<{}>", env.from), &[250])?;
        for rcpt in &env.to {
            // 251 = 「我不负责这个地址，但我帮你转」。发信这侧算成功。
            expect(&mut self.pipe, &format!("RCPT TO:<{rcpt}>"), &[250, 251])?;
        }
        expect(&mut self.pipe, "DATA", &[354])?;
        write_data(&mut self.pipe, raw)?;
        let (code, text) = read_reply(&mut self.pipe)?;
        if code != 250 {
            return Err(Error::Smtp(format!("服务器收下了命令但没收下信（{code}）: {text}")));
        }
        Ok(())
    }

    /// 说再见。不叫也能发，但不叫的话服务器那边会留一条半死的连接到超时。
    pub fn quit(&mut self) -> Result<()> {
        expect(&mut self.pipe, "QUIT", &[221]).map(|_| ())
    }
}

/// 认证。优先 `PLAIN`（一条命令搞定），没有就退回 `LOGIN`（三步）。
///
/// 两种都用 base64，**载荷就是密码本身**，所以这里绝不往日志里写。
fn authenticate(
    pipe: &mut Pipe,
    caps: &[String],
    username: &str,
    secret: &str,
    is_oauth: bool,
) -> Result<()> {
    // XOAUTH2（Google 等）：`secret` 是 access_token。先试 XOAUTH2，
    // 服务器不支持就退到密码（不该发生，但稳一点）。
    if is_oauth {
        let sasl = xoauth2_sasl(username, secret);
        let (code, _) =
            expect_credential(pipe, &format!("AUTH XOAUTH2 {sasl}"), &[235, 334])
                .map_err(auth_err)?;
        if code == 334 {
            expect_credential(pipe, &sasl, &[235]).map_err(auth_err)?;
        }
        return Ok(());
    }

    let mechs = auth_mechs(caps);
    let plain_ok = mechs.iter().any(|m| m.eq_ignore_ascii_case("PLAIN"));
    let login_ok = mechs.iter().any(|m| m.eq_ignore_ascii_case("LOGIN"));

    let run = |pipe: &mut Pipe, cmd: &str, want: &[u16]| -> Result<()> {
        expect(pipe, cmd, want).map(|_| ())
    };

    if plain_ok {
        // 载荷是 `base64("\0user\0pass")` —— 第一个字节是空的「认证身份」，
        // RFC 4616 规定的。
        let payload = B64.encode(format!("\0{username}\0{secret}"));
        let (code, _) =
            expect_credential(pipe, &format!("AUTH PLAIN {payload}"), &[235, 334])
                .map_err(auth_err)?;
        if code == 334 {
            expect_credential(pipe, &payload, &[235]).map_err(auth_err)?;
        }
        return Ok(());
    }
    if login_ok {
        run(pipe, "AUTH LOGIN", &[334]).map_err(auth_err)?;
        expect_credential(pipe, &B64.encode(username), &[334]).map_err(auth_err)?;
        return expect_credential(pipe, &B64.encode(secret), &[235])
            .map(|_| ())
            .map_err(auth_err);
    }
    // 服务器没报任何机制。要么它压根不要认证（开放中继），要么它希望我们
    // 先把信交过去再说。我们有用户名却没地方用 —— 这是个该说清楚的拒绝。
    Err(Error::SmtpAuth(
        "服务器没提供认证方式，但这个账号填了用户名".into(),
    ))
}

/// XOAUTH2 的 SASL 初始响应（base64）：`user=<u>\x01auth=Bearer <t>\x01\x01`。
fn xoauth2_sasl(user: &str, token: &str) -> String {
    use base64::Engine;
    let raw = format!("user={user}\x01auth=Bearer {token}\x01\x01");
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// 把「命令被拒」重新归类成「认证失败」。
///
/// 认证失败对用户是另一回事（去改授权码，不是去查网络），所以要单列一类。
/// 这里只改错误的**类别**，载荷里仍然只有服务器的话，没有密码。
fn auth_err(e: Error) -> Error {
    match e {
        Error::Smtp(msg) => Error::SmtpAuth(msg),
        other => other,
    }
}

/// 按 SMTP 的规矩把原文写出去：逐行点填充，末尾补一个单独的 `.`。
fn write_data(pipe: &mut Pipe, raw: &str) -> Result<()> {
    let mut body = String::with_capacity(raw.len() + 16);
    let mut rest = raw;
    while !rest.is_empty() {
        let (line, next) = match rest.find('\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let line = line.strip_suffix('\r').unwrap_or(line);
        // 点填充：以 `.` 开头的行前面再补一个 `.`，收信方会自动去掉
        if line.starts_with('.') {
            body.push('.');
        }
        body.push_str(line);
        body.push_str("\r\n");
        rest = next;
    }
    // DATA 体以 CRLF 结束，然后才是单独一行的 `.`（RFC 5321 §3.3）
    body.push_str(".\r\n");
    pipe.write_all(body.as_bytes())
}

// ================================================================= 反点填充

/// 把服务器在 `DATA` 里收到的体还原成我们发的原文（测试用）。
///
/// 和 [`write_data`] 严格互逆，两边一起被测，就不怕哪天只改了一边。
pub fn undo_dot_stuffing(data: &str) -> String {
    let mut out = String::with_capacity(data.len());
    // 用序号判断是不是第一行，不能看 `out` 空不空 —— 正文第一行就是空行
    // 的话（比如 HTML 信前面有个空行），那样会把这行整个吃掉
    for (i, line) in data.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = line.strip_prefix('.').unwrap_or(line);
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(line);
    }
    out
}
