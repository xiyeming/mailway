//! 测试用的假 IMAP 服务器
//!
//! `tests/imap.rs` 和 `tests/sync.rs` 共用。起一个**真的 TCP 监听**，讲足够的
//! IMAP，让 `Conn` 连上去打。不用 mock stream 的理由：IDLE 那条路径靠的是
//! **阻塞读 + 读超时**，内存流测不出超时和并发投递，而这恰恰是最容易出错的
//! 地方。
//!
//! 它不是合规的 IMAP 服务器，只是个能骗过 `imap` crate 解析器的脚本机：
//! LIST/SELECT 的参数不解析，SEARCH 之类压根不支持。
//!
//! 状态是**可变**的，测试可以在跑的过程中改：
//!   - [`FakeServer::mail`] —— 信箱内容，加信/删信
//!   - [`FakeServer::cfg`] —— UIDVALIDITY，用来测「值变了要整箱重建」
//!   - [`FakeServer::boxes`] —— 信箱清单，CREATE/RENAME/DELETE 会改它

#![allow(dead_code)] // 共享模块，不是每个测试都用到每个 API

use base64::Engine as _;
use chrono::Utc;
use native_tls::{TlsAcceptor, TlsStream};
use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ================================================================= 行尾

/// 发一行响应。
///
/// IMAP 的行结束是 **CRLF**，`writeln!` 只给 LF —— `imap-proto` 会因此报
/// 「Unable to parse status response」，而且看不出是行尾的问题。所以这里
/// 强制补 `\r\n`，谁也别再用 `writeln!` 直接写 socket。
macro_rules! reply {
    ($out:expr, $($arg:tt)*) => {{
        let _ = write!($out, $($arg)*);
        let _ = ($out).write_all(b"\r\n");
    }};
}

// ================================================================= 夹具

/// 一封信：UID、标志、投递时间和完整 RFC 5322。
#[derive(Debug, Clone)]
pub struct Canned {
    pub uid: u32,
    /// 直接放进 `FLAGS (...)` 里的内容。
    ///
    /// **String 不是 &str**：`UID STORE` 要真改它 —— 「规则先推标志再挪箱，
    /// 新箱里的信得是已读」这种断言，假服务器得像服务器才验得了。
    pub flags: String,
    pub internal_date: &'static str,
    pub raw: &'static str,
}

impl Canned {
    /// 换一套标志（同步测试要制造「服务器上改了已读」这种变化）。
    pub fn with_flags(mut self, flags: &str) -> Self {
        self.flags = flags.into();
        self
    }
}

/// 默认的三封信，覆盖纯文本中文 / 附件 / HTML。
pub fn default_mails() -> Vec<Canned> {
    vec![
        Canned {
            uid: 1,
            flags: "\\Seen".into(),
            internal_date: "02-Oct-2016 14:06:22 +0000",
            raw: "From: =?UTF-8?B?5byg5LiJ?= <zhangsan@example.com>\r\n\
                  To: me@example.com\r\n\
                  Subject: =?UTF-8?B?56ys5LiA5bCB?=\r\n\
                  Date: Sun, 02 Oct 2016 14:06:22 +0000\r\n\
                  Message-ID: <m1@example.com>\r\n\
                  Content-Type: text/plain; charset=utf-8\r\n\
                  \r\n\
                  第一封正文\r\n",
        },
        Canned {
            uid: 2,
            flags: "".into(),
            internal_date: "03-Oct-2016 09:00:00 +0000",
            raw: "From: boss@example.com\r\n\
                  To: me@example.com\r\n\
                  Subject: Report\r\n\
                  Date: Mon, 03 Oct 2016 09:00:00 +0000\r\n\
                  Message-ID: <m2@example.com>\r\n\
                  Content-Type: multipart/mixed; boundary=bnd\r\n\
                  \r\n\
                  --bnd\r\n\
                  Content-Type: text/plain\r\n\
                  \r\n\
                  见附件\r\n\
                  --bnd\r\n\
                  Content-Type: application/pdf\r\n\
                  Content-Disposition: attachment; filename=\"a.pdf\"\r\n\
                  \r\n\
                  PDFBYTES\r\n\
                  --bnd--\r\n",
        },
        Canned {
            uid: 3,
            flags: "\\Flagged".into(),
            internal_date: "04-Oct-2016 18:30:00 +0000",
            raw: "From: html@example.com\r\n\
                  Subject: HTML 信\r\n\
                  Message-ID: <m3@example.com>\r\n\
                  Content-Type: text/html; charset=utf-8\r\n\
                  \r\n\
                  <p>富文本</p>\r\n",
        },
    ]
}

/// 服务端**初始**的信箱列表。跑起来之后是动态的：`CREATE`/`RENAME`/`DELETE`
/// 会增删改（见 `SharedBoxes`）。SELECT/APPEND 只认清单里的 ——
/// 不然「选一个不存在的文件夹」没法测。
///
/// `&XfJT0ZAB-` 是「已发送」（U+5DF2 U+53D1 U+9001 → UTF-16BE → base64 变体）。
/// `&U,BTFw-` 是台北，RFC 3501 §5.1.3 的例子，别拿它当「已发送」。
pub const KNOWN_FOLDERS: &[&str] = &["INBOX", "&XfJT0ZAB-", "Archive"];

/// 服务端可被测试驱动的指令。
pub enum Ev {
    /// 命令行后头还跟着一个字面量（APPEND 的原文），读线程在等一句续行。
    /// 主循环回一句 `+ …` 放行它；命令本身在随后那条 [`Ev::Line`] 里。
    ///
    /// **续行只能由主循环写**。读线程自己写的话，[`Ev::Exists`] 会和它在
    /// socket 上叠起来，客户端会把 `* 3 EXISTS` 当成续行 —— `imap` crate
    /// 见到的续行不以 `+` 开头就直接报 [`Error::Append`]。
    Pending,
    /// 一条命令行。行末带 `{n}` 的话，`literal` 是紧接着的那 n 个字节
    /// （APPEND 的原文）。**必须和命令一起读掉**，不然那 n 个字节会被
    /// 下一轮当成命令行，整个会话就错位了。
    Line {
        cmd: String,
        literal: Option<Vec<u8>>,
    },
    /// 让 IDLE 中的连接推一条 EXISTS
    Exists(u32),
    Closed,
}

/// 客户端 APPEND 进来的东西。
///
/// 两份信息都在：`raw` 是它发来的原文（字节级断言用），`uid` / `internal_date`
/// 是服务器收下之后给它编的号和时间。**APPEND 进来的信真存进信箱**（见
/// [`folder_msgs`]），下一次 SELECT/FETCH 取得出来 —— 假服务器要像服务器：
/// 「自己发的那封，同步回来能在已发送里看见」这条路得能走。
#[derive(Debug, Clone)]
pub struct Appended {
    /// 目标信箱的 **IMAP 名字**（可能是 modified UTF-7，比如 `&XfJT0ZAB-`）
    pub mailbox: String,
    /// flag 列表，**不带外层括号**（`\\Seen`、`\\Seen \\Flagged` 或空串）。
    /// FETCH 那边发的是 `FLAGS ({flags})`，这里再带括号就成了 `FLAGS ((\Seen))`
    /// —— `imap-proto` 解不出来，取信直接报 "Unable to parse status response"。
    pub flags: String,
    /// 服务器编的 UID（该信箱里最大 UID + 1）
    pub uid: u32,
    /// 服务器给的 INTERNALDATE
    pub internal_date: String,
    /// 原文那 n 个字节，一个不改
    pub raw: Vec<u8>,
}

/// 服务器的可变配置。
#[derive(Debug, Clone)]
pub struct FakeCfg {
    pub uid_validity: u32,
    /// 让 `LOGOUT` 的响应**解析不了**。模拟「副本已经存上了，收尾时却出了
    /// 岔子」—— 服务器在 APPEND 之后掉线、中间盒子乱改响应，结果都一样。
    pub logout_broken: bool,
}

impl Default for FakeCfg {
    fn default() -> Self {
        FakeCfg { uid_validity: 1000, logout_broken: false }
    }
}

pub struct FakeServer {
    pub addr: SocketAddr,
    /// 服务端收到的原始命令行，用来断言「客户端到底发了什么」
    pub log: Arc<Mutex<Vec<String>>>,
    /// 信箱内容。测试可以直接改，模拟「服务器来了新信」。
    pub mail: Arc<Mutex<Vec<Canned>>>,
    /// UIDVALIDITY 之类的可变配置。
    pub cfg: Arc<Mutex<FakeCfg>>,
    /// 客户端 APPEND 进来的东西，按顺序。断言「已发送」里落了什么就是看它。
    pub appends: Arc<Mutex<Vec<Appended>>>,
    /// 信箱清单（wire 名）。CREATE/RENAME/DELETE 改的就是它。
    pub boxes: Arc<Mutex<Vec<String>>>,
    /// 每条连接一个发送端。广播用，因为 `mpsc` 只能一对一。
    peers: Arc<Mutex<Vec<Sender<Ev>>>>,
}

impl FakeServer {
    pub fn start() -> Self {
        Self::start_with(default_mails(), FakeCfg::default())
    }

    pub fn start_with(mail: Vec<Canned>, cfg: FakeCfg) -> Self {
        Self::start_on("127.0.0.1:0", mail, cfg)
    }

    /// 监听指定地址。端口给 `0` 就让系统挑一个（测试用），给具体端口就是
    /// 给别的进程连的 —— `core/src/bin/fake-imap.rs` 起的开发服务器就是这么用。
    ///
    /// 返回值必须有人拿着：accept 线程是 detached 的，但 [`Drop`] 会广播
    /// `Closed` 让所有连接退出。
    pub fn start_on(bind: &str, mail: Vec<Canned>, cfg: FakeCfg) -> Self {
        let listener = TcpListener::bind(bind).unwrap_or_else(|e| panic!("bind {bind}: {e}"));
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let peers: Arc<Mutex<Vec<Sender<Ev>>>> = Arc::new(Mutex::new(Vec::new()));
        let mail = Arc::new(Mutex::new(mail));
        let cfg = Arc::new(Mutex::new(cfg));
        let appends = Arc::new(Mutex::new(Vec::new()));
        let boxes = Arc::new(Mutex::new(KNOWN_FOLDERS.iter().map(|s| s.to_string()).collect()));

        {
            let log = Arc::clone(&log);
            let peers = Arc::clone(&peers);
            let mail = Arc::clone(&mail);
            let cfg = Arc::clone(&cfg);
            let appends = Arc::clone(&appends);
            let boxes = Arc::clone(&boxes);
            // accept 要循环：一个测试里可能先后连上好几次
            // （登录成功用一条、登录失败再开一条）。只 accept 一次的话，
            // 第二条连接会一直等一个永远不来的响应 —— 整个套件挂死。
            let _handle = thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { break };
                    let (tx, ev_rx) = mpsc::channel::<Ev>();
                    peers.lock().unwrap().push(tx);
                    let log = Arc::clone(&log);
                    let mail = Arc::clone(&mail);
                    let cfg = Arc::clone(&cfg);
                    let appends = Arc::clone(&appends);
                    let boxes = Arc::clone(&boxes);
                    thread::spawn(move || serve(stream, log, ev_rx, mail, cfg, appends, boxes));
                }
            });
        }

        FakeServer { addr, log, mail, cfg, appends, boxes, peers }
    }

    /// 追加一封信，返回它的 UID。模拟「服务器来了新信」。
    pub fn push_mail(&self, uid: u32, flags: &str, raw: &'static str) -> u32 {
        self.mail.lock().unwrap().push(Canned {
            uid,
            flags: flags.into(),
            internal_date: "05-Oct-2016 12:00:00 +0000",
            raw,
        });
        uid
    }

    /// 改一封信的标志。模拟「在别的设备上标了已读」。
    pub fn set_flags(&self, uid: u32, flags: &str) {
        for m in self.mail.lock().unwrap().iter_mut() {
            if m.uid == uid {
                m.flags = flags.into();
            }
        }
    }

    /// 换 UIDVALIDITY。模拟「服务器重建了信箱」。
    pub fn set_uid_validity(&self, v: u32) {
        self.cfg.lock().unwrap().uid_validity = v;
    }

    /// 让 `LOGOUT` 失败。测「收尾失败不能把已经存好的副本算成没存上」。
    pub fn set_logout_broken(&self, on: bool) {
        self.cfg.lock().unwrap().logout_broken = on;
    }

    pub fn push_exists(&self, n: u32) {
        for tx in self.peers.lock().unwrap().iter() {
            tx.send(Ev::Exists(n)).ok();
        }
    }

    pub fn commands(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// 客户端 APPEND 进来的东西，按顺序。
    pub fn appends(&self) -> Vec<Appended> {
        self.appends.lock().unwrap().clone()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        for tx in self.peers.lock().unwrap().iter() {
            tx.send(Ev::Closed).ok();
        }
        // 不 join：服务端可能还在等 DONE，测试进程退出会带走它
    }
}

// ================================================================= 服务端

struct State {
    idle_tag: Option<String>,
    /// IDLE 之前就到的 EXISTS，进 IDLE 后立刻补发
    pending_exists: Option<u32>,
    /// 当前选中的信箱。UID 只在选中的箱子里有意义，FETCH 之前得知道是哪个。
    selected: Option<String>,
}

/// 取信时看到的一封信。
///
/// 信箱里现在有**两种**信：夹具放的（[`Canned`]）和客户端 APPEND 进来的
/// （[`Appended`]）。取信那侧不该知道这个区别 —— 它只要 UID、标志、时间和原文，
/// 所以借着两个锁各自的生命周期拼一个视图出来。原文用 [`Cow`]：夹具那几封
/// 直接借，APPEND 那几封是线上的字节，得转成 UTF-8 才能当字符串发出去。
struct Msg<'a> {
    uid: u32,
    flags: &'a str,
    internal_date: &'a str,
    raw: Cow<'a, str>,
}

/// 每个信箱里有什么信，按 UID 排。
///
/// 夹具**只给 INBOX 放信**，其它箱子的信全是 APPEND 进来的。一开始所有箱子
/// 共用同一份列表，结果「已发送」里出现三封和收件箱一模一样的信 —— 看演示的人
/// 会以为同步把信箱串了。假服务器要像服务器：信箱之间互不相干。
fn folder_msgs<'a>(name: &str, canned: &'a [Canned], appends: &'a [Appended]) -> Vec<Msg<'a>> {
    let mut v: Vec<Msg> = if name.eq_ignore_ascii_case("INBOX") {
        canned
            .iter()
            .map(|m| Msg {
                uid: m.uid,
                flags: &m.flags,
                internal_date: m.internal_date,
                raw: Cow::Borrowed(m.raw),
            })
            .collect()
    } else {
        Vec::new()
    };
    v.extend(
        appends
            .iter()
            .filter(|a| a.mailbox.eq_ignore_ascii_case(name))
            .map(|a| Msg {
                uid: a.uid,
                flags: &a.flags,
                internal_date: &a.internal_date,
                raw: String::from_utf8_lossy(&a.raw),
            }),
    );
    v.sort_by_key(|m| m.uid);
    v
}

type SharedMail = Arc<Mutex<Vec<Canned>>>;
type SharedCfg = Arc<Mutex<FakeCfg>>;
type SharedAppends = Arc<Mutex<Vec<Appended>>>;
/// 信箱清单（wire 名，可能是 modified UTF-7）。从 [`KNOWN_FOLDERS`] 播种，
/// 之后 CREATE/RENAME/DELETE 增删改 —— 服务器的信箱本来就是活的。
type SharedBoxes = Arc<Mutex<Vec<String>>>;

fn serve(
    stream: TcpStream,
    log: Arc<Mutex<Vec<String>>>,
    ev_rx: Receiver<Ev>,
    mail: SharedMail,
    cfg: SharedCfg,
    appends: SharedAppends,
    boxes: SharedBoxes,
) {
    let mut out = stream.try_clone().expect("try_clone");
    let mut st = State { idle_tag: None, pending_exists: None, selected: None };

    let (tx, rx) = mpsc::channel::<Ev>();
    // 读线程要主循环回一句续行之后才敢读原文。**读线程自己不写 socket** ——
    // 理由见 [`Ev::Pending`]。
    let (go_tx, go_rx) = mpsc::channel::<()>();
    {
        let mut r = BufReader::new(stream.try_clone().expect("try_clone"));
        thread::spawn(move || loop {
            let mut line = String::new();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    tx.send(Ev::Closed).ok();
                    break;
                }
                Ok(_) => {
                    if line.trim_end().is_empty() {
                        continue;
                    }
                    // 行末是 `{n}` 的话，后面还跟着 n 个字节的原文（APPEND 的信体）。
                    // **必须读掉**，不然那 n 个字节会被下一轮当成命令行。
                    let literal = match literal_len(&line) {
                        Some(n) => {
                            // 客户端要先听到一句 `+ …` 才肯发原文（RFC 3501
                            // §6.3.11 的字面量续行），所以先请主循环回一句。
                            if tx.send(Ev::Pending).is_err() {
                                break;
                            }
                            if go_rx.recv().is_err() {
                                break;
                            }
                            let mut buf = vec![0u8; n + 2]; // 原文 + 行尾 CRLF
                            if r.read_exact(&mut buf).is_err() {
                                tx.send(Ev::Closed).ok();
                                break;
                            }
                            buf.truncate(n);
                            Some(buf)
                        }
                        None => None,
                    };
                    tx.send(Ev::Line { cmd: line, literal }).ok();
                }
            }
        });
    }

    let _ = reply!(out, "* OK [CAPABILITY IMAP4rev1 IDLE MOVE AUTH=PLAIN] Fake ready");

    loop {
        // 两条事件源汇到一起：socket 读线程 + 测试驱动
        let ev = match rx.try_recv() {
            Ok(e) => e,
            Err(mpsc::TryRecvError::Empty) => match ev_rx.try_recv() {
                Ok(e) => e,
                Err(mpsc::TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
            },
            Err(mpsc::TryRecvError::Disconnected) => break,
        };

        match ev {
            Ev::Closed => break,
            Ev::Pending => {
                // 字面量续行。客户端（`imap` crate）拿到这句才把原文发过来。
                let _ = reply!(out, "+ Ready for literal");
                go_tx.send(()).ok();
            }
            Ev::Exists(n) => {
                if st.idle_tag.is_some() {
                    let _ = reply!(out, "* {n} EXISTS");
                } else {
                    st.pending_exists = Some(n);
                }
            }
            Ev::Line { cmd, literal } => {
                log.lock().unwrap().push(cmd.trim_end().to_string());
                handle_command(&mut out, &mut st, &cmd, literal.as_deref(), &mail, &cfg, &appends, &boxes);
            }
        }
    }
}

fn handle_command(
    out: &mut TcpStream,
    st: &mut State,
    line: &str,
    literal: Option<&[u8]>,
    mail: &SharedMail,
    cfg: &SharedCfg,
    appends: &SharedAppends,
    boxes: &SharedBoxes,
) {
    let t = line.trim_end();
    let mut it = t.splitn(3, ' ');
    let tag = it.next().unwrap_or("");
    let cmd = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("");

    // DONE 没有 tag：它挂在当前 IDLE 下
    if cmd.eq_ignore_ascii_case("DONE") || t.eq_ignore_ascii_case("DONE") {
        if let Some(idle_tag) = st.idle_tag.take() {
            let _ = reply!(out, "{idle_tag} OK IDLE completed");
        }
        return;
    }

    match cmd.to_ascii_uppercase().as_str() {
        "CAPABILITY" => {
            let _ = reply!(out, "* CAPABILITY IMAP4rev1 IDLE MOVE AUTH=PLAIN");
            let _ = reply!(out, "{tag} OK CAPABILITY completed");
        }
        "LOGIN" => {
            // 只认 "good" 这个密码，方便测认证失败。
            // imap crate 会给参数加引号（LOGIN "me@x" "good"），先剥掉。
            let pass = rest.split_whitespace().nth(1).unwrap_or("").trim_matches('"');
            if pass == "good" {
                let _ = reply!(out, "{tag} OK [CAPABILITY IMAP4rev1 IDLE MOVE] LOGIN completed");
            } else {
                let _ = reply!(out, "{tag} NO [AUTHENTICATIONFAILED] invalid credentials");
            }
        }
        "LIST" | "LSUB" => {
            for name in boxes.lock().unwrap().iter() {
                let attrs = if name == "Archive" {
                    "\\Noselect \\HasChildren"
                } else {
                    "\\HasNoChildren"
                };
                let _ = reply!(out, "* LIST ({attrs}) \"/\" \"{name}\"");
            }
            let _ = reply!(out, "{tag} OK LIST completed");
        }
        "SELECT" | "EXAMINE" => {
            // 只认清单里的箱子 —— 不然「选一个不存在的文件夹」就没法测
            let name = rest.trim_matches('"');
            if !boxes.lock().unwrap().iter().any(|b| b == name) {
                let _ = reply!(out, "{tag} NO [NONEXISTENT] no such mailbox");
                return;
            }
            // 记住选中了哪个：后面的 UID FETCH 要按它取信
            st.selected = Some(name.to_string());
            let mail = mail.lock().unwrap();
            let all = appends.lock().unwrap();
            let mine = folder_msgs(name, mail.as_slice(), all.as_slice());
            let uid_next = mine.iter().map(|m| m.uid).max().unwrap_or(0) + 1;
            let unseen = mine.iter().position(|m| m.flags.is_empty()).map(|i| i + 1);
            let _ = reply!(out, "* {} EXISTS", mine.len());
            let _ = reply!(out, "* 0 RECENT");
            let _ = reply!(out, "* OK [UIDVALIDITY {}] UIDs valid", cfg.lock().unwrap().uid_validity);
            let _ = reply!(out, "* OK [UIDNEXT {uid_next}] Predicted next UID");
            let _ = reply!(out, "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)");
            if let Some(u) = unseen {
                let _ = reply!(out, "* OK [UNSEEN {u}] First unseen");
            }
            let _ = reply!(out, "{tag} OK [READ-WRITE] SELECT completed");
        }
        "APPEND" => {
            // `APPEND "已发送" (\Seen) {42}`，后面跟着 42 字节原文。
            // 信箱名可能是 modified UTF-7（`&XfJT0ZAB-`），原样收下。
            let Some((mailbox, tail)) = take_token(rest) else {
                let _ = reply!(out, "{tag} BAD APPEND needs a mailbox");
                return;
            };
            let mailbox = mailbox.trim_matches('"').to_string();
            // flag 列表是可选的（`(\Seen)`）。日期时间参数也合法，假服务器不支持。
            // 括号**剥掉再存**：`Appended.flags` 只要里面那串，见它的文档注释。
            let tail = tail.trim_start();
            let flags = if tail.starts_with('(') {
                let end = tail.find(')').unwrap_or(tail.len());
                tail[1..end].to_string()
            } else {
                String::new()
            };
            let Some(raw) = literal else {
                let _ = reply!(out, "{tag} BAD APPEND needs a literal");
                return;
            };
            // 只认清单里的箱子。**缺箱子回 `NO [TRYCREATE]`**：
            // 「已发送」没建起来的时候信照样发得出去，只是不留副本 ——
            // 那条路（`core/src/send.rs` 的 `saved_to_sent = false`）必须能测。
            if !boxes.lock().unwrap().iter().any(|b| *b == mailbox) {
                let _ = reply!(out, "{tag} NO [TRYCREATE] no such mailbox");
                return;
            }
            let uid_validity = cfg.lock().unwrap().uid_validity;
            let mut all = appends.lock().unwrap();
            // UID 是**这个信箱里**最大 UID + 1，不是全局计数：UID 只在信箱内唯一
            // （RFC 3501 §2.3.1.1），「已发送」里的第一封就是 UID 1，和 INBOX
            // 里的信各编各的号。
            let uid = all
                .iter()
                .filter(|a| a.mailbox == mailbox)
                .map(|a| a.uid)
                .max()
                .unwrap_or(0)
                + 1;
            // 收下时间就是现在。INTERNALDATE 由**服务器**定（RFC 3501 §2.3.3），
            // 客户端给的那个日期参数是可选的，上面说了假服务器不支持。
            let internal_date = Utc::now().format("%d-%b-%Y %H:%M:%S +0000").to_string();
            all.push(Appended { mailbox, flags, uid, internal_date, raw: raw.to_vec() });
            drop(all);
            let _ = reply!(out, "{tag} OK [APPENDUID {uid_validity} {uid}] APPEND completed");
        }
        "CREATE" | "RENAME" | "DELETE" => {
            // 信箱的增删改。清单是**全局**的（所有连接看同一份），所以这里
            // 锁 `boxes` 而不是看 `st`。名字是 wire 形态（modified UTF-7），
            // 真服务器就是这么比的。
            let Some((first, tail)) = take_token(rest) else {
                let _ = reply!(out, "{tag} BAD {cmd} needs a mailbox");
                return;
            };
            let first = first.trim_matches('"');
            let mut list = boxes.lock().unwrap();

            // INBOX：RENAME 在协议里有特殊语义（搬空），DELETE 干脆不许
            // （RFC 3501 §6.3.4）。搬夹具信那种语义假服务器不做 —— 我们的
            // 客户端本来也不许对 INBOX 动这两样，犯不上为测不到的路写搬箱逻辑。
            if (cmd.eq_ignore_ascii_case("RENAME") || cmd.eq_ignore_ascii_case("DELETE"))
                && first.eq_ignore_ascii_case("INBOX")
            {
                let _ = reply!(out, "{tag} NO [CANNOT] this fake does not touch INBOX");
                return;
            }

            if cmd.eq_ignore_ascii_case("RENAME") {
                let Some((second, _)) = take_token(tail) else {
                    let _ = reply!(out, "{tag} BAD RENAME needs two mailboxes");
                    return;
                };
                let second = second.trim_matches('"');
                if !list.iter().any(|b| b == first) {
                    let _ = reply!(out, "{tag} NO [NONEXISTENT] no such mailbox");
                    return;
                }
                if list.iter().any(|b| b == second) {
                    let _ = reply!(out, "{tag} NO [ALREADYEXISTS] mailbox already exists");
                    return;
                }
                for b in list.iter_mut() {
                    if b == first {
                        *b = second.to_string();
                    }
                }
                drop(list);
                // 信跟着箱子走，不然「改完名信丢了」—— 那是 APPEND 那条
                // 回读路径（`folder_msgs` 按信箱名取）最怕的假象。
                for a in appends.lock().unwrap().iter_mut() {
                    if a.mailbox == first {
                        a.mailbox = second.to_string();
                    }
                }
                let _ = reply!(out, "{tag} OK RENAME completed");
            } else if cmd.eq_ignore_ascii_case("CREATE") {
                if list.iter().any(|b| b == first) {
                    let _ = reply!(out, "{tag} NO [ALREADYEXISTS] mailbox already exists");
                    return;
                }
                list.push(first.to_string());
                let _ = reply!(out, "{tag} OK CREATE completed");
            } else {
                // DELETE：箱里的信一起走（和 SQLite 那边 ON DELETE CASCADE 对齐）
                let before = list.len();
                list.retain(|b| b != first);
                if list.len() == before {
                    let _ = reply!(out, "{tag} NO [NONEXISTENT] no such mailbox");
                    return;
                }
                drop(list);
                appends.lock().unwrap().retain(|a| a.mailbox != first);
                let _ = reply!(out, "{tag} OK DELETE completed");
            }
        }
        "UID" => {
            let mut it2 = rest.splitn(2, ' ');
            let sub = it2.next().unwrap_or("").to_ascii_uppercase();
            let args = it2.next().unwrap_or("");
            match sub.as_str() {
                "FETCH" => uid_fetch(out, tag, args, mail, appends, st.selected.as_deref()),
                "STORE" => {
                    // `UID STORE <set> <±FLAGS[.SILENT]> (...)` —— 真改标志。
                    // 以前只回 OK 不动状态，「规则先推标志再挪箱，新箱里的信
                    // 是已读」就没法验 —— 假服务器得像服务器。锁的顺序和
                    // SELECT/MOVE 一致（先 mail 后 appends），免得两条连接
                    // 各锁一个等对方（AB-BA）。
                    let Some((set, tail)) = take_token(args) else {
                        let _ = reply!(out, "{tag} BAD UID STORE needs a set");
                        return;
                    };
                    let Some((op, tail)) = take_token(tail) else {
                        let _ = reply!(out, "{tag} BAD UID STORE needs a modification");
                        return;
                    };
                    let op = op.trim_end_matches(".SILENT");
                    if !matches!(op, "FLAGS" | "+FLAGS" | "-FLAGS") {
                        let _ = reply!(out, "{tag} BAD unknown modification {op}");
                        return;
                    }
                    let list = tail.trim().trim_start_matches('(').trim_end_matches(')');
                    let want: Vec<&str> = list.split_whitespace().collect();
                    let Some(src) = st.selected.clone() else {
                        let _ = reply!(out, "{tag} BAD no mailbox selected");
                        return;
                    };
                    {
                        let mut mail = mail.lock().unwrap();
                        for m in mail.iter_mut() {
                            // 夹具只在 INBOX（见 folder_msgs）
                            if src.eq_ignore_ascii_case("INBOX") && uid_set_matches(set, m.uid) {
                                m.flags = merge_flags(&m.flags, op, &want);
                            }
                        }
                        let mut all = appends.lock().unwrap();
                        for a in all.iter_mut() {
                            if a.mailbox.eq_ignore_ascii_case(&src) && uid_set_matches(set, a.uid) {
                                a.flags = merge_flags(&a.flags, op, &want);
                            }
                        }
                    }
                    let _ = reply!(out, "{tag} OK UID STORE completed");
                }
                "MOVE" => {
                    // `UID MOVE <uid-set> "<mailbox>"`（RFC 6851）：把选中信箱
                    // 里的信挪到目标信箱，UID 按**目标信箱**的 UIDNEXT 重发 ——
                    // 真服务器就这么干（信到新箱就是新 UID）。不发 EXPUNGE：
                    // MOVE 的卖点之一就是不惊动序列号。
                    let Some((set, tail)) = take_token(args) else {
                        let _ = reply!(out, "{tag} BAD UID MOVE needs a set");
                        return;
                    };
                    let Some((mbox, _)) = take_token(tail) else {
                        let _ = reply!(out, "{tag} BAD UID MOVE needs a mailbox");
                        return;
                    };
                    let mbox = mbox.trim_matches('"').to_string();
                    let Some(src) = st.selected.clone() else {
                        let _ = reply!(out, "{tag} BAD no mailbox selected");
                        return;
                    };
                    if !boxes.lock().unwrap().iter().any(|b| *b == mbox) {
                        let _ = reply!(out, "{tag} NO [TRYCREATE] no such mailbox");
                        return;
                    }
                    if src == mbox {
                        let _ = reply!(out, "{tag} NO [CANNOT] already in that mailbox");
                        return;
                    }
                    // 锁的顺序和 SELECT 一致（先 mail 后 appends），别和别的
                    // 连接凑成 AB-BA。先把要搬的抄成自有数据再动手 ——
                    // folder_msgs 的返回值借着这两把锁，边迭代边改是编译不过的。
                    let mut mail = mail.lock().unwrap();
                    let mut all = appends.lock().unwrap();
                    let moving: Vec<(u32, String, String, Vec<u8>)> = folder_msgs(&src, &mail, &all)
                        .iter()
                        .filter(|m| uid_set_matches(set, m.uid))
                        .map(|m| {
                            (m.uid, m.flags.to_string(), m.internal_date.to_string(), m.raw.clone().into_owned().into_bytes())
                        })
                        .collect();
                    let mut next = folder_msgs(&mbox, &mail, &all)
                        .iter()
                        .map(|m| m.uid)
                        .max()
                        .unwrap_or(0)
                        + 1;
                    if moving.is_empty() {
                        let _ = reply!(out, "{tag} NO [NONEXISTENT] no such message");
                        return;
                    }
                    for (uid, flags, internal_date, raw) in moving {
                        // 信从哪儿来决定从哪儿拿走：夹具信在 mail 里（INBOX 专属），
                        // APPEND / 以前搬进来的在 appends 里
                        let before = all.len();
                        all.retain(|a| !(a.mailbox == src && a.uid == uid));
                        if all.len() == before {
                            mail.retain(|c| c.uid != uid);
                        }
                        all.push(Appended {
                            mailbox: mbox.clone(),
                            flags,
                            uid: next,
                            internal_date,
                            raw,
                        });
                        next += 1;
                    }
                    let _ = reply!(out, "{tag} OK MOVE completed");
                }
                "EXPUNGE" => {
                    // `UID EXPUNGE <set>`（RFC 4315 UIDPLUS）：只删**指定集合里
                    // 且打了 \Deleted** 的信。彻底删除走这条；裸 `EXPUNGE` 是
                    // 没有 UIDPLUS 的退化路径，删整个信箱的 \Deleted。
                    let Some((set, _)) = take_token(args) else {
                        let _ = reply!(out, "{tag} BAD UID EXPUNGE needs a set");
                        return;
                    };
                    expunge(out, tag, mail, appends, st.selected.as_deref(), Some(set));
                }
                _ => {
                    let _ = reply!(out, "{tag} BAD unknown UID command");
                }
            }
        }
        "EXPUNGE" => {
            // 裸 `EXPUNGE`：整个选中信箱的 \Deleted 一起删。语义是老协议下
            // 「删信」的唯一做法，`Conn::uid_expunge` 在 UIDPLUS 失败后退回它。
            expunge(out, tag, mail, appends, st.selected.as_deref(), None);
        }
        "NOOP" => {
            let _ = reply!(out, "{tag} OK NOOP completed");
        }
        "LOGOUT" => {
            // `* BYE` 后面**必须有正文**（RFC 3501 的 `text = 1*TEXT-CHAR`）。
            // 光秃秃的 `* BYE` 不合语法，`imap-proto` 会报 `Invalid`，客户端
            // 的 `logout()` 就成了「Unable to parse status response」。这个坑
            // 踩过一次，所以 `logout_broken` 也故意拿它来制造失败。
            if cfg.lock().unwrap().logout_broken {
                let _ = reply!(out, "* BYE");
                return;
            }
            let _ = reply!(out, "* BYE fake server logging out");
            let _ = reply!(out, "{tag} OK LOGOUT completed");
        }
        "IDLE" => {
            st.idle_tag = Some(tag.to_string());
            let _ = reply!(out, "+ idling");
            if let Some(n) = st.pending_exists.take() {
                let _ = reply!(out, "* {n} EXISTS");
            }
        }
        _ => {
            let _ = reply!(out, "{tag} BAD unsupported");
        }
    }
}

/// 命令行末尾的 `{n}` —— 紧跟在后面的原文长度（APPEND）。
///
/// 同步字面量写成 `{n+}`，先把 `+` 去掉。只认**行末**那个：`BODY[] {42}`
/// 这种是服务端发出去的，方向不对，而且假服务器也不支持那种命令。
fn literal_len(line: &str) -> Option<usize> {
    let t = line.trim_end_matches(['\r', '\n']);
    let t = t.strip_suffix('+').unwrap_or(t);
    let inner = t.strip_suffix('}')?;
    let open = inner.rfind('{')?;
    let n = &inner[open + 1..];
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// 命令参数里的第一个 token：引号包起来的算一个（中间可以有空格），
/// 否则按空白切。返回 `(token, 剩下的)`。
fn take_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        Some((&s[..end + 2], &rest[end + 1..]))
    } else {
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        Some((&s[..end], &s[end..]))
    }
}

/// `EXPUNGE` / `UID EXPUNGE <set>` 的公共实现：删掉选中信箱里打了
/// `\Deleted`（`set` 给了还要落在集合里）的信，每删一封发一行
/// `* <seq> EXPUNGE`。序列号要照着现场数 —— 删一封，后面的信整体往前
/// 挪一位，所以 seq 不跟着涨。
fn expunge(
    out: &mut TcpStream,
    tag: &str,
    mail: &SharedMail,
    appends: &SharedAppends,
    selected: Option<&str>,
    set: Option<&str>,
) {
    let Some(src) = selected else {
        let _ = reply!(out, "{tag} BAD no mailbox selected");
        return;
    };
    // 先把「信箱现在的样子」抄成自有数据再动手（folder_msgs 借着锁），
    // 拿走信的口径和 MOVE 一致：先 appends 后 mail，别把别的信箱的同号信碰了。
    let snapshot: Vec<(u32, String)> = {
        let mail = mail.lock().unwrap();
        let all = appends.lock().unwrap();
        folder_msgs(&src, &mail, &all)
            .iter()
            .map(|m| (m.uid, m.flags.to_string()))
            .collect()
    };
    let mut mail = mail.lock().unwrap();
    let mut all = appends.lock().unwrap();
    let mut seq = 1;
    for (uid, flags) in snapshot {
        let flagged = flags
            .split_whitespace()
            .any(|f| f.eq_ignore_ascii_case("\\deleted"));
        let in_set = set.map(|s| uid_set_matches(s, uid)).unwrap_or(true);
        if flagged && in_set {
            let before = all.len();
            all.retain(|a| !(a.mailbox == src && a.uid == uid));
            if all.len() == before {
                mail.retain(|c| c.uid != uid);
            }
            let _ = reply!(out, "* {seq} EXPUNGE");
        } else {
            seq += 1;
        }
    }
    let _ = reply!(out, "{tag} OK EXPUNGE completed");
}

fn uid_fetch(
    out: &mut TcpStream,
    tag: &str,
    args: &str,
    mail: &SharedMail,
    appends: &SharedAppends,
    selected: Option<&str>,
) {
    // args 形如 `1:3 (UID FLAGS ...)`、`2 (BODY.PEEK[])`、`1:* (UID FLAGS)`。
    //
    // **必须按集合过滤**：不滤的话 `uid_fetch_raw(2)` 会拿到第 1 封
    // （客户端取第一条命中），这条坑已经被测试逮住过一次。
    let set = args.split_whitespace().next().unwrap_or("");
    let upper = args.to_ascii_uppercase();
    let want_header = upper.contains("HEADER");
    let want_body = upper.contains("BODY");

    // 锁的顺序和 SELECT 那边一致（先 mail 后 appends），免得两边各锁一半。
    let mail = mail.lock().unwrap();
    let all = appends.lock().unwrap();
    // 只发**当前选中**那个信箱的信，别把整个夹具倒出来
    let mine = folder_msgs(selected.unwrap_or("INBOX"), mail.as_slice(), all.as_slice());

    // RFC 3501 §6.4.8：`n:*` **总是**包含信箱里 UID 最大的那一封，哪怕 `n`
    // 比它还大。不模拟这一点，同步引擎「跳过已收过的」那条分支就永远跑不到
    // —— 而那正是每次同步都把最后一封重算一遍的坑。
    let has_star = set.split(',').any(|p| p.trim().ends_with(":*"));
    let highest = mine.iter().map(|m| m.uid).max();

    for (i, m) in mine.iter().enumerate() {
        // 序号是**信箱里的位置**，不是本次响应里的第几条
        let seq = i + 1;
        let is_star_tail = has_star && highest == Some(m.uid);
        if !uid_set_matches(set, m.uid) && !is_star_tail {
            continue;
        }

        if want_header {
            let hdr = header_block(&m.raw);
            let _ = write!(
                out,
                "* {seq} FETCH (UID {} FLAGS ({}) RFC822.SIZE {} INTERNALDATE \"{}\" BODY[HEADER] {{{}}}\r\n",
                m.uid, m.flags, m.raw.len(), m.internal_date, hdr.len(),
            );
            let _ = out.write_all(hdr);
            let _ = out.write_all(b")\r\n");
        } else if want_body {
            let _ = write!(
                out,
                "* {seq} FETCH (UID {} FLAGS ({}) RFC822.SIZE {} INTERNALDATE \"{}\" BODY[] {{{}}}\r\n",
                m.uid, m.flags, m.raw.len(), m.internal_date, m.raw.len(),
            );
            let _ = out.write_all(m.raw.as_bytes());
            let _ = out.write_all(b")\r\n");
        } else {
            // 只要标志：别把正文也发出去（那是几百 KB 的浪费）
            let _ = reply!(
                out,
                "* {seq} FETCH (UID {} FLAGS ({}))",
                m.uid,
                m.flags
            );
        }
    }
    let _ = reply!(out, "{tag} OK UID FETCH completed");
}

/// `BODY[HEADER]` 的内容含末尾那个空行（RFC 3501 的 HEADER 定义）。
fn header_block(raw: &str) -> &[u8] {
    let end = raw.find("\r\n\r\n").map(|i| i + 4).unwrap_or(raw.len());
    &raw.as_bytes()[..end]
}

/// IMAP 的 UID 集：`"5"`、`"1:100"`、`"1:*"`、`"1,3:5"`。`*` 是无穷。
pub fn uid_set_matches(set: &str, uid: u32) -> bool {
    set.split(',').any(|part| {
        let part = part.trim();
        if part.is_empty() {
            return false;
        }
        let Some((lo, hi)) = part.split_once(':') else {
            return part.parse::<u32>().is_ok_and(|n| n == uid);
        };
        let Ok(lo) = lo.parse::<u32>() else { return false };
        let hi = if hi == "*" {
            u32::MAX
        } else {
            let Ok(h) = hi.parse::<u32>() else { return false };
            h
        };
        uid >= lo && uid <= hi
    })
}

/// 按 `UID STORE` 的三种改法合成新标志串：`FLAGS` 换掉全部、`+FLAGS` 并进去、
/// `-FLAGS` 抠出来。格式和 [`Canned::flags`] 一致：空格分隔、不带括号。
fn merge_flags(current: &str, op: &str, want: &[&str]) -> String {
    match op {
        "FLAGS" => want.join(" "),
        "+FLAGS" => {
            let mut have: Vec<&str> = current.split_whitespace().collect();
            for w in want {
                if !have.iter().any(|h| h.eq_ignore_ascii_case(w)) {
                    have.push(w);
                }
            }
            have.join(" ")
        }
        "-FLAGS" => current
            .split_whitespace()
            .filter(|h| !want.iter().any(|w| h.eq_ignore_ascii_case(w)))
            .collect::<Vec<_>>()
            .join(" "),
        _ => current.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_set_syntax() {
        assert!(uid_set_matches("5", 5));
        assert!(!uid_set_matches("5", 6));
        assert!(uid_set_matches("1:3", 2));
        assert!(!uid_set_matches("1:3", 4));
        assert!(uid_set_matches("3:*", 99));
        assert!(uid_set_matches("1,3:5", 4));
        assert!(!uid_set_matches("", 1));
    }

    #[test]
    fn literal_len_only_catches_a_trailing_brace() {
        assert_eq!(literal_len("a1 APPEND \"x\" {42}\r\n"), Some(42));
        assert_eq!(literal_len("a1 APPEND \"x\" {0}"), Some(0));
        // 同步字面量
        assert_eq!(literal_len("a1 APPEND \"x\" {7}+"), Some(7));
        // 中途的 `{}` 不算
        assert_eq!(literal_len("a1 UID FETCH 1 (BODY[] {42})"), None);
        assert_eq!(literal_len("a1 NOOP"), None);
        assert_eq!(literal_len("a1 APPEND \"x\" {}"), None);
    }

    #[test]
    fn take_token_keeps_quoted_names_intact() {
        let (tok, rest) = take_token("\"&XfJT0ZAB-\" (\\Seen) {42}").unwrap();
        assert_eq!(tok, "\"&XfJT0ZAB-\"");
        assert_eq!(rest, " (\\Seen) {42}");
        let (tok, rest) = take_token("INBOX {5}").unwrap();
        assert_eq!(tok, "INBOX");
        assert_eq!(rest, " {5}");
    }
}

// ================================================================= 假 SMTP

/// 一封假服务器收下来的信。
#[derive(Debug, Clone)]
pub struct Delivery {
    /// 信封上的发件人（`MAIL FROM`）
    pub from: String,
    /// 信封上的收件人（`RCPT TO`），**包括 Bcc**
    pub to: Vec<String>,
    /// `DATA` 体的原文，已经去掉点填充。就是客户端 `build()` 出来的字节。
    pub raw: String,
    /// 线上**去掉填充之前**的样子。要证明「点填充真的发生了」只能看它 ——
    /// 光看 `raw` 会发现客户端和服务端各少补一个点也能对上，那测试就是空的。
    pub wire: String,
}

/// 让服务器在某一步说「不」，测错误路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Auth,
    Rcpt,
    Data,
}

/// 假 SMTP 服务器。
///
/// 和 [`FakeServer`] 一样是**真的 TCP 监听**，把客户端发的每一条命令都记进
/// [`FakeSmtp::log`]。发信这侧最值钱的证据是「客户端到底发了哪几条命令」——
/// `RCPT TO` 有几条、`DATA` 里的原文长什么样，都得看得见才算验过。
///
/// 认证只认密码 `good`（和 IMAP 假服务器同一套）。**AUTH 的载荷不记进 log**：
/// 那是 base64 的密码，记下来等于养成坏习惯。机制本身是记的。
///
/// TLS 也讲得了（[`TlsMode`]）：隐式 TLS 走 [`FakeSmtp::start_implicit_tls`]，
/// STARTTLS 走 [`FakeSmtp::start_starttls`]。证书由测试现场造，见那两个方法。
pub struct FakeSmtp {
    pub addr: SocketAddr,
    /// 客户端发来的命令，按顺序
    pub log: Arc<Mutex<Vec<String>>>,
    /// 收到的信
    pub received: Arc<Mutex<Vec<Delivery>>>,
    /// 让某一步失败
    pub reject: Arc<Mutex<Option<Reject>>>,
    /// EHLO 里报的 AUTH 机制。默认 `PLAIN LOGIN`，测试可以改成只剩一个 ——
    /// 客户端该跟着换一条路走。
    pub auth_mechs: Arc<Mutex<String>>,
    /// 即使客户端把载荷内联在 `AUTH PLAIN` 里，也先回 `334` 要它单独再发一遍。
    /// 模拟「不吃内联初始应答」的服务器。
    pub two_step_plain: Arc<Mutex<bool>>,
}

impl FakeSmtp {
    pub fn start() -> Self {
        Self::start_on("127.0.0.1:0")
    }

    /// 监听指定地址。端口给 `0` 就让系统挑一个（测试用），给具体端口就是
    /// 给别的进程连的 —— `core/src/bin/fake-smtp.rs` 起的开发服务器就是这么用。
    pub fn start_on(bind: &str) -> Self {
        Self::start_with(bind, TlsMode::None)
    }

    /// 隐式 TLS（465 那条路）：accept 之后立刻握手，连问候语都在隧道里说。
    pub fn start_implicit_tls(acceptor: TlsAcceptor) -> Self {
        Self::start_with("127.0.0.1:0", TlsMode::Implicit(acceptor))
    }

    /// STARTTLS（587 那条路）：先明文谈，EHLO 报 `STARTTLS`，收到命令再升级。
    pub fn start_starttls(acceptor: TlsAcceptor) -> Self {
        Self::start_with("127.0.0.1:0", TlsMode::StartTls(acceptor))
    }

    fn start_with(bind: &str, tls: TlsMode) -> Self {
        let listener = TcpListener::bind(bind).unwrap_or_else(|e| panic!("bind {bind}: {e}"));
        let addr = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let received: Arc<Mutex<Vec<Delivery>>> = Arc::new(Mutex::new(Vec::new()));
        let reject: Arc<Mutex<Option<Reject>>> = Arc::new(Mutex::new(None));
        let auth_mechs: Arc<Mutex<String>> = Arc::new(Mutex::new("PLAIN LOGIN".into()));
        let two_step_plain: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        {
            let log = Arc::clone(&log);
            let received = Arc::clone(&received);
            let reject = Arc::clone(&reject);
            let auth_mechs = Arc::clone(&auth_mechs);
            let two_step_plain = Arc::clone(&two_step_plain);
            // accept 要循环：一个测试里可能先后连上好几次
            // （发成功一封、发失败再开一条）
            let _handle = thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { break };
                    let knobs = Knobs {
                        log: Arc::clone(&log),
                        received: Arc::clone(&received),
                        reject: Arc::clone(&reject),
                        auth_mechs: Arc::clone(&auth_mechs),
                        two_step_plain: Arc::clone(&two_step_plain),
                        tls: tls.clone(),
                    };
                    thread::spawn(move || smtp_serve(stream, knobs));
                }
            });
        }
        FakeSmtp { addr, log, received, reject, auth_mechs, two_step_plain }
    }

    /// 换 EHLO 报的 AUTH 机制，比如只留 `LOGIN`。
    pub fn set_auth_mechs(&self, mechs: &str) {
        *self.auth_mechs.lock().unwrap() = mechs.to_string();
    }

    /// 让服务器**不吃内联的初始应答**：即使 `AUTH PLAIN <载荷>` 也先回 `334`，
    /// 要客户端单独再发一遍载荷。真实服务器里有这样的。
    pub fn set_plain_two_step(&self, on: bool) {
        *self.two_step_plain.lock().unwrap() = on;
    }

    pub fn commands(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    pub fn deliveries(&self) -> Vec<Delivery> {
        self.received.lock().unwrap().clone()
    }

    /// 让某一步失败。测试要制造「授权码不对」「收件人被拒」这种。
    pub fn reject(&self, r: Reject) {
        *self.reject.lock().unwrap() = Some(r);
    }
}

/// 把命令记进日志前抹掉凭据。
///
/// AUTH 的载荷是 base64 的 `"\0user\0pass"`，记下来就是在日志里留密码。
/// 机制名留着 —— 测试要断言「走的是 PLAIN 还是 LOGIN」。
fn redact(cmd: &str) -> String {
    let verb = cmd.split(' ').next().unwrap_or("");
    if verb.eq_ignore_ascii_case("AUTH") {
        let mech = cmd.split_whitespace().nth(1).unwrap_or("");
        format!("AUTH {mech} ****")
    } else {
        cmd.to_string()
    }
}

type SharedLog = Arc<Mutex<Vec<String>>>;
type SharedRcv = Arc<Mutex<Vec<Delivery>>>;
type SharedRej = Arc<Mutex<Option<Reject>>>;

/// 这台假服务器的 TLS 形态。
///
/// 证书由测试现场造（`rcgen`），**不放仓库里** —— 写死的证书会过期，过期之后
/// 每个人的第一次运行都是红的，还以为是代码坏了。
#[derive(Clone)]
pub enum TlsMode {
    /// 不讲 TLS（默认。绝大多数测试用不着加密）
    None,
    /// 隐式 TLS（465）：accept 之后立刻握手，问候语已经在隧道里
    Implicit(TlsAcceptor),
    /// STARTTLS（587）：先明文谈，EHLO 报 `STARTTLS`，收到命令再升级
    StartTls(TlsAcceptor),
}

/// 一条连接要用到的共享状态。参数再涨就该打包了，这里先打包。
struct Knobs {
    log: SharedLog,
    received: SharedRcv,
    reject: SharedRej,
    auth_mechs: Arc<Mutex<String>>,
    two_step_plain: Arc<Mutex<bool>>,
    tls: TlsMode,
}

/// 认证走到一半的状态。
///
/// AUTH 的应答是**裸 base64，没有动词**（`AUTH LOGIN` 两条、`AUTH PLAIN` 两步
/// 形式一条），只能靠状态认出来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthWait {
    /// 不在认证中
    None,
    /// `AUTH PLAIN` 没带初始应答，等一条 `base64("\0user\0pass")`。
    /// RFC 4616 里内联和两步两种都合法 —— **curl 走的就是两步**。
    Plain,
    /// `AUTH LOGIN` 等用户名
    LoginUser,
    /// `AUTH LOGIN` 等密码
    LoginPass,
}

/// `base64("\0user\0pass")` 解开之后密码对不对。
fn plain_ok(decoded: &str) -> bool {
    decoded.rsplit('\0').next().unwrap_or("") == "good"
}

struct SmtpState {
    from: String,
    to: Vec<String>,
    auth: AuthWait,
}

/// 服务器侧的一条连接：写就直接写，读先过自己手上的缓冲。
///
/// 和客户端 `smtp.rs` 的 `Pipe` 同构。**不能**用「BufReader 读 + `try_clone`
/// 再开一个写口」那套 —— TLS 的流没法克隆，读和写必须走同一个对象。
struct Sock {
    io: SmtpIo,
    rbuf: Vec<u8>,
}

/// 连接的两种形态，和客户端 `smtp.rs` 的 `Io` 对称。
enum SmtpIo {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Read for SmtpIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SmtpIo::Plain(s) => s.read(buf),
            SmtpIo::Tls(s) => s.read(buf),
        }
    }
}

impl Write for SmtpIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            SmtpIo::Plain(s) => s.write(buf),
            SmtpIo::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SmtpIo::Plain(s) => s.flush(),
            SmtpIo::Tls(s) => s.flush(),
        }
    }
}

impl Sock {
    fn new(io: SmtpIo) -> Self {
        Sock { io, rbuf: Vec::new() }
    }

    /// 读一行（**行尾留着**，调用方自己决定剥不剥）。`None` = 连接关了。
    fn read_line(&mut self) -> Option<String> {
        loop {
            if let Some(i) = self.rbuf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.rbuf.drain(..=i).collect();
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            let mut chunk = [0u8; 512];
            match self.io.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    // 发完就关的客户端会留半行在缓冲里，那半行也得交出去
                    if self.rbuf.is_empty() {
                        return None;
                    }
                    let rest = std::mem::take(&mut self.rbuf);
                    return Some(String::from_utf8_lossy(&rest).into_owned());
                }
                Ok(n) => self.rbuf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// STARTTLS：把明文那端换成 TLS。握手失败（多半是客户端不信任证书）
    /// 就当这条连接没了 —— 测试要断言的是**客户端**那边报的错。
    fn start_tls(self, acceptor: &TlsAcceptor) -> Option<Sock> {
        let Sock { io, rbuf } = self;
        let plain = match io {
            SmtpIo::Plain(s) => s,
            SmtpIo::Tls(_) => unreachable!("STARTTLS 之前不可能是 TLS"),
        };
        let tls = acceptor.accept(plain).ok()?;
        Some(Sock { io: SmtpIo::Tls(tls), rbuf })
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

fn smtp_serve(stream: TcpStream, knobs: Knobs) {
    let Knobs { log, received, reject, auth_mechs, two_step_plain, tls } = knobs;
    // 隐式 TLS：握手在问候语**之前**（465 一连上就是隧道）。失败就安静退场。
    let mut sock = Sock::new(match &tls {
        TlsMode::Implicit(acc) => match acc.accept(stream) {
            Ok(s) => SmtpIo::Tls(s),
            Err(_) => return,
        },
        _ => SmtpIo::Plain(stream),
    });
    let mut st = SmtpState { from: String::new(), to: Vec::new(), auth: AuthWait::None };

    reply!(sock, "220 fake.smtp ESMTP ready");

    loop {
        let Some(line) = sock.read_line() else { break };
        let t = line.trim_end_matches(['\r', '\n']);

        // ---- AUTH 的中间应答（裸 base64，没有动词）
        if st.auth != AuthWait::None {
            log.lock().unwrap().push("****".to_string());
            let bytes = base64_decode(t);
            let payload = String::from_utf8_lossy(&bytes);
            match st.auth {
                AuthWait::Plain => {
                    st.auth = AuthWait::None;
                    if plain_ok(&payload) {
                        reply!(sock, "235 2.7.0 Authentication successful");
                    } else {
                        reply!(sock, "535 5.7.8 Authentication credentials invalid");
                    }
                }
                AuthWait::LoginUser => {
                    if payload == "me@example.com" {
                        st.auth = AuthWait::LoginPass;
                        reply!(sock, "334 UGFzc3dvcmQ6"); // "Password:"
                    } else {
                        st.auth = AuthWait::None;
                        reply!(sock, "535 5.7.8 Authentication credentials invalid");
                    }
                }
                AuthWait::LoginPass => {
                    st.auth = AuthWait::None;
                    if payload == "good" {
                        reply!(sock, "235 2.7.0 Authentication successful");
                    } else {
                        reply!(sock, "535 5.7.8 Authentication credentials invalid");
                    }
                }
                AuthWait::None => unreachable!("上面刚判过"),
            }
            continue;
        }

        // ---- DATA 体（一行一个 `.` 才算完）
        if t == "DATA" {
            log.lock().unwrap().push("DATA".to_string());
            if *reject.lock().unwrap() == Some(Reject::Data) {
                reply!(sock, "554 5.0.0 no thanks");
                continue;
            }
            reply!(sock, "354 End data with <CR><LF>.<CR><LF>");
            let mut body = String::new();
            let mut stuffed = String::new();
            loop {
                let Some(l) = sock.read_line() else { break };
                let lt = l.trim_end_matches(['\r', '\n']);
                if lt == "." {
                    break;
                }
                stuffed.push_str(&l);
                // 点填充的反面：以 `.` 开头的行去掉一个 `.`（RFC 5321 §4.5.2）
                let l = l.strip_prefix('.').unwrap_or(&l).to_string();
                body.push_str(&l);
            }
            log.lock().unwrap().push(format!("<<< {} bytes", body.len()));
            received.lock().unwrap().push(Delivery {
                from: st.from.clone(),
                to: st.to.clone(),
                raw: body,
                wire: stuffed,
            });
            reply!(sock, "250 2.0.0 Ok: queued");
            continue;
        }

        // ---- 普通命令
        log.lock().unwrap().push(redact(t));
        let mut it = t.splitn(2, ' ');
        let verb = it.next().unwrap_or("").to_ascii_uppercase();
        let rest = it.next().unwrap_or("");

        match verb.as_str() {
            "EHLO" => {
                // 最后一行是 `250 `（空格），不是 `250-` —— 续行到此为止
                reply!(sock, "250-fake.smtp greets you");
                reply!(sock, "250-AUTH {}", auth_mechs.lock().unwrap());
                reply!(sock, "250-SIZE 35882577");
                reply!(sock, "250-8BITMIME");
                // `STARTTLS` **只在 StartTls 模式报**：None 模式故意不报 ——
                // `Security::StartTls` 的客户端必须因此拒发，而不是退回明文。
                if matches!(tls, TlsMode::StartTls(_)) {
                    reply!(sock, "250-STARTTLS");
                }
                reply!(sock, "250 SMTPUTF8");
            }
            "HELO" => reply!(sock, "250 fake.smtp"),
            "STARTTLS" => {
                let TlsMode::StartTls(acc) = &tls else {
                    reply!(sock, "502 5.5.2 Command not implemented");
                    continue;
                };
                reply!(sock, "220 2.0.0 Ready to start TLS");
                // 这句之后的每个字节都在隧道里。客户端接着会**重新 EHLO**
                // （RFC 3207 §4.2）—— 会话继续，问候语不再发。
                let Some(upgraded) = sock.start_tls(acc) else { break };
                sock = upgraded;
            }
            "AUTH" => {
                if *reject.lock().unwrap() == Some(Reject::Auth) {
                    reply!(sock, "535 5.7.8 Authentication credentials invalid");
                    continue;
                }
                let mech = rest.split_whitespace().next().unwrap_or("");
                if mech.eq_ignore_ascii_case("PLAIN") {
                    let payload = rest.split_whitespace().nth(1).unwrap_or("");
                    if payload.is_empty() || *two_step_plain.lock().unwrap() {
                        // 两步形式：不带初始应答（或服务器就是不吃内联的），
                        // 先回 334，载荷下一条到。**curl 走的就是这条路。**
                        st.auth = AuthWait::Plain;
                        reply!(sock, "334 ");
                        continue;
                    }
                    let bytes = base64_decode(payload);
                    let decoded = String::from_utf8_lossy(&bytes);
                    if plain_ok(&decoded) {
                        reply!(sock, "235 2.7.0 Authentication successful");
                    } else {
                        reply!(sock, "535 5.7.8 Authentication credentials invalid");
                    }
                } else if mech.eq_ignore_ascii_case("LOGIN") {
                    st.auth = AuthWait::LoginUser;
                    reply!(sock, "334 VXNlcm5hbWU6"); // "Username:"
                } else {
                    reply!(sock, "504 5.5.4 Unrecognized authentication type");
                }
            }
            "MAIL" => {
                if *reject.lock().unwrap() == Some(Reject::Rcpt) {
                    reply!(sock, "550 5.1.0 sender rejected");
                    continue;
                }
                st.from = angle_addr(rest);
                st.to.clear();
                reply!(sock, "250 2.1.0 Ok");
            }
            "RCPT" => {
                if *reject.lock().unwrap() == Some(Reject::Rcpt) {
                    reply!(sock, "550 5.1.1 recipient rejected");
                    continue;
                }
                st.to.push(angle_addr(rest));
                reply!(sock, "250 2.1.5 Ok");
            }
            "RSET" => {
                st.from.clear();
                st.to.clear();
                reply!(sock, "250 2.0.0 Ok");
            }
            "NOOP" => reply!(sock, "250 2.0.0 Ok"),
            "QUIT" => {
                reply!(sock, "221 2.0.0 Bye");
                break;
            }
            _ => reply!(sock, "502 5.5.2 Command not implemented"),
        }
    }
}

/// `MAIL FROM:<a@b>` / `RCPT TO:<a@b>` 里的地址。尖括号外的东西（ESMTP 参数）丢掉。
fn angle_addr(rest: &str) -> String {
    let Some(a) = rest.split('<').nth(1) else { return String::new() };
    a.split('>').next().unwrap_or("").to_string()
}

/// 极简 base64 解码。测试里用，够用就行 —— 别为它引一个 crate 进 `tests`。
fn base64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .unwrap_or_default()
}
