//! 开发用的假 IMAP 服务器 —— **不是产品的一部分**
//!
//! 用途只有一个：不靠真实邮箱，也能把「收信」这条路完整跑一遍看。
//! 协议实现直接复用集成测试里那个（`core/tests/support/mod.rs`），保证
//! 测试和实机跑的是同一份脚本机，不会出现「测试过了、真跑是另一回事」。
//!
//! ## 怎么用
//!
//! ```bash
//! # 1. 起假服务器（默认 2143 端口）
//! cargo run -p mailway-core --bin fake-imap
//!
//! # 2. 起应用，顺带把账号指向它（密码固定 good，进的是真钥匙串）
//! MAILWAY_DEV_FAKE_IMAP=2143 cargo run -p mailway
//!
//! # 3. 在**假服务器这个终端**里敲一行字回车 = 投递一封新信
//! #    然后到应用里按 F5，列表里就多出一封
//! ```
//!
//! ## 怎么投信（两条路都行）
//!
//! | 怎么做 | 效果 |
//! |---|---|
//! | 在**这个终端**敲一行字回车 | 投 1 封，主题和正文都是这句 |
//! | 在**别的终端** `echo "今天下雨了" >> /tmp/mailway-fake.inject` | 同上 |
//! | 敲 / 写一个数字，比如 `3` | 投 3 封，主题是「自动投递 #1」… |
//! | 空行 | 忽略 |
//!
//! 两条路都要留：这个终端敲字是最自然的，而注入文件能在不抢终端的情况下
//! 从任意 shell 投信（排错、脚本、别的窗口）。注入文件每 400ms 轮询一次
//! 追加的内容 —— 开发工具，够用，别为它上 inotify。
//!
//! 另外它每 5 秒把客户端发的命令打出来（`< a4 UID FETCH 4:* …`），
//! **增量同步对不对一眼可见**：第二轮的 UID 集该从水位线之后起。
//!
//! ## 为什么要能投信
//!
//! 只靠 `default_mails()` 那 3 封，「收信」永远证明不了「新信会到」——
//! 按多少次 F5 都是 3 封，看不出是引擎没干活还是压根没新信。能投信之后，
//! 「收到新信」变成一件可以当场演示的事。
//!
//! 它只讲足够的 IMAP：`LOGIN` / `LIST` / `SELECT` / `APPEND` / `UID FETCH` /
//! `UID STORE` / `UID MOVE` / `IDLE` / `LOGOUT`，外加文件夹的 `CREATE` /
//! `RENAME` / `DELETE`（建/改名/删文件夹那条路要能实测）。SEARCH 之类不支持，
//! 也不是合规服务器 —— 它只是个能骗过 `imap` crate 解析器的脚本机。

#[path = "../../tests/support/mod.rs"]
#[macro_use]
mod support;

use std::io::{BufRead, Write};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;
use support::*;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2143);

    let server = Arc::new(FakeServer::start_on(
        &format!("127.0.0.1:{port}"),
        default_mails(),
        FakeCfg::default(),
    ));

    println!("fake IMAP listening on {}", server.addr);
    println!("  username: me@example.com");
    println!("  password: good          <- 假服务器只认这个");
    println!("  mailboxes: INBOX / &XfJT0ZAB-（已发送）/ Archive(\\Noselect)");
    println!("  {} 封信", server.mail.lock().map(|m| m.len()).unwrap_or(0));
    println!();
    println!("  ★ 投信 = 往 INBOX 加一封信，然后去应用里按 F5 就能看到它");
    println!("    · 在这个终端敲一行字回车");
    println!("    · 或在别的终端:  echo \"今天下雨了\" >> {INJECT}");
    println!("    · 敲 / 写一个数字（比如 `3`）= 一次投那么多封");
    println!("  ★ 不投信时，下面每 5 秒回显一次客户端发的命令");
    println!("    · 增量对不对看 UID 集：第二轮该从水位线之后起（`4:*` 而不是 `1:*`）");
    println!();
    println!("  应用侧:  MAILWAY_DEV_FAKE_IMAP={port} cargo run -p mailway");
    println!();

    // 投递两条路：stdin（敲字）+ 注入文件（别的 shell）。
    // stdin 那条在后台管道里会立刻 EOF 然后安静退出，不影响别的功能。
    {
        let server = Arc::clone(&server);
        thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.lock().read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                handle_line(&server, &line);
            }
        });
    }
    {
        let server = Arc::clone(&server);
        thread::spawn(move || inject_loop(server));
    }

    // 每 5 秒把收到的命令打出来 —— 排查「客户端到底发了什么」时用得上。
    // 只打**新增**的部分，别刷屏。
    let mut seen = 0usize;
    loop {
        thread::sleep(Duration::from_secs(5));
        let cmds = server.commands();
        if cmds.len() > seen {
            for c in &cmds[seen..] {
                println!("< {c}");
            }
            seen = cmds.len();
        }
    }
}

/// 注入文件：别的 shell 往里追加一行就是投一封信。
///
/// 轮询而不是 FIFO + inotify：这是个开发工具，400ms 的延迟无所谓，而
/// 纯 std 少一条依赖、少一堆「谁来建 FIFO / 写端关了要不要重开」的坑。
const INJECT: &str = "/tmp/mailway-fake.inject";

fn inject_loop(server: Arc<FakeServer>) {
    use std::io::{Read, Seek, SeekFrom};
    let mut pos = 0u64;
    loop {
        thread::sleep(Duration::from_millis(400));
        let Ok(mut f) = std::fs::File::options().read(true).append(true).create(true).open(INJECT)
        else {
            continue;
        };
        let Ok(len) = f.metadata().map(|m| m.len()) else { continue };
        // 被人清空过就从头读，别卡在一个不存在的偏移上
        if len < pos {
            pos = 0;
        }
        if len == pos {
            continue;
        }
        if f.seek(SeekFrom::Start(pos)).is_err() {
            continue;
        }
        let mut buf = String::new();
        if f.read_to_string(&mut buf).is_err() {
            continue;
        }
        pos = len;
        for line in buf.lines() {
            handle_line(&server, line);
        }
    }
}

/// 一行 = 一封信（或者「一次投 N 封」）。
fn handle_line(server: &FakeServer, raw: &str) {
    let text = raw.trim();
    if text.is_empty() {
        return;
    }

    // `3` 这种纯数字 = 一次投 N 封；其它当一封信的主题和正文
    if !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(batch) = text.parse::<usize>() {
            if batch > 0 {
                for i in 1..=batch {
                    let subject = format!("自动投递 #{i}");
                    deliver(server, &subject, &format!("这是第 {i} 封自动投递的信。"));
                }
                return;
            }
        }
    }
    deliver(server, text, text);
}

/// 投一封信进 INBOX，并叫醒所有挂在 IDLE 上的连接。
fn deliver(server: &FakeServer, subject: &str, body: &str) {
    // UID 要接着**已有的最大值**走，不能用 `len() + 1` —— 删过信之后两者就不一样了，
    // 撞上已有 UID 会让客户端的水位线逻辑误判。
    let next = server
        .mail
        .lock()
        .map(|m| m.iter().map(|c| c.uid).max().unwrap_or(0) + 1)
        .unwrap_or(1);
    let raw = build_mail(next, subject, body);

    // `Canned::raw` 是 `&'static str`（夹具都是字面量）。运行时拼出来的字符串
    // 只能 `Box::leak` 才塞得进去 —— 开发工具，投几十封信泄漏几百字节，不值得
    // 为此把整套夹具的类型改掉。
    let uid = server.push_mail(next, "", Box::leak(raw.into_boxed_str()));
    // 叫醒 IDLE：不然应用要等 IDLE 超时（20 分钟）才知道有新信
    server.push_exists(server.mail.lock().map(|m| m.len() as u32).unwrap_or(0));

    println!("→ 已投递 UID {uid}：{subject}");
    let _ = std::io::stdout().flush();
}

/// 拼一封最小可用的 RFC 5322。
fn build_mail(n: u32, subject: &str, body: &str) -> String {
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000");
    format!(
        "From: 投递器 <deliver@fake.local>\r\n\
         To: me@example.com\r\n\
         Subject: {}\r\n\
         Date: {date}\r\n\
         Message-ID: <deliver-{n}@fake.local>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {body}\r\n",
        encode_header(subject),
    )
}

/// 非 ASCII 的头部值走 RFC 2047。不编码的话中文主题会被当成 latin-1
/// 解出来一堆乱码 —— 那是解析器的问题，不是投递的问题，别混在一起看。
fn encode_header(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    )
}
