//! 开发用的假 SMTP 服务器 —— **不是产品的一部分**
//!
//! 用途只有一个：不靠真实邮箱，也能把「发信」这条路完整跑一遍看。
//! 协议实现直接复用集成测试里那个（`core/tests/support/mod.rs`），保证测试和
//! 实机跑的是同一台假服务器，不会出现「测试过了、真跑是另一回事」。
//!
//! ## 怎么用
//!
//! ```bash
//! # 1. 起假服务器（默认 2255 端口）
//! cargo run -p mailway-core --bin fake-smtp
//!
//! # 2. 起假 IMAP（发完的信要能看到，得有地方收）
//! cargo run -p mailway-core --bin fake-imap
//!
//! # 3. 起应用，账号的发信部分填：
//! #      SMTP 主机 127.0.0.1  端口 2255  加密 明文
//! #      用户名 me@example.com  授权码 good
//!
//! # 4. 写一封信发出去。这个终端会把客户端发的每条命令和收到的原文都打出来
//! ```
//!
//! ## 为什么要把命令打出来
//!
//! 发信最容易出错的三件事，在命令日志里一眼可见：
//!
//!   * **Bcc 有没有泄漏进原文** —— 看 `RCPT TO` 有几条、`DATA` 里有没有 Bcc 头
//!   * **点填充做没做** —— 正文里单独一行的 `.` 不补点会把信截断，而服务器
//!     还回 250，发信的人完全看不出来
//!   * **AUTH 走的哪条路** —— PLAIN 还是 LOGIN，以及有没有把密码记进日志
//!
//! ## 凭据
//!
//! 密码固定 `good`，别的都会被拒（和假 IMAP 同一套）。**AUTH 的载荷不打印**：
//! 那是 base64 的密码，打出来等于养成坏习惯。
//!
//! ## 一个会让人误以为是 bug 的现象
//!
//! 拿 `curl` 往这里发信、正文里又有单独一行的 `.` 时，信会在那一行被截断，
//! 后半截会混进命令日志里。**这不是假服务器的问题**，是客户端没做点填充的
//! 必然结果：`curl --upload-file` 喂进去是 LF 行尾时，它不认那是个行首的 `.`。
//! 不补点的话，服务器看到的就是 DATA 的结束标记。
//!
//! 想自己验，用裸 socket 把字节写死，`..` 会还原成 `.`、`.dot` 会还原成 `dot`：
//!
//! ```bash
//! P=$(printf '\0me@example.com\0good' | base64 -w0)
//! { printf 'EHLO x\r\nAUTH PLAIN %s\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n' "$P"
//!   printf 'DATA\r\n\r\nbefore\r\n..\r\nend\r\n.\r\nQUIT\r\n'
//! } | nc -q1 127.0.0.1 2255
//! ```

#[path = "../../tests/support/mod.rs"]
#[macro_use]
mod support;

use std::thread;
use std::time::Duration;

use support::*;

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2255);
    let bind = format!("127.0.0.1:{port}");
    let s = FakeSmtp::start_on(&bind);

    println!("假 SMTP 服务器听在 {bind}");
    println!("账号填：SMTP 主机 127.0.0.1  端口 {port}  加密 明文");
    println!("        用户名 me@example.com   授权码 good");
    println!();
    println!("下面按顺序打出客户端发的每条命令，以及收到的每封信。");
    println!("（AUTH 的载荷不打 —— 那是 base64 的密码）");
    println!();

    let mut shown_cmd = 0usize;
    let mut shown_mail = 0usize;
    loop {
        thread::sleep(Duration::from_millis(300));

        let cmds = s.commands();
        for c in &cmds[shown_cmd..] {
            println!("< {c}");
        }
        shown_cmd = cmds.len();

        let got = s.deliveries();
        for d in &got[shown_mail..] {
            println!();
            println!("┌─ 收到一封信 ───────────────────────────────");
            println!("│ 信封 From: {}", d.from);
            println!("│ 信封 To:   {}", d.to.join(", "));
            println!("├─ 原文（{} 字节）──────────────────────────", d.raw.len());
            for line in d.raw.lines() {
                println!("│ {line}");
            }
            println!("└────────────────────────────────────────────");
            println!();
        }
        shown_mail = got.len();
    }
}
