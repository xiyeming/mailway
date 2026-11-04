//! imap-proto 解析回归（163/Coremail 真实服务器的响应形态）。
//!
//! 真实抓包：`INTERNALDATE " 4-Nov-2026 …"` —— **日期「日」是空格填充**。
//! 上游 imap-proto 0.10.2（vendored 前）解析属性表时在此中断，UID 之后的
//! FLAGS/RFC822.SIZE/BODY[] **全部丢失**，导致真实邮件主题/正文全空。
//! vendor/imap-proto 修了日期解析；本测试钉住这个行为。

use imap_proto::{parse_response, Response};

#[test]
fn fetch_with_space_padded_day_parses_all_attributes() {
    let mut line: Vec<u8> = Vec::new();
    line.extend_from_slice(
        b"* 2478 FETCH (UID 1323496947 INTERNALDATE \" 4-Nov-2026 15:39:15 +0800\" \
         FLAGS () RFC822.SIZE 1025 BODY[] {1025}\r\n",
    );
    line.extend_from_slice(&vec![b'x'; 1025]);
    line.extend_from_slice(b")\r\n");

    let (_, resp) = parse_response(&line).expect("整条 FETCH 响应该能解析");
    let Response::Fetch(num, attrs) = resp else {
        panic!("该是 Response::Fetch，得到 {resp:?}");
    };
    assert_eq!(num, 2478);
    // UID + INTERNALDATE + FLAGS + RFC822.SIZE + BODY[] —— 一个都不能丢
    assert!(
        attrs.len() >= 5,
        "属性被丢弃了（只剩 {:?}）—— 空格填充日期的解析回退了",
        attrs.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>()
    );
}

#[test]
fn fetch_with_zero_padded_day_still_parses() {
    let mut line: Vec<u8> = Vec::new();
    line.extend_from_slice(
        b"* 1 FETCH (UID 42 FLAGS (\\Seen) RFC822.SIZE 3 INTERNALDATE \
         \"04-Nov-2026 15:39:15 +0800\" BODY[] {3}\r\n",
    );
    line.extend_from_slice(b"abc");
    line.extend_from_slice(b")\r\n");
    let (_, resp) = parse_response(&line).expect("零填充日期也该能解析");
    let Response::Fetch(_, attrs) = resp else {
        panic!("该是 Response::Fetch");
    };
    assert!(attrs.len() >= 5, "attrs={attrs:?}");
}
