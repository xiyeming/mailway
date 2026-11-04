//! IMAP 邮箱名的 modified UTF-7（RFC 3501 §5.1.3）
//!
//! IMAP 的邮箱名只能是可打印 ASCII，非 ASCII 要用一套 base64 变体编码。
//! 163 / QQ 的「已发送」「垃圾邮件」、Gmail 的 `[Gmail]/已发送` 都是这么来的。
//! 不解码的话，文件夹列表里就是一堆 `&ZeVnLIqe-`。
//!
//! 和常见 base64 的差别只有一处：`/` 换成 `,`（`/` 在邮箱名里有歧义）。
//! 编码时去掉 `=` 填充，解码时补回去。

use base64::Engine;

/// 解码邮箱名。`&Jjo-` → `好`，`&ZeVnLIqe-` → `日本語`，`&-` → `&`。
pub fn decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;

    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp + 1..];

        match rest.find('-') {
            Some(end) => {
                let chunk = &rest[..end];
                rest = &rest[end + 1..];
                if chunk.is_empty() {
                    out.push('&'); // `&-` 是字面量 &
                } else {
                    out.push_str(&decode_chunk(chunk));
                }
            }
            // 没有收尾的 `-`：服务端发了非法序列，剩下的按字面处理，别丢数据
            None => {
                out.push('&');
                out.push_str(rest);
                rest = "";
            }
        }
    }

    out.push_str(rest);
    out
}

/// 编码邮箱名。`好` → `&Jjo-`，`a&b` → `a&-b`。
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run: Vec<u16> = Vec::new();

    for ch in s.chars() {
        match ch {
            '&' => {
                flush(&mut run, &mut out);
                out.push_str("&-");
            }
            // 可打印 ASCII（空格到 ~）原样保留
            ' '..='~' => {
                flush(&mut run, &mut out);
                out.push(ch);
            }
            _ => {
                let mut buf = [0u16; 2];
                let n = ch.encode_utf16(&mut buf).len();
                run.extend_from_slice(&buf[..n]);
            }
        }
    }
    flush(&mut run, &mut out);
    out
}

fn flush(run: &mut Vec<u16>, out: &mut String) {
    if run.is_empty() {
        return;
    }
    let mut bytes = Vec::with_capacity(run.len() * 2);
    for u in run.drain(..) {
        bytes.extend_from_slice(&u.to_be_bytes());
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    out.push('&');
    out.push_str(b64.trim_end_matches('=').replace('/', ",").as_str());
    out.push('-');
}

fn decode_chunk(chunk: &str) -> String {
    let mut b64: String = chunk.chars().map(|c| if c == ',' { '/' } else { c }).collect();
    // 编码时去掉了填充，这里补回来（补 0~2 个 `=`，len%4==1 是非法的，补两个也解不出）
    while b64.len() % 4 != 0 {
        b64.push('=');
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&b64) else {
        return String::new();
    };
    // UTF-16BE → String。奇数长度说明服务端发了坏数据，丢掉而不是 panic。
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_untouched() {
        for s in ["INBOX", "Sent Items", "Sent", "a/b.c"] {
            assert_eq!(decode(s), s);
            assert_eq!(encode(s), s);
        }
    }

    #[test]
    fn ampersand_is_escaped_both_ways() {
        assert_eq!(encode("a&b"), "a&-b");
        assert_eq!(decode("a&-b"), "a&b");
    }

    #[test]
    fn rfc3501_examples() {
        // RFC 3501 §5.1.3 正文里的三个例子
        assert_eq!(decode("~peter/mail/台北/日本語"), "~peter/mail/台北/日本語");
        assert_eq!(encode("台北"), "&U,BTFw-");
        assert_eq!(decode("&U,BTFw-"), "台北");
        assert_eq!(encode("日本語"), "&ZeVnLIqe-");
        assert_eq!(decode("&ZeVnLIqe-"), "日本語");
    }

    #[test]
    fn roundtrip_is_stable() {
        for s in [
            "已发送",
            "垃圾邮件",
            "草稿箱",
            "归档/2024年",
            "Mixed 中英文 Name",
            "带&符号的中文",
            "🙂emoji",
            "é",
        ] {
            assert_eq!(decode(&encode(s)), s, "roundtrip 失败: {s}");
        }
    }

    #[test]
    fn undecodable_run_degrades_not_panics() {
        // 长度 %4 == 1 的 base64 是非法的；解不出时返回空，不 panic
        assert_eq!(decode("&A-"), "");
        // 缺收尾 `-`：整段按字面处理，数据不丢
        assert_eq!(decode("x&abc"), "x&abc");
        assert_eq!(decode("&-"), "&");
    }
}
