//! MIME 解析 —— RFC 5322 + RFC 2045..2049
//!
//! 输入是 `store::read_raw` 读回来的原始字节，输出是 [`ParsedMessage`]。
//!
//! 三个设计决定：
//!
//! 1. **这里不净化 HTML**。`body_html` 是发件人给的原样。净化发生在
//!    「Rust → webview」那道信任边界上（[`crate::sanitize::sanitize_body`]），
//!    因为策略会变（用户点了「显示图片」），净化要能按需重跑。
//! 2. **附件字节跟解析结果一起返回**。M1 的调用方写盘存元数据；阅读时
//!    重新解析原文取字节。换成独立的附件落盘布局是以后的优化，不动这个 API。
//! 3. **正文选取走一个显式的模式递归**（Body / Resource / Extra），不靠
//!    「第一段是正文」这种启发式。理由见 [`walk`] 的注释。
//!
//! 字符集：`mailparse` 用 `encoding_rs`，`gbk` / `gb18030` / `big5` /
//! `shift_jis` 都认。但**没声明 charset 时它默认按 windows-1252 解**，
//! 而国内大量邮件就是裸 UTF-8 不写 charset —— 这个坑在 [`body_string`] 里堵掉。

use chrono::{DateTime, Utc};
use mailparse::{
    addrparse, dateparse, parse_content_disposition, parse_header, parse_mail,
    DispositionType, MailAddr, MailHeaderMap, ParsedMail,
};

use crate::error::{Error, Result};
use crate::sanitize::CidMap;
use crate::types::*;

// ================================================================= 结果类型

/// 一个附件，带字节。
#[derive(Debug, Clone)]
pub struct ParsedAttachment {
    pub meta: Attachment,
    pub data: Vec<u8>,
}

/// 一封邮件解析后的完整形态。
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    /// RFC 5322 Message-ID，**去掉了尖括号**
    pub message_id: Option<String>,
    pub subject: String,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub date: Option<DateTime<Utc>>,
    pub in_reply_to: Option<String>,
    /// `References` 链，去掉尖括号，按原顺序
    pub references: Vec<String>,

    pub body_kind: BodyKind,
    /// 邮件原样的 HTML（**未净化**，不能直接进 webview）
    pub body_html: Option<String>,
    pub body_text: Option<String>,

    /// 附件 + 内嵌图片，按出现顺序。用 [`Attachment::inline`] 区分。
    pub attachments: Vec<ParsedAttachment>,
    /// 原始 MIME 头，「详情」面板用
    pub raw_headers: Vec<(String, String)>,
    /// 原始字节数（不是解析后的大小）
    pub size: u64,
}

impl ParsedMessage {
    /// 有没有**真正的**附件（内嵌图片不算）。
    ///
    /// 列表页那个回形针图标看这个，一封只有 logo 图的邮件不该显示附件标记。
    pub fn has_attachments(&self) -> bool {
        self.attachments.iter().any(|a| !a.meta.inline)
    }

    /// 构造 `cid:` → 内联资源 的映射，喂给 [`crate::sanitize::sanitize_body`]。
    pub fn cid_map(&self) -> CidMap<'_> {
        self.attachments
            .iter()
            .filter(|a| a.meta.inline)
            .filter_map(|a| {
                let cid = a.meta.content_id.as_deref()?;
                Some((cid, (a.meta.mime_type.as_str(), a.data.as_slice())))
            })
            .collect()
    }
}

// ================================================================= 入口

/// 解析一封原始邮件。
pub fn parse_message(raw: &[u8]) -> Result<ParsedMessage> {
    let mail = parse_mail(raw).map_err(|e| Error::Mime(e.to_string()))?;

    let mut c = Collector::default();
    walk(&mail, Mode::Body, &mut c, false);

    // 附件 id = 在这封邮件里的下标，够前端在下载命令里定位。
    // 稳定性上：同一份原始邮件解析多少次，下标都一样。
    let attachments: Vec<ParsedAttachment> = c
        .attachments
        .into_iter()
        .enumerate()
        .map(|(i, mut a)| {
            a.meta.id = i.to_string();
            a
        })
        .collect();

    let body_kind = if c.html.is_some() {
        BodyKind::Html
    } else if c.plain.is_some() {
        BodyKind::Plain
    } else {
        BodyKind::Empty
    };

    let h = |k: &str| first_header(&mail, k);

    Ok(ParsedMessage {
        message_id: h("Message-ID").map(|v| strip_msgid(&v)).filter(|s| !s.is_empty()),
        subject: h("Subject").unwrap_or_default(),
        from: addresses(&h("From").unwrap_or_default()),
        to: addresses(&h("To").unwrap_or_default()),
        cc: addresses(&h("Cc").unwrap_or_default()),
        bcc: addresses(&h("Bcc").unwrap_or_default()),
        reply_to: addresses(&h("Reply-To").unwrap_or_default()),
        date: h("Date").as_deref().and_then(parse_date),
        in_reply_to: parse_references(&h("In-Reply-To").unwrap_or_default())
            .into_iter()
            .next(),
        references: parse_references(&h("References").unwrap_or_default()),
        body_kind,
        body_html: c.html,
        body_text: c.plain,
        attachments,
        raw_headers: mail.headers.iter().map(|h| (h.get_key(), h.get_value())).collect(),
        size: raw.len() as u64,
    })
}

/// 只看信头就能判断的「可能有附件」。
///
/// 列表页要在还没取正文的时候显示回形针，所以这里只读 `BODY[HEADER]`。
/// 判据刻意和 [`ParsedMessage::has_attachments`] 保持一致：
///
///   * 根是 `multipart/mixed` / `multipart/digest` → 有（mixed 的语义就是
///     「正文 + 附件」，`walk` 也把非第一段全放 Extra 槽）
///   * 根写了 `Content-Disposition: attachment` → 有
///   * 其它 → 没有
///
/// 例外会有一封 `multipart/mixed` 里只挂内嵌图的误报（Outlook 偶尔这么干）。
/// 可接受：打开邮件时会用 [`parse_message`] 算出真值。
pub fn headers_hint_attachments(raw_headers: &[u8]) -> bool {
    let Ok(mail) = parse_mail(raw_headers) else {
        return false;
    };
    if matches!(content_disposition(&mail), DispositionType::Attachment) {
        return true;
    }
    let mime = mime_of(&mail);
    mime == "multipart/mixed" || mime == "multipart/digest"
}

// ================================================================= 正文选取
//
// 为什么不用「第一个 text/* 就是正文」：那样 multipart/mixed 里正文后面挂的
// 一个 text/html 附件会被当成第二段正文覆盖掉。
//
// 为什么不用「最后一段是正文」或「最大的那段是正文」：同样有反例。
//
// 这里改成显式三种槽位，由父节点的 subtype 决定往哪个槽里放：
//
//   Body     正文候选（text/html 和 text/plain 各占一个槽，先到先得）
//   Resource 被正文用 cid: 引用的内嵌资源
//   Extra    附件
//
// 父节点的分派规则是 MIME 语义规定的，不是猜的：
//   alternative  → 所有子节点都是同一个正文的不同表示 → 全进 Body
//   related      → 第一个是根正文，其余是它引用的资源 → Body / Resource
//   signed       → 第一个是正文，第二个是签名          → 只走 Body
//   report       → 第一个是给人看的，其余是机器可读的   → 只走 Body
//   mixed 等其它 → 第一个是正文，其余是附件             → Body / Extra

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Body,
    Resource,
    Extra,
}

#[derive(Default)]
struct Collector {
    html: Option<String>,
    plain: Option<String>,
    attachments: Vec<ParsedAttachment>,
}

fn walk(mail: &ParsedMail<'_>, mode: Mode, c: &mut Collector, is_subpart: bool) {
    let mime = mime_of(mail);

    // 非正文槽里的 multipart 整体就是一个附件（附件里嵌一封完整的 MIME
    // 信，拆开反而看不出「这是一个东西」）。
    if mode != Mode::Body && mime.starts_with("multipart/") {
        push_attachment(mail, c, mode, is_subpart);
        return;
    }

    if mime == "multipart/alternative" {
        for sub in &mail.subparts {
            walk(sub, Mode::Body, c, true);
        }
        return;
    }
    if mime == "multipart/related" {
        if let Some((first, rest)) = mail.subparts.split_first() {
            walk(first, Mode::Body, c, true);
            for sub in rest {
                walk(sub, Mode::Resource, c, true);
            }
        }
        return;
    }
    if mime == "multipart/signed" || mime == "multipart/report" {
        // 第二段是 pkcs7 签名 / DSN 的机器可读体，都不是用户要看的附件
        if let Some(first) = mail.subparts.first() {
            walk(first, Mode::Body, c, true);
        }
        return;
    }
    if mime.starts_with("multipart/") {
        if let Some((first, rest)) = mail.subparts.split_first() {
            walk(first, Mode::Body, c, true);
            for sub in rest {
                walk(sub, Mode::Extra, c, true);
            }
        }
        return;
    }

    // ---- 叶子 ----------------------------------------------------
    match mode {
        Mode::Body => {
            // `Content-Disposition: attachment` 是发件人明说「这是附件」，
            // 哪怕它是 text/plain 也不该当正文（导出的报告、日志都这么发）。
            let declared_attachment =
                matches!(content_disposition(mail), DispositionType::Attachment);

            if mime == "text/html" && !declared_attachment {
                if c.html.is_none() {
                    c.html = Some(body_string(mail, is_subpart));
                }
            } else if mime == "text/plain" && !declared_attachment {
                if c.plain.is_none() {
                    c.plain = Some(body_string(mail, is_subpart));
                }
            } else {
                // 正文槽里出现了非文本（纯附件邮件、text/calendar 邀请…）
                push_attachment(mail, c, Mode::Extra, is_subpart);
            }
        }
        Mode::Resource => {
            // 能被 cid: 引用的只有带 Content-ID 的图片；否则它丢了用户就
            // 找不回来了，退回附件槽。
            if mime.starts_with("image/") && content_id(mail).is_some() {
                push_attachment(mail, c, Mode::Resource, is_subpart);
            } else {
                push_attachment(mail, c, Mode::Extra, is_subpart);
            }
        }
        Mode::Extra => push_attachment(mail, c, Mode::Extra, is_subpart),
    }
}

// ================================================================= 叶子处理

fn push_attachment(mail: &ParsedMail<'_>, c: &mut Collector, mode: Mode, is_subpart: bool) {
    let mut data = if mail.subparts.is_empty() {
        // 叶子：拿转移编码解码后的字节，这才是附件本身
        mail.get_body_raw()
            .unwrap_or_else(|_| mail.raw_bytes.to_vec())
    } else {
        // multipart 整体当附件：保留完整原始字节（含头）
        mail.raw_bytes.to_vec()
    };
    if is_subpart && !is_base64(mail) {
        let n = data.len();
        data.truncate(n - boundary_crlf_len(&data));
    }

    let mime = mime_of(mail);
    let cid = content_id(mail);
    let cd = content_disposition(mail);

    // inline 的判据是「正文真的用 cid: 引了它」，不是 Content-Disposition
    // 上写了 inline —— 后者在真实邮件里几乎总是乱写的，会把 PDF 变成内嵌。
    let inline = mode == Mode::Resource
        && cid.is_some()
        && mime.starts_with("image/")
        && !matches!(cd, DispositionType::Attachment);

    c.attachments.push(ParsedAttachment {
        meta: Attachment {
            id: String::new(), // 出循环时统一编号
            filename: filename_of(mail),
            mime_type: mime,
            size: data.len() as u64,
            inline,
            content_id: cid,
        },
        data,
    });
}

// ================================================================= 头与正文

fn first_header(mail: &ParsedMail<'_>, key: &str) -> Option<String> {
    mail.headers.get_first_value(key)
}

fn mime_of(mail: &ParsedMail<'_>) -> String {
    mail.ctype.mimetype.to_ascii_lowercase()
}

fn content_id(mail: &ParsedMail<'_>) -> Option<String> {
    first_header(mail, "Content-ID")
        .map(|v| strip_msgid(&v))
        .filter(|s| !s.is_empty())
}

fn content_disposition(mail: &ParsedMail<'_>) -> DispositionType {
    // 用原始字节喂 parser：参数里可能有 RFC 2047 编码字，先解码再解析参数
    // 会破坏引号结构。
    let raw = mail
        .headers
        .get_first_header("Content-Disposition")
        .map(|h| String::from_utf8_lossy(h.get_value_raw()).into_owned())
        .unwrap_or_default();
    parse_content_disposition(&raw).disposition
}

/// 取正文文本。
///
/// 邮件不写 charset 是常态（尤其国内），而 `mailparse` 在 charset 缺失或
/// 不认识时按 windows-1252 解 —— UTF-8 的中文会变成一堆 `ä¸­æ–‡`。
/// 所以**没显式声明 charset 时先按 UTF-8 试**，解得动就用，解不动才回落。
fn body_string(mail: &ParsedMail<'_>, is_subpart: bool) -> String {
    let charset = mail.ctype.charset.trim().to_ascii_lowercase();
    let declared = !charset.is_empty() && charset != "us-ascii";

    let text = if !declared {
        match mail.get_body_raw().ok().and_then(|r| String::from_utf8(r).ok()) {
            Some(s) => s,
            None => decoded_body(mail),
        }
    } else {
        decoded_body(mail)
    };

    if is_subpart && !is_base64(mail) {
        strip_boundary_crlf(&text).to_string()
    } else {
        text
    }
}

fn decoded_body(mail: &ParsedMail<'_>) -> String {
    mail.get_body().unwrap_or_else(|_| {
        String::from_utf8_lossy(&mail.get_body_raw().unwrap_or_default()).into_owned()
    })
}

/// 去掉末尾那一个属于 boundary 的换行。
///
/// RFC 2046 §5.1.1：boundary 前面的 CRLF 概念上属于 boundary 本身，不属于
/// 正文。但 mailparse 把它留在 body 里（它自己的测试就是这么断言的：
/// `get_body() == "part0\r\n"`）。不去掉的话每段正文末尾多一个空行，
/// 附件字节多两个字节。
///
/// **base64 例外**：它的解码器本来就滤掉所有 ASCII 空白，boundary 的 CRLF
/// 早没了，再剥会切掉附件真以 CRLF 结尾的那两个字节。
fn strip_boundary_crlf(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

fn boundary_crlf_len(b: &[u8]) -> usize {
    if b.ends_with(b"\r\n") {
        2
    } else if b.ends_with(b"\n") {
        1
    } else {
        0
    }
}

fn is_base64(mail: &ParsedMail<'_>) -> bool {
    matches!(mail.get_body_encoded(), mailparse::body::Body::Base64(_))
}

fn filename_of(mail: &ParsedMail<'_>) -> String {
    // 顺序按真实邮件的出现频率：Content-Disposition 的 filename 最标准，
    // Content-Type 的 name 是老写法，两个都不给就用类型起名。
    if let Some(f) = content_disposition_params(mail).get("filename") {
        let f = decode_maybe_encoded(f);
        if !f.trim().is_empty() {
            return f;
        }
    }
    if let Some(n) = mail.ctype.params.get("name") {
        let n = decode_maybe_encoded(n);
        if !n.trim().is_empty() {
            return n;
        }
    }
    format!("附件{}", ext_for_mime(&mime_of(mail)))
}

fn content_disposition_params(
    mail: &ParsedMail<'_>,
) -> std::collections::BTreeMap<String, String> {
    let raw = mail
        .headers
        .get_first_header("Content-Disposition")
        .map(|h| String::from_utf8_lossy(h.get_value_raw()).into_owned())
        .unwrap_or_default();
    parse_content_disposition(&raw).params
}

fn ext_for_mime(mime: &str) -> &'static str {
    match mime {
        "application/pdf" => ".pdf",
        "application/zip" => ".zip",
        "application/x-7z-compressed" => ".7z",
        "application/x-rar-compressed" => ".rar",
        "application/msword" => ".doc",
        "application/vnd.ms-excel" => ".xls",
        "application/vnd.ms-powerpoint" => ".ppt",
        "text/plain" => ".txt",
        "text/html" => ".html",
        "text/calendar" => ".ics",
        "text/vcard" | "text/x-vcard" => ".vcf",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        _ => "",
    }
}

/// 解码可能带 RFC 2047 编码字的参数值（`filename="=?UTF-8?B?...?="`）。
///
/// 这种写法违反 RFC（参数该用 RFC 2231），但邮件世界里到处都是。
/// 借 `mailparse` 的解码器用：喂一个假头部给它，省得自己写 Q/B 解码。
fn decode_maybe_encoded(value: &str) -> String {
    if !value.contains("=?") {
        return value.to_string();
    }
    match parse_header(format!("X-: {value}").as_bytes()) {
        Ok((h, _)) => h.get_value(),
        Err(_) => value.to_string(),
    }
}

fn strip_msgid(s: &str) -> String {
    s.trim().trim_start_matches('<').trim_end_matches('>').trim().to_string()
}

fn parse_references(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(strip_msgid)
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_date(raw: &str) -> Option<DateTime<Utc>> {
    let secs = dateparse(raw).ok()?;
    DateTime::from_timestamp(secs, 0)
}

fn addresses(raw: &str) -> Vec<Mailbox> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let Ok(list) = addrparse(raw) else {
        // 地址串畸形（真不少见，Outlook 的 group 语法尤其）。别整封丢掉，
        // 退化成一个只用于显示的条目。
        return vec![Mailbox { display: None, address: raw.to_string() }];
    };

    let mut out = Vec::new();
    for a in list.iter() {
        let singles: Vec<&mailparse::SingleInfo> = match a {
            MailAddr::Single(s) => vec![s],
            MailAddr::Group(g) => g.addrs.iter().collect(),
        };
        for s in singles {
            let display = s
                .display_name
                .as_deref()
                .map(decode_maybe_encoded)
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty());
            out.push(Mailbox { display, address: s.addr.clone() });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// 拼一封最简单的纯文本邮件。
    fn plain(headers: &str, body: &str) -> String {
        format!("{headers}\r\n\r\n{body}")
    }

    #[test]
    fn parses_headers_and_plain_body() {
        let raw = plain(
            "From: =?UTF-8?B?5byg5LiJ?= <zhangsan@example.com>\r\n\
             To: lisi@example.com, 王五 <wangwu@example.com>\r\n\
             Subject: =?UTF-8?B?5rWL6K+V5Li76aKY?=\r\n\
             Date: Sun, 02 Oct 2016 07:06:22 -0700\r\n\
             Message-ID: <abc123@example.com>",
            "第一行\n第二行",
        );
        let m = parse_message(raw.as_bytes()).unwrap();

        assert_eq!(m.subject, "测试主题");
        assert_eq!(m.message_id.as_deref(), Some("abc123@example.com"));
        assert_eq!(m.from.len(), 1);
        assert_eq!(m.from[0].display.as_deref(), Some("张三"));
        assert_eq!(m.from[0].address, "zhangsan@example.com");
        assert_eq!(m.to.len(), 2);
        assert_eq!(m.to[1].display.as_deref(), Some("王五"));
        assert_eq!(m.body_kind, BodyKind::Plain);
        assert_eq!(m.body_text.as_deref(), Some("第一行\n第二行"));
        assert!(m.body_html.is_none());
        assert_eq!(m.date.unwrap().timestamp(), 1475417182);
        assert!(!m.has_attachments());
    }

    #[test]
    fn untagged_message_id_and_references() {
        let raw = plain(
            "Message-ID: <a@x>\r\nIn-Reply-To: <b@x> <c@x>\r\nReferences: <p@x>\r\n  <q@x>  <r@x>",
            "x",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.message_id.as_deref(), Some("a@x"));
        assert_eq!(m.in_reply_to.as_deref(), Some("b@x"));
        assert_eq!(m.references, vec!["p@x", "q@x", "r@x"]);
    }

    #[test]
    fn bcc_is_parsed_like_the_other_address_headers() {
        let raw = plain(
            "From: a@x\r\nTo: b@x\r\nCc: c@x\r\nBcc: d@x, =?UTF-8?B?5byg5LiJ?= <e@x>",
            "x",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.cc.len(), 1);
        assert_eq!(m.bcc.len(), 2, "Bcc 要和 To/Cc 一样解析: {:?}", m.bcc);
        assert_eq!(m.bcc[0].address, "d@x");
        assert_eq!(m.bcc[1].display.as_deref(), Some("张三"));
        assert_eq!(m.bcc[1].address, "e@x");
    }

    #[test]
    fn malformed_address_falls_back_to_display() {
        let raw = plain("From: 张三（无地址）", "x");
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.from.len(), 1);
        assert_eq!(m.from[0].address, "张三（无地址）");
    }

    #[test]
    fn prefers_html_over_plain_in_alternative() {
        let raw = concat!(
            "Content-Type: multipart/alternative; boundary=bnd\r\n\r\n",
            "--bnd\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n纯文本\r\n",
            "--bnd\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>富文本</p>\r\n",
            "--bnd--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_kind, BodyKind::Html);
        assert_eq!(m.body_html.as_deref(), Some("<p>富文本</p>"));
        // 纯文本那一路留着，列表预览和搜索要它
        assert_eq!(m.body_text.as_deref(), Some("纯文本"));
    }

    #[test]
    fn nested_related_inside_alternative() {
        // Outlook / Exchange 的典型结构
        let raw = concat!(
            "Content-Type: multipart/alternative; boundary=alt\r\n\r\n",
            "--alt\r\nContent-Type: text/plain\r\n\r\n纯的\r\n",
            "--alt\r\nContent-Type: multipart/related; boundary=rel\r\n\r\n",
            "--rel\r\nContent-Type: text/html\r\n\r\n<p>hi <img src=\"cid:logo\"></p>\r\n",
            "--rel\r\nContent-Type: image/png\r\nContent-ID: <logo>\r\nContent-Disposition: inline\r\n\r\nPNGDATA\r\n",
            "--rel--\r\n",
            "--alt--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_kind, BodyKind::Html);
        assert!(m.body_html.as_deref().unwrap().contains("cid:logo"));
        assert_eq!(m.attachments.len(), 1);
        assert!(m.attachments[0].meta.inline, "cid 引用的图是内嵌，不是附件");
        assert_eq!(m.attachments[0].meta.content_id.as_deref(), Some("logo"));
        assert!(!m.has_attachments(), "只有内嵌图不该显示附件标记");
    }

    #[test]
    fn mixed_body_plus_attachments() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=mix\r\n\r\n",
            "--mix\r\nContent-Type: text/plain\r\n\r\n正文\r\n",
            "--mix\r\nContent-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename=\"=?UTF-8?B?5oql5Lu3LnBkZg==?=\"\r\n\r\nPDFBYTES\r\n",
            "--mix\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=\"logo.png\"\r\n\r\nPNG\r\n",
            "--mix--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_text.as_deref(), Some("正文"));
        assert_eq!(m.attachments.len(), 2);

        // `=?UTF-8?B?5oql5Lu3LnBkZg==?=` 解出来是「报价.pdf」
        assert_eq!(m.attachments[0].meta.filename, "报价.pdf");
        assert!(!m.attachments[0].meta.inline);
        assert_eq!(m.attachments[0].meta.mime_type, "application/pdf");

        // 没有 Content-ID 的 inline 图片不叫内嵌，它就是个附件
        assert_eq!(m.attachments[1].meta.filename, "logo.png");
        assert!(!m.attachments[1].meta.inline);
        assert!(m.has_attachments());
    }

    #[test]
    fn html_attachment_is_not_second_body() {
        // 这是「第一个 text/* 就是正文」那种启发式的反例
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=mix\r\n\r\n",
            "--mix\r\nContent-Type: text/plain\r\n\r\n正文\r\n",
            "--mix\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=\"report.html\"\r\n\r\n<h1>报表</h1>\r\n",
            "--mix--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_kind, BodyKind::Plain);
        assert_eq!(m.body_text.as_deref(), Some("正文"));
        assert!(m.body_html.is_none(), "附件里的 HTML 不能当第二段正文");
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].meta.filename, "report.html");
    }

    #[test]
    fn signed_second_part_is_not_an_attachment() {
        let raw = concat!(
            "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=sg\r\n\r\n",
            "--sg\r\nContent-Type: text/plain\r\n\r\n正文\r\n",
            "--sg\r\nContent-Type: application/pkcs7-signature\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\nSIG\r\n",
            "--sg--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_text.as_deref(), Some("正文"));
        assert!(m.attachments.is_empty(), "签名块不该出现在附件列表里");
    }

    #[test]
    fn pure_attachment_mail_has_empty_body() {
        let raw = concat!(
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nPDF",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_kind, BodyKind::Empty);
        assert!(m.body_html.is_none() && m.body_text.is_none());
        assert_eq!(m.attachments.len(), 1);
    }

    #[test]
    fn unlabelled_utf8_body_is_not_mojibake() {
        // 国内邮件最常见的形态：UTF-8 正文，Content-Type 不写 charset。
        // mailparse 会按 windows-1252 解，中文就废了。
        let raw = plain("Content-Type: text/plain", "中文正文测试");
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_text.as_deref(), Some("中文正文测试"));
    }

    #[test]
    fn gbk_body_is_decoded() {
        let (bytes, _, _) = encoding_rs::GBK.encode("中文 GBK 正文");
        let mut raw: Vec<u8> = b"Content-Type: text/plain; charset=gbk\r\n\
                                 Content-Transfer-Encoding: base64\r\n\r\n"
            .to_vec();
        raw.extend_from_slice(base64_engine().encode(bytes.as_ref()).as_bytes());
        let m = parse_message(&raw).unwrap();
        assert_eq!(m.body_text.as_deref(), Some("中文 GBK 正文"));
    }

    #[test]
    fn base64_and_quoted_printable_bodies() {
        let raw = concat!(
            "Content-Type: multipart/alternative; boundary=b\r\n\r\n",
            "--b\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
            "5Lit5paH\r\n",
            "--b\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
            "<p>=E4=B8=AD=E6=96=87</p>\r\n",
            "--b--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.body_text.as_deref(), Some("中文"));
        assert_eq!(m.body_html.as_deref(), Some("<p>中文</p>"));
    }

    #[test]
    fn attachment_id_is_stable_index() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=m\r\n\r\n",
            "--m\r\nContent-Type: text/plain\r\n\r\nx\r\n",
            "--m\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\nAAA\r\n",
            "--m\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"b.bin\"\r\n\r\nBBB\r\n",
            "--m--\r\n",
        );
        let m = parse_message(raw.as_bytes()).unwrap();
        assert_eq!(m.attachments[0].meta.id, "0");
        assert_eq!(m.attachments[1].meta.id, "1");
        assert_eq!(m.attachments[1].data, b"BBB");
    }

    #[test]
    fn raw_headers_are_collected() {
        let raw = plain("X-Custom: hello\r\nSubject: s", "b");
        let m = parse_message(raw.as_bytes()).unwrap();
        assert!(m.raw_headers.iter().any(|(k, v)| k == "X-Custom" && v == "hello"));
        assert!(m.raw_headers.iter().any(|(k, _)| k == "Subject"));
    }

    /// 只为了 gbk 那个测试能拿到 base64 encoder（base64 是 sanitize 的依赖，
    /// 这里不 re-export）。
    #[cfg(test)]
    fn base64_engine() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }
}
