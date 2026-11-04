//! 撰写 —— 把「一封信」组装成 RFC 5322 原文
//!
//! 解析在 [`crate::mime`]，构造在这里。两个方向**不共享中间表示**：解析出来的
//! 是「别人写的信长什么样」，构造的是「我要发什么」，勉强共用会把两边的约束
//! 混在一起。
//!
//! ## 不变量：`build()` 的输出是纯 ASCII
//!
//! 非 ASCII 一律编码掉 —— 头部走 RFC 2047，正文走 quoted-printable，附件走
//! base64，文件名走 RFC 2231。于是：
//!
//! - 原文可以直接当字节写进 socket / 写进文件，不用再操心编码
//! - 测试可以拿 `str` 断言，不用比字节数组
//!
//! 有一条**单测**守着这条不变量（`output_is_always_ascii`）。
//!
//! ## 三条容易做错的
//!
//! 1. **`Bcc` 不进原文。**RFC 5322 说 Bcc 头不随信送出，投递是 SMTP 的
//!    `RCPT TO` 决定的。塞进 DATA 的后果是每个收件人都看得见密送名单。
//! 2. **正文行尾的空格 / 制表符必须编码掉**（`=20` / `=09`）。quoted-printable
//!    的行尾空白会被接收端吃掉，一个字都不留。
//! 3. **内嵌图和附件分属两层**。`cid:` 引用的图要进 `multipart/related`，
//!    真正的附件进 `multipart/mixed`。塞错层对方就看不见图。
//!
//! ## 这里的 HTML 不净化
//!
//! [`Composer::html`] 是**用户自己写的**（contenteditable 产出），要原样发出去，
//! 净化是给「收到的信」用的（[`crate::sanitize`]）。
//!
//! ⚠️ 但**任何把外部 HTML 塞进来的功能（回复引用、邮件模板）都必须先净化**，
//! 否则就等于把 `<script>` 发给收件人，回信时还会渲染回自己脸上。这条留给做
//! 回复的人，别漏。

use chrono::{DateTime, Utc};

use crate::error::{Error, Result};
use crate::types::Mailbox;

// ================================================================= 输入

/// 一个要发出去的附件。
#[derive(Debug, Clone)]
pub struct OutAttachment {
    pub filename: String,
    /// `image/png` 之类。空就当 `application/octet-stream`
    pub mime_type: String,
    pub content: Vec<u8>,
    /// 带这个就是**内嵌图**（正文里用 `cid:` 引用它），不带就是普通附件。
    /// 值是 Content-ID，**不含尖括号**。
    pub content_id: Option<String>,
}

/// 一封信的全部内容。正文**不含签名**，签名在 [`Composer::build`] 里追加。
#[derive(Debug, Clone)]
pub struct Composer {
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    /// 会用来算 `RCPT TO`，但**不会写进原文**（见模块头）
    pub bcc: Vec<Mailbox>,
    pub subject: String,
    /// 回复时带上原信的 Message-ID（不含尖括号）
    pub in_reply_to: Option<String>,
    /// 引用链，按「最早的在前」排列（不含尖括号）
    pub references: Vec<String>,
    pub text: String,
    /// `None` = 只发纯文本
    pub html: Option<String>,
    /// 签名，纯文本。`None` 不加
    pub signature: Option<String>,
    pub attachments: Vec<OutAttachment>,
    /// 不给就用当前时间
    pub date: Option<DateTime<Utc>>,
    /// 不给就现生成一个
    pub message_id: Option<String>,
}

impl Composer {
    pub fn new(from: Mailbox) -> Self {
        Composer {
            from,
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: String::new(),
            in_reply_to: None,
            references: Vec::new(),
            text: String::new(),
            html: None,
            signature: None,
            attachments: Vec::new(),
            date: None,
            message_id: None,
        }
    }

    /// 组装成 RFC 5322 原文。返回的是纯 ASCII [`String`]。
    pub fn build(&self) -> Result<String> {
        let date = self.date.unwrap_or_else(Utc::now);
        let message_id = self
            .message_id
            .clone()
            .unwrap_or_else(|| generate_message_id(&self.from.address));

        // ---- 正文（签名追加在这一层）------------------------------------
        let text = apply_signature_text(&self.text, self.signature.as_deref());
        let html = self
            .html
            .as_deref()
            .map(|h| apply_signature_html(h, self.signature.as_deref()));

        // ---- MIME 树 ----------------------------------------------------
        //   body = alternative(text, html)
        //   有内嵌图 → related(body, 图…)
        //   有附件   → mixed(body, 附件…)
        let inline: Vec<&OutAttachment> =
            self.attachments.iter().filter(|a| a.content_id.is_some()).collect();
        let attached: Vec<&OutAttachment> =
            self.attachments.iter().filter(|a| a.content_id.is_none()).collect();

        let mut body = match &html {
            Some(h) => part_multipart(
                "alternative",
                &[part_text("plain", &text), part_text("html", h)],
            )?,
            None => part_text("plain", &text),
        };

        if !inline.is_empty() {
            let mut parts = vec![body];
            for a in &inline {
                parts.push(part_binary(a)?);
            }
            body = part_multipart("related", &parts)?;
        }
        if !attached.is_empty() {
            let mut parts = vec![body];
            for a in &attached {
                parts.push(part_binary(a)?);
            }
            body = part_multipart("mixed", &parts)?;
        }

        // ---- 头 ---------------------------------------------------------
        // 注意顺序：Subject 要能被 `head -1` 之类看到，From/To/Date 在前是惯例
        let mut out = String::new();
        push_addr(&mut out, "From", &[self.from.clone()]);
        if !self.to.is_empty() {
            push_addr(&mut out, "To", &self.to);
        }
        if !self.cc.is_empty() {
            push_addr(&mut out, "Cc", &self.cc);
        }
        // Bcc 故意不写 —— 见模块头
        push_header(&mut out, "Subject", &header_atoms(&self.subject));
        out.push_str(&format!("Date: {}\r\n", format_date(date)));
        out.push_str(&format!("Message-ID: <{message_id}>\r\n"));
        if let Some(rt) = &self.in_reply_to {
            out.push_str(&format!("In-Reply-To: <{rt}>\r\n"));
        }
        if !self.references.is_empty() {
            let chain: Vec<String> = self.references.iter().map(|r| format!("<{r}>")).collect();
            out.push_str(&format!("References: {}\r\n", chain.join(" ")));
        }
        out.push_str("MIME-Version: 1.0\r\n");
        out.push_str(&body.headers);
        out.push_str("\r\n");
        out.push_str(&body.content);
        // RFC 5322 的「行」是以 CRLF 结束的，最后那行正文也一样。
        //
        // 不补的话，上线时是 SMTP 层替它补的 —— 于是「`build()` 的输出就是
        // 线上字节」这条性质破了。这条性质一破，「发出去的信和撰写时拼的那封
        // 是同一封」就没法验了，而这恰恰是发信测试的第一条断言。
        if !out.ends_with("\r\n") {
            out.push_str("\r\n");
        }
        Ok(out)
    }
}

// ================================================================= 内联图

/// 把正文里的内联图从 `data:` URL 拆成内嵌附件，正文里的 `src` 换成 `cid:`。
///
/// 撰写窗口把插进去的图存成 `data:` URL —— 编辑器要能就地看见图，而 `cid:`
/// 在浏览器里渲染不出来。发信时才拆开：收信方的客户端认的是 `cid:` 引用 +
/// `multipart/related` 里的图，一大串 base64 塞在 `src` 里它多半不认。
///
/// 返回 `(改写后的正文, 拆出来的图)`。拆出来的图带
/// [`OutAttachment::content_id`]，于是 [`Composer::build`] 会把它们放进
/// `multipart/related` 那一层。正文除了那几个 `src` 的值，**一个字节都不动**
/// —— 这是作者自己写的 HTML（见模块头），不是拿来净化的。
///
/// 同一个 `data:` URL 出现几次就只发一份图，正文里几处都指向它。
///
/// 只认 `data:<mime>;base64,<数据>` 这一种写法。别的（百分号编码的 data URL、
/// `https:`、本来就是 `cid:` 的）原样留着：撰写窗口只产生 base64，其余的
/// 既不该拆，也多半拆不动。
///
/// `content_id` 是 `img0`、`img1`…（按出现顺序）。这些名字由本函数分配，
/// 调用方**别**给自己的附件用同名 `content_id` —— 撞了会有两段 MIME 共用
/// 一个 Content-ID，收信方只显示其中一张。现在的调用链撞不上：草稿里的
/// 附件不设 `content_id`（见 `src/compose.js`）。
pub fn extract_inline_images(html: &str) -> (String, Vec<OutAttachment>) {
    use base64::Engine;

    let b = html.as_bytes();
    let mut out = String::with_capacity(html.len());
    let mut images: Vec<OutAttachment> = Vec::new();
    // value(整个 data URL) → cid。同一张图插两次只发一份
    let mut seen: Vec<(&str, String)> = Vec::new();
    // `out` 已经原样抄进来的前缀长度。不逐段抄是因为中间那几段是 base64，
    // 抄一遍白抄一遍
    let mut copied = 0usize;

    let mut i = 0usize;
    while let Some(eq) = find_src_assign(b, i) {
        i = eq + 4;
        let quote = *b.get(i).unwrap_or(&0);
        if quote != b'"' && quote != b'\'' {
            continue;
        }
        let val_start = i + 1;
        let Some(val_end) = find_quote(b, val_start, quote) else {
            continue;
        };
        let value = &html[val_start..val_end];
        let Some((mime, payload)) = split_base64_data_url(value) else {
            continue;
        };

        let cid = match seen.iter().find(|(v, _)| *v == value) {
            // 同一张图已经发过了，正文里这处也指向它
            Some((_, cid)) => cid.clone(),
            None => {
                let Ok(content) = base64::engine::general_purpose::STANDARD.decode(payload) else {
                    continue;
                };
                let cid = format!("img{}", images.len());
                seen.push((value, cid.clone()));
                images.push(OutAttachment {
                    filename: guess_filename(&cid, mime),
                    mime_type: mime.to_string(),
                    content,
                    content_id: Some(cid.clone()),
                });
                cid
            }
        };

        out.push_str(&html[copied..val_start]);
        out.push_str("cid:");
        out.push_str(&cid);
        copied = val_end;
        i = val_end;
    }
    out.push_str(&html[copied..]);
    (out, images)
}

/// 找下一个 `src=`（属性名大小写不敏感），返回 `s` 那个字节的位置。
///
/// 前面必须不是属性名里能出现的字符 —— 免得把 `data-src=` 里的 `src=`
/// 当成真属性。
fn find_src_assign(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 4 <= b.len() {
        let is_src = (b[i] | 0x20) == b's'
            && (b[i + 1] | 0x20) == b'r'
            && (b[i + 2] | 0x20) == b'c'
            && b[i + 3] == b'=';
        let starts_name = i > 0 && {
            let c = b[i - 1];
            c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':' | b'.')
        };
        if is_src && !starts_name {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 找 `from` 之后第一个 `quote` 字节。HTML 属性值里没有转义，见到引号就是结束。
fn find_quote(b: &[u8], from: usize, quote: u8) -> Option<usize> {
    b[from.min(b.len())..].iter().position(|&c| c == quote).map(|p| from + p)
}

/// `data:image/png;base64,AAAA` → `("image/png", "AAAA")`。
///
/// mediatype 里的参数原样带出去（`data:image/svg+xml;charset=utf-8;base64,…`
/// → `"image/svg+xml;charset=utf-8"`），那是合法的 `Content-Type`，扔了可惜。
/// 不是 base64 写法就返回 `None`，让调用方原样留着。
fn split_base64_data_url(value: &str) -> Option<(&str, &str)> {
    let (meta, payload) = value.strip_prefix("data:")?.split_once(',')?;
    let mime = meta.strip_suffix(";base64")?;
    // `;base64` 必须是**最后一段**，`data:image/png;base64x` 那种不是
    if mime.is_empty() || payload.is_empty() {
        return None;
    }
    Some((mime, payload))
}

/// 内嵌图的文件名，只给调试看。`Content-Disposition: inline` 不写 filename
/// （见 [`part_binary`]），所以这个名字不会上线路。
fn guess_filename(cid: &str, mime: &str) -> String {
    let ext = match mime.split(';').next().unwrap_or("").trim() {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        _ => "img",
    };
    format!("{cid}.{ext}")
}

// ================================================================= 一个 MIME 段

struct Part {
    /// `Content-Type: …\r\n` + `Content-Transfer-Encoding: …\r\n` + 可选的
    /// `Content-Disposition` / `Content-ID`
    headers: String,
    content: String,
}

fn part_text(subtype: &str, body: &str) -> Part {
    Part {
        headers: format!(
            "Content-Type: text/{subtype}; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n"
        ),
        content: encode_quoted_printable(body),
    }
}

fn part_binary(a: &OutAttachment) -> Result<Part> {
    use base64::Engine;
    let mime = if a.mime_type.is_empty() { "application/octet-stream" } else { &a.mime_type };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&a.content);

    let mut headers = format!("Content-Type: {mime}\r\n");
    match &a.content_id {
        Some(cid) => {
            // 内嵌图：没有 filename，靠 Content-ID 被 `cid:` 引用
            headers.push_str(&format!("Content-ID: <{cid}>\r\n"));
            headers.push_str("Content-Disposition: inline\r\n");
        }
        None => {
            headers.push_str(&format!(
                "Content-Disposition: attachment; {}\r\n",
                filename_param(&a.filename)
            ));
        }
    }
    headers.push_str("Content-Transfer-Encoding: base64\r\n");

    Ok(Part { headers, content: fold_base64(&b64) })
}

fn part_multipart(subtype: &str, parts: &[Part]) -> Result<Part> {
    // 边界不能撞上内容。撞上了就换一个再来，换五次还不行就报错。
    let mut nonce = 0u32;
    let boundary = loop {
        let b = format!("----=_Mailway_{:08x}_{nonce}", Utc::now().timestamp_subsec_nanos());
        let collision = parts.iter().any(|p| p.content.contains(&b) || p.headers.contains(&b));
        if !collision {
            break b;
        }
        nonce += 1;
        if nonce > 5 {
            return Err(Error::Compose("生成不出不冲突的 MIME 边界".into()));
        }
    };

    let mut content = String::new();
    for p in parts {
        content.push_str(&format!("--{boundary}\r\n"));
        content.push_str(&p.headers);
        content.push_str("\r\n");
        content.push_str(&p.content);
        if !p.content.ends_with("\r\n") {
            content.push_str("\r\n");
        }
    }
    content.push_str(&format!("--{boundary}--\r\n"));

    // `related` 的 type 参数要说清内层是什么，不然对方可能只渲染最后一段。
    // 只取**媒体类型**本身 —— 把整个 Content-Type 值塞进去会把 boundary 也
    // 带上，出来的 `type="multipart/alternative; boundary="…""` 是非法的。
    let type_param = match subtype {
        "related" => {
            let inner = parts
                .first()
                .and_then(|p| p.headers.lines().find_map(|l| l.strip_prefix("Content-Type: ")))
                .map(|v| v.split(';').next().unwrap_or("").trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "multipart/alternative".into());
            format!("; type=\"{inner}\"")
        }
        _ => String::new(),
    };

    Ok(Part {
        headers: format!(
            "Content-Type: multipart/{subtype}; boundary=\"{boundary}\"{type_param}\r\n"
        ),
        content,
    })
}

// ================================================================= 编码

/// RFC 2045 quoted-printable。
///
/// 三个容易漏的点：
///   - **行尾空白必须编码**（`=20` / `=09`），否则接收端吃掉它们
///   - 一行最长 76 字符（含 CRLF），超了用软换行 `=\r\n` 接
///   - 软换行**不能切开 `=XX` 转义**，所以按「原子」推进而不是按字符
fn encode_quoted_printable(input: &str) -> String {
    let mut out = String::new();
    for (li, raw_line) in input.split('\n').enumerate() {
        if li > 0 {
            out.push_str("\r\n");
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let bytes = line.as_bytes();

        // 结尾的空白要编码，先记下「不用编码的边界」
        let mut keep = bytes.len();
        while keep > 0 && matches!(bytes[keep - 1], b' ' | b'\t') {
            keep -= 1;
        }

        let mut cur = String::new();
        for (i, &b) in bytes.iter().enumerate() {
            let atom: String = match b {
                _ if i >= keep => escape_byte(b),
                b'=' => escape_byte(b),
                0x21..=0x7e => (b as char).to_string(),
                _ => escape_byte(b),
            };
            // 留一位给软换行那个 `=`
            if cur.len() + atom.len() > 75 {
                out.push_str(&cur);
                out.push_str("=\r\n");
                cur = String::new();
            }
            cur.push_str(&atom);
        }
        out.push_str(&cur);
    }
    out
}

fn escape_byte(b: u8) -> String {
    format!("={b:02X}")
}

/// encoded-word 的最大长度。
///
/// RFC 2047 §2 说单个 encoded-word 最长 75，但**整行**还得装下 `Subject: ` 这样的
/// 前缀（RFC 5322 上限 78）。折行救不了单个原子 —— encoded-word 不能被切开。
/// 所以这里取 69 = 78 − len("Subject: ")，是我们用到的最长前缀
/// （`In-Reply-To: ` 更长，但它的原子是 Message-ID，不编码）。
const MAX_WORD: usize = 69;

/// 一个头部值拆成**原子** —— 折行时不会被切开的最小单位。
///
/// - 非 ASCII → 若干 RFC 2047 encoded-word
/// - ASCII → 按空格拆词（空格属于 CFWS，折在这里不影响语义）
fn header_atoms(s: &str) -> Vec<String> {
    if s.is_ascii() {
        return s.split(' ').filter(|w| !w.is_empty()).map(str::to_string).collect();
    }
    // **按字节切，不能按字符**：base64 的长度由字节数决定，一个汉字占 3 字节
    // 却只算 1 个字符 —— 按字符数切会切出 100 多字符的「单词」，第一版就是
    // 这么错的，单测当场逮住。
    const WRAPPER: usize = 12; // "=?UTF-8?B?" (10) + "?=" (2)
    let payload_max = MAX_WORD - WRAPPER; // 57 个 base64 字符
    // base64 每 3 字节变 4 字符，所以每块最多 57/4*3 = 42 字节
    let chunk_bytes = payload_max / 4 * 3;

    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if !cur.is_empty() && cur.len() + ch.len_utf8() > chunk_bytes {
            words.push(encode_word(&cur));
            cur = String::new();
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        words.push(encode_word(&cur));
    }
    words
}

fn encode_word(s: &str) -> String {
    use base64::Engine;
    format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    )
}

/// 一个地址拆成原子。显示名非 ASCII 走 RFC 2047；ASCII 但含特殊字符就加引号。
///
/// 引号包起来的显示名是**一个**原子 —— 中间的空格不能拿来折行。
fn mailbox_atoms(m: &Mailbox) -> Vec<String> {
    let mut atoms = Vec::new();
    if let Some(d) = m.display.as_deref().filter(|s| !s.is_empty()) {
        if !d.is_ascii() {
            atoms.extend(header_atoms(d));
        } else {
            // RFC 5322 的 atext 之外都要引号包起来
            let special =
                d.contains(['(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '[', ']']);
            atoms.push(if special {
                format!("\"{}\"", d.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                d.to_string()
            });
        }
    }
    atoms.push(format!("<{}>", m.address));
    atoms
}

/// 把原子摆进一个头部，按 RFC 5322 §2.1.1 折行。
///
/// 一行最长 78 字符，续行前导一个空格。**只在原子之间折**，所以原子自己得短
/// （encoded-word 已经限到 [`MAX_WORD`]）。原子之间用单个空格连 —— 那是 CFWS，
/// 多一个少一个都不影响语义。
fn push_header(out: &mut String, name: &str, atoms: &[String]) {
    const MAX_LINE: usize = 78;

    let mut line = format!("{name}: ");
    let mut width = line.len();

    for (i, a) in atoms.iter().enumerate() {
        let sep = if i == 0 { 0 } else { 1 };
        if i > 0 && width + sep + a.len() > MAX_LINE {
            out.push_str(&line);
            out.push_str("\r\n");
            line = String::from(" ");
            width = 1;
        } else if i > 0 {
            line.push(' ');
            width += 1;
        }
        line.push_str(a);
        width += a.len();
    }
    out.push_str(&line);
    out.push_str("\r\n");
}

fn push_addr(out: &mut String, name: &str, list: &[Mailbox]) {
    let mut atoms = Vec::new();
    for (i, m) in list.iter().enumerate() {
        if i > 0 {
            atoms.push(",".to_string());
        }
        atoms.extend(mailbox_atoms(m));
    }
    push_header(out, name, &atoms);
}

/// RFC 5322 日期，**永远用英文缩写和 +0000**。
///
/// 不要用本地时区：`Date` 是给全世界的人看的，自己算偏移只会把人绕晕，
/// 而且 `%Z` 在某些平台会给出本地化的时区名，那不是合法的 RFC 5322。
fn format_date(t: DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S +0000").to_string()
}

/// Content-Disposition 的 filename 参数。
///
/// 非 ASCII 走 RFC 2231 的 `filename*=UTF-8''%XX…`。**不要**用 RFC 2047 编
/// 文件名 —— 那在参数里不是合法语法，只是大家凑合能解。
fn filename_param(name: &str) -> String {
    if name.is_ascii() && !name.contains(['"', '\\']) {
        return format!("filename=\"{name}\"");
    }
    if name.is_ascii() {
        return format!("filename=\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""));
    }
    let mut enc = String::from("filename*=UTF-8''");
    for b in name.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                enc.push(*b as char)
            }
            _ => enc.push_str(&format!("%{b:02X}")),
        }
    }
    enc
}

/// base64 每 76 个字符折一行（RFC 2045）。
fn fold_base64(s: &str) -> String {
    let mut out = String::new();
    for (i, chunk) in s.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(std::str::from_utf8(chunk).expect("base64 输出是 ASCII"));
    }
    out.push_str("\r\n");
    out
}

// ================================================================= 签名

/// 签名的正文 —— **分隔线之后**那几行。
///
/// 现实里几乎所有人的签名都自带一行 `--`（从别的客户端复制过来的、或者是
/// 网上抄的模板）。那种就别再加一遍分隔线：发出去是两行破折号，收件人看着
/// 像坏了。见到第一行是 `--` 就当它已经带了，丢掉那一行，剩下的照用。
fn signature_body(sig: &str) -> &str {
    let s = sig.trim_start_matches('\n');
    let Some((first, rest)) = s.split_once('\n') else {
        // 整个签名就一行。是 `--` 的话等于没有正文，那就整个不要
        return if s.trim_end() == "--" { "" } else { s };
    };
    if first.trim_end() == "--" {
        rest.trim_start_matches('\n')
    } else {
        s
    }
}

/// 纯文本签名。分隔符是 `-- `（**破折号、破折号、空格**），尾巴那个空格
/// 不能少 —— 那是 Usenet 定下的惯例，客户端据此判断「下面是签名」。
fn apply_signature_text(body: &str, sig: Option<&str>) -> String {
    let Some(sig) = sig.map(signature_body).filter(|s| !s.trim().is_empty()) else {
        return body.to_string();
    };
    let mut out = body.trim_end_matches('\n').to_string();
    out.push_str("\n\n-- \n");
    out.push_str(sig.trim_end_matches('\n'));
    out.push('\n');
    out
}

/// HTML 签名。签名是**纯文本**，进 HTML 前必须转义 —— 它是配置项，
/// 但配置项也是能被塞进 `<script>` 的，别开这个口子。
fn apply_signature_html(body: &str, sig: Option<&str>) -> String {
    let Some(sig) = sig.map(signature_body).filter(|s| !s.trim().is_empty()) else {
        return body.to_string();
    };
    let escaped: String = sig
        .trim_end_matches('\n')
        .chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '\n' => "<br>".into(),
            _ => c.to_string(),
        })
        .collect();
    format!("{body}<br><br>-- <br>{escaped}")
}

// ================================================================= 杂项

/// 生成一个 Message-ID（**不含尖括号**）。
///
/// 发信前要定死一个（[`crate::send`] 用）—— 「报出去的 id」和「信头里的 id」
/// 必须是同一个，否则排错时对不上服务器的记录。不给 [`Composer::message_id`]
/// 的话 [`Composer::build`] 也会自己调它。
pub fn generate_message_id(from_address: &str) -> String {
    let domain = from_address.rsplit('@').next().unwrap_or("localhost");
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    // pid 混进来，同一秒内起两个进程也不会撞
    let pid = std::process::id();
    format!("{nanos:x}.{pid:x}.{domain}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Mailbox {
        Mailbox { display: Some("我".into()), address: "me@example.com".into() }
    }

    fn you() -> Mailbox {
        Mailbox { display: None, address: "you@example.com".into() }
    }

    fn body_of(raw: &str) -> &str {
        raw.split_once("\r\n\r\n").expect("有空行分隔头和体").1
    }

    /// 正文的**内容**，不含最后一行的行终止符。
    ///
    /// RFC 5322 的「行」是由 CRLF 结束的 —— 最后那行正文也一样。那个 CRLF 是
    /// 行的终止符，不是正文的一部分（收件人打出来的就是 `hello`，不是 `hello`
    /// 再加一空行）。逐字节的解析器会把它原样带回来，所以这里去掉**正好一个**。
    ///
    /// 只去一个是有意的：去掉两个就藏得住「正文末尾多打了一个空行」那种 bug。
    fn content_of(body: &str) -> &str {
        body.strip_suffix("\r\n").or_else(|| body.strip_suffix('\n')).unwrap_or(body)
    }

    /// 绕一圈：构造 → 解析。
    ///
    /// 断言**「收件人看到什么」**比断言原文的字节形态稳得多 —— 前者是需求，
    /// 后者是实现细节（quoted-printable 会把中文和 `-- ` 里的空格一起编码，
    /// 在原文上找字符串只会自己绊自己）。
    fn parsed(raw: &str) -> crate::mime::ParsedMessage {
        crate::mime::parse_message(raw.as_bytes()).unwrap()
    }

    /// 全篇最硬的一条不变量：输出必须是纯 ASCII。
    #[test]
    fn output_is_always_ascii() {
        let mut c = Composer::new(me());
        c.to.push(Mailbox { display: Some("张三 李四".into()), address: "z@e.com".into() });
        c.subject = "中文主题里还夹着 emoji 🎉 和一个很长很长很长很长很长的句子用来逼出折行".into();
        c.text = "正文带中文、emoji 🎉、等号 = 和行尾空格   \n第二行\t制表符\n".into();
        c.html = Some("<p>中文 <b>加粗</b> 🎉</p>".into());
        c.signature = Some("张三\n研发部".into());
        c.attachments.push(OutAttachment {
            filename: "中文报告.pdf".into(),
            mime_type: "application/pdf".into(),
            content: vec![0, 1, 2, 255, 254],
            content_id: None,
        });
        c.attachments.push(OutAttachment {
            filename: "logo.png".into(),
            mime_type: "image/png".into(),
            content: vec![137, 80, 78, 71],
            content_id: Some("logo@mailway.local".into()),
        });

        let raw = c.build().unwrap();
        assert!(
            raw.is_ascii(),
            "原文必须纯 ASCII，才好直接当字节发。非 ASCII 出现在: {:?}",
            raw.chars().find(|ch| !ch.is_ascii()).map(|ch| {
                let i = raw.find(ch).unwrap();
                raw[i.saturating_sub(40)..(i + 20).min(raw.len())].to_string()
            })
        );
    }

    #[test]
    fn plain_text_only_is_not_multipart() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.subject = "hi".into();
        c.text = "hello".into();

        let raw = c.build().unwrap();
        assert!(raw.starts_with("From: "), "头从 From 开始: {raw}");
        assert!(raw.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(!raw.contains("multipart/"), "没有别的部件就别套 multipart");
        assert_eq!(content_of(body_of(&raw)), "hello");
    }

    #[test]
    fn html_makes_an_alternative() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "纯文本".into();
        c.html = Some("<p>富文本</p>".into());

        let raw = c.build().unwrap();
        assert!(
            raw.contains("Content-Type: multipart/alternative; boundary="),
            "文本 + HTML 要走 alternative: {raw}"
        );
        assert!(raw.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(raw.contains("Content-Type: text/html; charset=utf-8"));
    }

    #[test]
    fn inline_image_goes_into_related_and_attachment_into_mixed() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.html = Some("<p><img src=\"cid:logo@x\"></p>".into());
        c.attachments.push(OutAttachment {
            filename: "logo.png".into(),
            mime_type: "image/png".into(),
            content: b"PNG".to_vec(),
            content_id: Some("logo@x".into()),
        });
        c.attachments.push(OutAttachment {
            filename: "a.pdf".into(),
            mime_type: "application/pdf".into(),
            content: b"%PDF".to_vec(),
            content_id: None,
        });

        let raw = c.build().unwrap();
        // 从外到内：mixed → related → alternative → (text, html) + 图
        assert!(raw.contains("Content-Type: multipart/mixed; boundary="), "最外层是 mixed");
        assert!(raw.contains("Content-Type: multipart/related; boundary="), "内嵌图进 related");
        assert!(raw.contains("Content-ID: <logo@x>"), "内嵌图要有 Content-ID");
        assert!(raw.contains("Content-Disposition: inline"), "内嵌图是 inline");
        assert!(raw.contains("Content-Disposition: attachment; filename=\"a.pdf\""));
        // related 的 type 参数要说清内层，对方才知道怎么渲染
        assert!(
            raw.contains("type=\"multipart/alternative\""),
            "related 要带 type 参数: {raw}"
        );
    }

    #[test]
    fn inline_data_image_becomes_a_cid_part() {
        // 撰写窗口存的是 `data:` URL（编辑器要能就地看见图），发信时才拆开。
        let (html, images) = extract_inline_images(
            r#"<p>hi</p><img src="data:image/png;base64,aGVsbG8=" alt="x">"#,
        );
        // 除了 `src` 的值一个字节都不动 —— 作者写的 HTML 不是拿来规整的
        assert_eq!(html, r#"<p>hi</p><img src="cid:img0" alt="x">"#);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].content_id.as_deref(), Some("img0"));
        assert_eq!(images[0].mime_type, "image/png");
        assert_eq!(images[0].content, b"hello");

        // 整条路上线：拆出来的东西要被 build 放进 related，正文要指得到它
        let mut c = Composer::new(me());
        c.to.push(you());
        c.html = Some(html);
        c.attachments = images;
        let raw = c.build().unwrap();
        assert!(raw.contains("cid:img0"), "正文要指向 cid: {raw}");
        assert!(raw.contains("Content-ID: <img0>"));
        assert!(raw.contains("Content-Type: multipart/related; boundary="));
    }

    #[test]
    fn the_same_image_twice_is_sent_once() {
        // 同一张图在正文里出现两次（复制粘贴、页眉 logo）不该发两份
        let (html, images) = extract_inline_images(
            r#"<img src="data:image/png;base64,aGVsbG8="><img src="data:image/png;base64,aGVsbG8=">"#,
        );
        assert_eq!(html, r#"<img src="cid:img0"><img src="cid:img0">"#);
        assert_eq!(images.len(), 1, "同一张图发一份就够");
    }

    #[test]
    fn srcs_that_are_not_base64_data_urls_stay_put() {
        let html = r#"<img src="https://a/b.png"><img src="cid:x@y"><img src="data:text/plain,hi"><img src="data:image/png;base64,">"#;
        let (out, images) = extract_inline_images(html);
        assert_eq!(out, html, "一个字都不该动");
        assert!(images.is_empty());
    }

    #[test]
    fn data_src_is_not_mistaken_for_src() {
        let (out, images) = extract_inline_images(
            r#"<img data-src="data:image/png;base64,aGVsbG8=" src="data:image/png;base64,d29ybGQ=">"#,
        );
        assert_eq!(out, r#"<img data-src="data:image/png;base64,aGVsbG8=" src="cid:img0">"#);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].content, b"world");
    }

    #[test]
    fn single_quotes_and_uppercase_attr_work() {
        let (out, images) = extract_inline_images(r#"<IMG SRC='data:image/gif;base64,aGVsbG8='>"#);
        assert_eq!(out, r#"<IMG SRC='cid:img0'>"#, "引号和大小写照原样留着");
        assert_eq!(images[0].mime_type, "image/gif");
    }

    #[test]
    fn mediatype_parameters_keep_their_place() {
        let (out, images) =
            extract_inline_images(r#"<img src="data:image/svg+xml;charset=utf-8;base64,aGVsbG8=">"#);
        assert_eq!(out, r#"<img src="cid:img0">"#);
        assert_eq!(images[0].mime_type, "image/svg+xml;charset=utf-8");
    }

    #[test]
    fn undecodable_base64_stays_in_the_html() {
        // 拆不动就原样发出去 —— 把它摘掉等于把图弄丢，比发不出去更糟
        let html = r#"<img src="data:image/png;base64,!!! not base64 !!!">"#;
        let (out, images) = extract_inline_images(html);
        assert_eq!(out, html);
        assert!(images.is_empty());
    }

    #[test]
    fn bcc_never_reaches_the_wire() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.bcc.push(Mailbox { display: None, address: "secret@example.com".into() });
        c.text = "hi".into();

        let raw = c.build().unwrap();
        assert!(!raw.contains("secret@example.com"), "Bcc 头不能进原文: {raw}");
        assert!(!raw.contains("Bcc:"), "连 Bcc 这个字段名都不该出现");
    }

    #[test]
    fn trailing_whitespace_is_encoded_not_lost() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "行尾空格   \n行尾制表\t".into();

        let raw = c.build().unwrap();
        // 原文里必须是 =20 / =09 —— 直接留白会被接收端吃掉，一个字都不剩
        let body = body_of(&raw);
        assert!(body.contains("=20"), "行尾空格要编码: {body:?}");
        assert!(body.contains("=09"), "行尾制表符要编码: {body:?}");

        // 解回来一个字都不能少（原文是 CRLF，这里统一成 \n 再比）
        let got = parsed(&raw).body_text.unwrap().replace("\r\n", "\n");
        assert!(got.starts_with("行尾空格   \n行尾制表\t"), "空白被吃掉了: {got:?}");
    }

    #[test]
    fn equals_sign_is_escaped() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "a=b".into();
        let raw = c.build().unwrap();
        let body = content_of(body_of(&raw));
        assert_eq!(body, "a=3Db", "`=` 不转义会被当成软换行: {body}");
    }

    #[test]
    fn subject_is_rfc2047_and_survives_a_roundtrip() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.subject = "这是一封很长很长很长很长很长很长很长很长很长的中文主题".into();
        c.text = "x".into();

        let raw = c.build().unwrap();
        let line = raw.lines().find(|l| l.starts_with("Subject: ")).unwrap();
        assert!(line.contains("=?UTF-8?B?"), "主题要编码: {line}");
        assert!(line.is_ascii());

        // 拆行的每个 encoded-word 都不能超长
        for cont in raw.lines().filter(|l| l.starts_with("Subject: ") || l.starts_with(' ')) {
            assert!(cont.len() <= 78, "头行太长（RFC 5322 上限 78）: {:?}", cont);
        }

        // 往回解一遍，解不回来等于白编
        let parsed = crate::mime::parse_message(raw.as_bytes()).unwrap();
        assert_eq!(parsed.subject, "这是一封很长很长很长很长很长很长很长很长很长的中文主题");
    }

    #[test]
    fn non_ascii_filename_uses_rfc2231_and_survives_a_roundtrip() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "x".into();
        c.attachments.push(OutAttachment {
            filename: "年度报告.pdf".into(),
            mime_type: "application/pdf".into(),
            content: b"%PDF".to_vec(),
            content_id: None,
        });

        let raw = c.build().unwrap();
        assert!(raw.contains("filename*=UTF-8''"), "非 ASCII 文件名走 RFC 2231: {raw}");

        let parsed = crate::mime::parse_message(raw.as_bytes()).unwrap();
        let att = parsed
            .attachments
            .iter()
            .find(|a| !a.meta.inline)
            .expect("有一个真正的附件");
        assert_eq!(att.meta.filename, "年度报告.pdf", "文件名要能原样解回来");
    }

    #[test]
    fn signature_uses_the_usenet_delimiter() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "正文".into();
        c.signature = Some("张三\n研发部".into());

        let raw = c.build().unwrap();
        // 解出来才是收件人看到的 —— 原文里 `-- ` 的空格被编成了 =20
        let got = parsed(&raw).body_text.unwrap().replace("\r\n", "\n");
        assert!(got.contains("\n\n-- \n张三"), "分隔符是 `-- `，尾巴空格不能少: {got:?}");
    }

    #[test]
    fn signature_html_escapes_the_signature() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.html = Some("<p>hi</p>".into());
        c.signature = Some("<script>alert(1)</script>".into());

        let raw = c.build().unwrap();
        // 只看 HTML 那一段：纯文本里的 `<script>` 是无害的字面量，不该被转义
        let html = parsed(&raw).body_html.unwrap();
        assert!(!html.contains("<script>"), "签名里的标签必须转义: {html}");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn empty_signature_is_ignored() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "正文".into();
        c.signature = Some("   \n".into());

        let raw = c.build().unwrap();
        let got = parsed(&raw).body_text.unwrap();
        assert_eq!(content_of(&got), "正文", "空白签名不该加尾巴: {got:?}");
    }

    #[test]
    fn a_signature_that_already_has_the_delimiter_is_not_doubled() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "正文".into();
        // 从别的客户端复制过来的签名，自带一行 `--`。现实里基本都是这样。
        c.signature = Some("--\n张三\n研发部".into());

        let raw = c.build().unwrap();
        let got = parsed(&raw).body_text.unwrap().replace("\r\n", "\n");
        assert!(got.contains("\n\n-- \n张三"), "带了分隔线就直接用: {got:?}");
        assert!(!got.contains("-- \n--"), "不能出现两行破折号: {got:?}");
    }

    #[test]
    fn the_same_doubling_fix_applies_to_html() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.html = Some("<p>hi</p>".into());
        c.signature = Some("--\n张三".into());

        let raw = c.build().unwrap();
        let html = parsed(&raw).body_html.unwrap();
        assert!(html.contains("-- <br>张三"), "{html}");
        assert!(!html.contains("-- <br>--"), "不能出现两行破折号: {html}");
    }

    #[test]
    fn a_signature_of_only_the_delimiter_adds_nothing() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "正文".into();
        c.signature = Some("--".into());

        let raw = c.build().unwrap();
        let got = parsed(&raw).body_text.unwrap();
        assert_eq!(content_of(&got), "正文", "只有一行 `--` 等于没有签名: {got:?}");
    }

    #[test]
    fn ascii_display_name_with_specials_gets_quoted() {
        let m = Mailbox { display: Some(r#"Bob "The Builder""#.into()), address: "b@e.com".into() };
        assert_eq!(
            mailbox_atoms(&m).join(" "),
            r#""Bob \"The Builder\"" <b@e.com>"#,
            "特殊字符要引号包起来并转义"
        );
        // 空格不属于 atext 之外那些特殊字符，不用引号
        let m = Mailbox { display: Some("Bob Builder".into()), address: "b@e.com".into() };
        assert_eq!(mailbox_atoms(&m).join(" "), "Bob Builder <b@e.com>");
    }

    #[test]
    fn date_uses_english_and_utc() {
        let t = DateTime::parse_from_rfc3339("2026-11-02T10:41:07+08:00").unwrap().to_utc();
        assert_eq!(format_date(t), "Mon, 02 Nov 2026 02:41:07 +0000");
    }

    /// 长头必须折行，而且**不能在 encoded-word 中间折**。
    /// 这条守的是「单个原子装不下一行」的那类 bug —— 折行救不了它，
    /// 只能把原子本身弄短（见 [`MAX_WORD`]）。
    #[test]
    fn long_headers_fold_at_atom_boundaries() {
        let mut c = Composer::new(Mailbox {
            display: Some("一个特别特别长的中文显示名字用来把这一行撑爆".into()),
            address: "someone-with-a-very-long-name@subdomain.example.com".into(),
        });
        for i in 0..6 {
            c.to.push(Mailbox {
                display: Some(format!("收件人{号}", 号 = "一二三四五六".chars().nth(i).unwrap())),
                address: format!("recipient{i}@somewhere.example.com"),
            });
        }
        c.subject = "这是一封很长很长很长很长很长很长很长很长很长很长很长很长的中文主题".into();
        c.text = "x".into();

        let raw = c.build().unwrap();
        for line in raw.split("\r\n").take_while(|l| !l.is_empty()) {
            assert!(line.len() <= 78, "头行超长（RFC 5322 上限 78）: {:?}", line);
            // 折出来的续行以一个空格开头
        }
        assert!(raw.contains("\r\n "), "长头该折出续行: {raw}");
        // 折完还能解回来
        let p = parsed(&raw);
        assert_eq!(p.to.len(), 6);
        assert_eq!(
            p.subject,
            "这是一封很长很长很长很长很长很长很长很长很长很长很长很长的中文主题"
        );
    }

    #[test]
    fn soft_breaks_never_split_an_escape() {        // 一个纯非 ASCII 的长串：每 3 字节一个 =XX，很容易被软换行切开
        let s = "中".repeat(60);
        let enc = encode_quoted_printable(&s);
        for line in enc.split("\r\n") {
            let line = line.strip_suffix('=').unwrap_or(line);
            assert!(line.len() <= 76, "超行长了: {:?}", line);
            // 不允许出现 `=X` 这种残缺转义
            for (i, ch) in line.chars().enumerate() {
                if ch == '=' {
                    assert!(
                        line[i..].starts_with('=') && line[i + 1..].starts_with(|c: char| c.is_ascii_hexdigit()) && line[i + 2..].starts_with(|c: char| c.is_ascii_hexdigit()),
                        "软换行切开了 =XX 转义: {:?}",
                        line
                    );
                }
            }
        }
    }

    #[test]
    fn base64_body_is_folded_to_76() {
        let mut c = Composer::new(me());
        c.to.push(you());
        c.text = "x".into();
        c.attachments.push(OutAttachment {
            filename: "big.bin".into(),
            mime_type: "application/octet-stream".into(),
            content: vec![7u8; 300],
            content_id: None,
        });

        let raw = c.build().unwrap();
        let in_b64 = raw
            .split("Content-Transfer-Encoding: base64\r\n")
            .nth(1)
            .and_then(|s| s.split("\r\n--").next())
            .expect("有 base64 段");
        for line in in_b64.lines() {
            assert!(line.len() <= 76, "base64 折行不对: {:?}", line);
        }
    }
}
