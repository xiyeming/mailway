//! HTML 净化 —— **安全边界**
//!
//! 邮件正文是不可信输入。这一层是「解析出来的 HTML → 可以塞进 webview 的 HTML」
//! 之间唯一的一道闸，出 bug 就是远程代码执行，所以：
//!
//!   - 不自己写正则剥标签。用 `ammonia`（html5ever 上的白名单净化器）。
//!   - 不做「先净化再改」的事后修补。改图片 `src` 用 ammonia 自己的
//!     `attribute_filter` 钩子，发生在净化管线内部，逃不掉。
//!   - 远程图片默认拦截（隐私：发件人靠 1x1 像素就能追踪你何时读信）。
//!
//! 两个容易踩的坑，都是实测出来的：
//!
//! 1. **不能靠 `url_schemes` 拦远程图片**。那个开关是全局的、不分标签不分属性。
//!    删掉 http 会把 `<a href="http://…">` 一起剥掉，邮件里的链接全废。
//!    所以拦图片走 `attribute_filter`，只针对 `("img","src")`。
//! 2. **`data:` 只能对 `img src` 放行**。往 `url_schemes` 里加 `data` 会让
//!    `<a href="data:text/html,<script>…">` 过关，点一下就执行。所以 href 上的
//!    `data:` 必须单独掐掉。

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine;

/// 超过这个大小的 `data:` 图片直接丢弃，防止一封邮件把内存撑爆。
const MAX_DATA_URI_BYTES: usize = 2 * 1024 * 1024;

/// 允许被内联成 `data:` URI 的图片格式。
///
/// 刻意不含 `image/svg+xml`：SVG 里能塞 `<script>`。虽然现代浏览器在 `<img>`
/// 语境下不执行 SVG 脚本，但 webview 的行为不赌，白名单收死。
/// 这里是**精确匹配**而不是前缀匹配，顺带堵掉 Content-Type 里塞分号/逗号
/// 去改写 data URI 结构的可能。
const INLINE_IMAGE_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
];

/// 内嵌图片资源表：`cid` → (mime_type, 原始字节)。
///
/// 由 [`crate::mime::ParsedMessage::cid_map`] 构造，喂给 [`sanitize_body`]。
pub type CidMap<'a> = HashMap<&'a str, (&'a str, &'a [u8])>;

/// 不允许出现的标签。`rm_tags` 会连同内容一起去掉。
///
/// ammonia 的默认白名单本来就不含这些，显式列一遍是为了让读代码的人不用翻
/// 文档就知道边界在哪，也防止以后有人 `add_tags` 时误加回来。
const FORBIDDEN_TAGS: &[&str] = &[
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet",
    "form", "input", "button", "select", "option", "textarea", "fieldset", "legend",
    "link", "meta", "base", "title", "head", "html", "body", "svg", "math",
    "template", "noscript", "canvas", "audio", "video", "source", "track", "portal",
];

/// 内容要连带丢掉的标签（不能只删标签留下里面的脚本）。
const DROP_CONTENT_TAGS: &[&str] = &["script", "style"];

/// 净化结果。
#[derive(Debug, Clone)]
pub struct SanitizedBody {
    /// 可以安全注入 webview 的 HTML 片段。
    ///
    /// ⚠️ 前端仍应配合 CSP（`img-src` 收紧、script 禁 `unsafe-inline`）。
    /// 净化器是单点，CSP 是纵深。
    pub html: String,
    /// 被拦下的远程图片数量。前端用来显示「这封邮件包含 N 张远程图片」。
    pub remote_image_count: usize,
    /// 是否放行了远程图片（回显策略，便于前端判断按钮状态）。
    pub remote_allowed: bool,
}

/// 净化邮件正文 HTML，不带内嵌图片。等价于 `sanitize_body(raw, allow, &CidMap::new())`。
pub fn sanitize_html(raw: &str, allow_remote: bool) -> SanitizedBody {
    sanitize_body(raw, allow_remote, &CidMap::new())
}

/// 净化邮件正文 HTML，并把 `cid:` 引用内联成 `data:`。
///
/// * `allow_remote = false`（默认）：`<img src="http(s)://…">` 的 src 被摘掉，
///   图片不加载。`cid:` 和小的 `data:` 图片照常显示（它们不产生网络请求）。
/// * `allow_remote = true`：用户点了「显示图片」，放行。
///
/// cid → data 的改写**必须发生在 ammonia 管线内部**（`attribute_filter`）。
/// 事后拿净化结果做字符串替换，等于在安全边界外面又开一条能改 `src` 的路，
/// 那条路上没有白名单兜底。
pub fn sanitize_body(raw: &str, allow_remote: bool, cid: &CidMap<'_>) -> SanitizedBody {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_filter = Arc::clone(&counter);

    // attribute_filter 要 move，把 cid 表搬成自有数据。mime 只收白名单里的
    // 光栅图，见 INLINE_IMAGE_MIMES。
    let cid_owned: HashMap<String, (String, Vec<u8>)> = cid
        .iter()
        .filter_map(|(k, v)| {
            let (mime, bytes) = *v;
            if !INLINE_IMAGE_MIMES.contains(&mime) {
                return None;
            }
            Some(((*k).to_string(), (mime.to_string(), bytes.to_vec())))
        })
        .collect();

    let mut b = ammonia::Builder::new();

    // 显式收掉危险标签。默认白名单已经不含它们，列出来是文档作用。
    b.rm_tags(FORBIDDEN_TAGS.iter().copied());
    // `clean_content_tags` 收 HashSet（整套替换），`add_clean_content_tags`
    // 才收迭代器（追加）。我们要的是追加。
    b.add_clean_content_tags(DROP_CONTENT_TAGS.iter().copied());

    // style 属性去掉：CSS 里能藏 url() 外呼，而邮件排版交给阅读视图的样式表。
    //
    // ⚠️ 这一行和 `src-tauri/tauri.conf.json` 的 CSP 是**成对的**：那边的
    // `style-src` 只放行 `'self'`（没有 `'unsafe-inline'`），前提就是这里一直
    // 把 style 属性和 `<style>` 块摘掉。哪天要给邮件 HTML 放行内联样式，
    // 两边必须同时改，别只改一边。
    b.rm_generic_attributes(&["style"]);

    // 相对 URL 一律拒绝。邮件 HTML 里的相对链接没有合理语义（相对于什么？
    // 我们没有 base），放行只会变成盲猜。
    b.url_relative(ammonia::UrlRelative::Deny);

    // cid: 给内嵌图片用；data: 给小图用——但 data 见下面的 href 掐断。
    b.add_url_schemes(&["cid", "data"]);

    // 关键钩子：在这里拦远程图片，同时统计数量。
    b.attribute_filter(move |element, attribute, value| {
        let lower = value.to_ascii_lowercase();

        // ---- href 上的 data: 一律掐掉 --------------------------------
        // 加进 url_schemes 是为了 img，副作用是 <a href="data:text/html,…">
        // 也能过。点一下就导航执行，必须单独拦。
        if attribute == "href" && lower.starts_with("data:") {
            return None;
        }

        // ---- img src -------------------------------------------------
        if element == "img" && attribute == "src" {
            // cid: → data:。引不到就把 src 摘掉，别留个死链。
            if lower.starts_with("cid:") {
                let key = value[4..].trim();
                return match cid_owned.get(key) {
                    Some((mime, bytes)) => Some(Cow::Owned(format!(
                        "data:{mime};base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    ))),
                    None => None,
                };
            }

            let is_remote = lower.starts_with("http://") || lower.starts_with("https://");

            if is_remote {
                if !allow_remote {
                    counter_for_filter.fetch_add(1, Ordering::Relaxed);
                    return None; // 摘掉 src，img 不会发起任何请求
                }
                return Some(Cow::Borrowed(value));
            }

            // data: 图片限大小，防 base64 大图吃光内存
            if lower.starts_with("data:") && value.len() > MAX_DATA_URI_BYTES {
                return None;
            }

            // cid: / 小 data: / 其它 —— 交给 scheme 白名单
            return Some(Cow::Borrowed(value));
        }

        Some(Cow::Borrowed(value))
    });

    let html = b.clean(raw).to_string();
    SanitizedBody {
        html,
        remote_image_count: counter.load(Ordering::Relaxed),
        remote_allowed: allow_remote,
    }
}

// ================================================================= HTML → 文本
//
// `ammonia::clean_text` **不是**抽取文本，它是把输入当纯文本做 HTML 转义
// （实测输出 `&lt;p&gt;a&#47;p&gt;`）。要拿纯文本得自己走一遍。
//
// 这里不是安全边界（那由 `sanitize_html` 负责），写坏了最坏是预览难看，
// 所以手写一个够用的小抽取器比引依赖划算。

/// 把 HTML 片段降成纯文本，保留段落换行。
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let bytes = html.as_bytes();
    let mut i = 0;
    let mut skip_depth = 0usize; // <script>/<style> 内部深度

    while i < bytes.len() {
        // ---- 标签 ----------------------------------------------------
        if bytes[i] == b'<' {
            if let Some(end) = find_tag_end(bytes, i) {
                let tag = &html[i + 1..end];
                let name = tag_name(tag);

                if name == "script" || name == "style" {
                    if !tag.starts_with('/') {
                        skip_depth += 1;
                    } else if skip_depth > 0 {
                        skip_depth -= 1;
                    }
                } else if skip_depth == 0 {
                    if is_block_boundary(name, tag.trim_start().starts_with('/')) {
                        push_newline(&mut out);
                    } else if name == "br" || name == "hr" {
                        push_newline(&mut out);
                    }
                }
                i = end + 1;
                continue;
            }
            // 没找到闭合的 `<`，当普通字符
            out.push('<');
            i += 1;
            continue;
        }

        if skip_depth > 0 {
            i += 1;
            continue;
        }

        // ---- 实体 ----------------------------------------------------
        if bytes[i] == b'&' {
            if let Some((ch, len)) = decode_entity(&html[i..]) {
                out.push(ch);
                i += len;
                continue;
            }
        }

        // ---- 普通字符（按 UTF-8 边界推进，别把汉字劈开）--------------
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&html[i..i + ch_len]);
        i += ch_len;
    }

    finalize_lines(&out)
}

/// 从纯文本正文生成列表页那一行灰字预览。
pub fn build_preview(text: &str) -> String {
    const MAX: usize = 200;
    let flat: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // 按字符数截断，不按字节——中文按字节截会把一个汉字劈成两半
    let mut out = String::new();
    for (i, ch) in flat.chars().enumerate() {
        if i >= MAX {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

// ---------------------------------------------------------------- 内部工具

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1, // 非法字节，跳一个，别死循环
    }
}

/// 找 `<...>` 的结束位置（返回 `>` 的下标）。简单实现：跳过引号内的 `>`。
fn find_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        match quote {
            Some(q) => {
                if bytes[i] == q {
                    quote = None;
                }
            }
            None => match bytes[i] {
                b'"' | b'\'' => quote = Some(bytes[i]),
                b'>' => return Some(i),
                _ => {}
            },
        }
        i += 1;
    }
    None
}

/// 取标签名（小写）。`</p>` → `p`，`<br/>` → `br`。
fn tag_name(tag: &str) -> &str {
    let t = tag.trim_start_matches('/').trim_start();
    let end = t
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(t.len());
    // 不分配：返回原切片即可，比较时用小写不敏感的匹配
    &t[..end]
}

/// 这个标签是不是段落级边界（收尾时要换行）。
fn is_block_boundary(name: &str, is_closing: bool) -> bool {
    if !is_closing {
        return false;
    }
    matches!(
        name.to_ascii_lowercase().as_str(),
        "p" | "div" | "section" | "article" | "header" | "footer" | "main" | "aside"
        | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
        | "ul" | "ol" | "li" | "dl" | "dt" | "dd"
        | "table" | "thead" | "tbody" | "tfoot" | "tr" | "blockquote" | "pre" | "figure"
    )
}

fn push_newline(out: &mut String) {
    if !out.ends_with('\n') {
        out.push('\n');
    }
}

/// 解码一个 HTML 实体。返回 `(字符, 实体总长度)`，不是实体则返回 None。
fn decode_entity(s: &str) -> Option<(char, usize)> {
    let semi = s.find(';')?;
    // 实体不该跨行太长
    if semi > 12 {
        return None;
    }
    let body = &s[1..semi];
    let total = semi + 1;

    let ch = if let Some(num) = body.strip_prefix('#') {
        let code = if let Some(hex) = num.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            num.parse::<u32>().ok()?
        };
        char::from_u32(code)?
    } else {
        match body {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            "nbsp" => ' ',
            "hellip" => '…',
            "mdash" => '—',
            "ndash" => '–',
            "copy" => '©',
            "reg" => '®',
            "trade" => '™',
            "times" => '×',
            "middot" => '·',
            "bull" => '•',
            "ldquo" | "rdquo" | "lsquo" | "rsquo" => '"',
            _ => return None,
        }
    };
    Some((ch, total))
}

/// 去掉空行、去掉每行两端空白。
///
/// 契约是「可预测」而不是「好看」：`<p>a</p><p>b</p>`、`a<br><br>b`、
/// `a\n\n\nb` 都得到 `a\nb`。唯一的消费者是预览（阅读视图走 HTML，
/// 纯文本邮件用 text/plain 原文），排版留给渲染层决定。
fn finalize_lines(s: &str) -> String {
    s.split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_script_and_event_handlers() {
        let raw = r#"
            <p onclick="alert(1)">你好</p>
            <script>fetch('http://evil')</script>
            <img src="x" onerror="alert(2)">
            <a href="javascript:alert(3)">点我</a>
        "#;
        let out = sanitize_html(raw, true);
        assert!(out.html.contains("你好"));
        assert!(!out.html.contains("script"), "script 标签必须消失: {}", out.html);
        assert!(!out.html.contains("onclick"), "事件属性必须消失: {}", out.html);
        assert!(!out.html.contains("onerror"), "事件属性必须消失: {}", out.html);
        assert!(!out.html.contains("javascript:"), "危险 scheme 必须消失: {}", out.html);
    }

    #[test]
    fn blocks_remote_images_by_default_and_counts_them() {
        let raw = r#"
            <img src="https://tracker.example.com/pixel.gif">
            <img src="http://cdn.example.com/a.png">
        "#;
        let out = sanitize_html(raw, false);
        assert_eq!(out.remote_image_count, 2, "两个远程图片都要被拦下");
        assert!(!out.html.contains("tracker.example.com"), "远程 src 必须被摘掉: {}", out.html);
        assert!(!out.html.contains("cdn.example.com"), "远程 src 必须被摘掉: {}", out.html);
    }

    #[test]
    fn unresolved_cid_reference_drops_the_src() {
        // 引不到资源的 cid: 是死链，留着只渲染出裂图
        let out = sanitize_html(r#"<img src="cid:missing">"#, false);
        assert!(!out.html.contains("cid:missing"), "引不到的 cid: 必须摘掉: {}", out.html);
    }

    #[test]
    fn resolved_cid_is_inlined_as_data_uri() {
        let mut cid: CidMap = HashMap::new();
        cid.insert("logo", ("image/png", &b"\x89PNG\r\n\x1a\nfake"[..]));

        let out = sanitize_body(r#"<p>hi <img src="cid:logo"></p>"#, false, &cid);
        assert!(
            out.html.contains("data:image/png;base64,"),
            "cid: 要内联成 data: URI: {}",
            out.html
        );
        assert!(!out.html.contains("cid:logo"), "内联后不该再留 cid: {}", out.html);
    }

    #[test]
    fn cid_inlining_refuses_svg() {
        // image/svg+xml 不在白名单里，宁可显示裂图也不内联
        let mut cid: CidMap = HashMap::new();
        cid.insert("x", ("image/svg+xml", b"<svg onload=alert(1)></svg>".as_slice()));

        let out = sanitize_body(r#"<img src="cid:x">"#, false, &cid);
        assert!(!out.html.contains("base64"), "SVG 不许内联: {}", out.html);
    }

    #[test]
    fn allow_remote_passes_images_through() {
        let raw = r#"<img src="https://cdn.example.com/a.png">"#;
        let out = sanitize_html(raw, true);
        assert!(out.html.contains("cdn.example.com"), "放行时 src 要保留: {}", out.html);
        assert_eq!(out.remote_image_count, 0, "放行时不该计数");
        assert!(out.remote_allowed);
    }

    #[test]
    fn keeps_normal_links_even_when_images_blocked() {
        // 这是不能用「从 url_schemes 里删掉 http」的原因：那样链接也会被一起剥掉。
        let raw = r#"<a href="https://example.com/x">官网</a><img src="https://t.com/p.gif">"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains("https://example.com/x"), "链接必须保留: {}", out.html);
        assert!(!out.html.contains("t.com"), "但远程图片必须被拦: {}", out.html);
    }

    #[test]
    fn data_uri_on_href_is_blocked() {
        // 加 data 进 url_schemes 是为了 img，副作用是 <a href="data:text/html,…">
        // 也能过——点一下就执行。必须单独掐掉。
        let raw = r#"<a href="data:text/html,<script>alert(1)</script>">点我</a>"#;
        let out = sanitize_html(raw, true);
        assert!(!out.html.contains("data:text/html"), "href 上的 data: 必须掐掉: {}", out.html);
        assert!(!out.html.contains("alert"), "脚本内容也该没了: {}", out.html);
    }

    #[test]
    fn data_uri_on_img_is_allowed_but_bounded() {
        let small = "data:image/gif;base64,R0lGODlhAQABAAAAACw=".to_string();
        let raw = format!("<img src=\"{small}\">");
        let out = sanitize_html(&raw, false);
        assert!(out.html.contains("data:image/gif"), "小 data: 图片要保留: {}", out.html);

        let big = "data:image/png;base64,".to_string() + &"A".repeat(MAX_DATA_URI_BYTES + 10);
        let raw = format!("<img src=\"{big}\">");
        let out = sanitize_html(&raw, false);
        assert!(!out.html.contains("AAAA"), "超大 data: 图片必须丢弃: {}", out.html);
    }

    #[test]
    fn keeps_layout_tags() {
        let raw = r#"
            <h2>标题</h2>
            <table><tr><td>格子</td></tr></table>
            <ul><li>项目</li></ul>
            <blockquote>引用</blockquote>
            <b>粗</b><i>斜</i>
        "#;
        let out = sanitize_html(raw, false);
        for t in ["<h2>", "<table>", "<td>", "<ul>", "<li>", "<blockquote>", "<b>", "<i>"] {
            assert!(out.html.contains(t), "排版标签不该被剥掉，缺 {t}: {}", out.html);
        }
    }

    #[test]
    fn relative_urls_are_dropped() {
        let raw = r#"<a href="/relative/path">x</a><img src="/img.png">"#;
        let out = sanitize_html(raw, true);
        assert!(!out.html.contains("/relative/path"), "相对链接没有合理语义，必须丢: {}", out.html);
    }

    #[test]
    fn style_attribute_is_stripped() {
        let raw = r#"<p style="background:url('http://evil.com/x')">text</p>"#;
        let out = sanitize_html(raw, false);
        assert!(!out.html.contains("evil.com"), "style 里的外呼必须消失: {}", out.html);
        assert!(!out.html.contains("style="), "style 属性必须消失: {}", out.html);
    }

    // ---------------------------------------------------------- html_to_text

    #[test]
    fn html_to_text_keeps_paragraphs() {
        assert_eq!(html_to_text("<p>a</p><p>b</p>"), "a\nb");
    }

    #[test]
    fn html_to_text_handles_br_and_nested() {
        assert_eq!(html_to_text("第一行<br>第二行"), "第一行\n第二行");
        assert_eq!(html_to_text("<div><p>x</p></div>"), "x");
    }

    #[test]
    fn html_to_text_drops_script_content() {
        assert_eq!(html_to_text("<p>a</p><script>var x = '<b>假的</b>';</script><p>b</p>"), "a\nb");
    }

    #[test]
    fn html_to_text_decodes_entities() {
        assert_eq!(html_to_text("a &amp; b &lt;c&gt; &#39;d&#39; &nbsp;e"), "a & b <c> 'd'  e");
        assert_eq!(html_to_text("&#x4e2d;&#25991;"), "中文");
    }

    #[test]
    fn html_to_text_is_utf8_safe() {
        // 按字节乱切会产生非法 UTF-8
        assert_eq!(html_to_text("<p>中文测试</p>"), "中文测试");
        assert_eq!(html_to_text("🙂 emoji"), "🙂 emoji");
    }

    #[test]
    fn html_to_text_collapses_blank_lines_and_trims() {
        assert_eq!(html_to_text("\n\n  <p>a</p>\n\n\n\n  <p>b   c</p>  \n\n"), "a\nb   c");
    }

    // ------------------------------------------------------------ build_preview

    #[test]
    fn preview_is_char_safe_and_bounded() {
        let s = "中".repeat(500);
        let p = build_preview(&s);
        assert!(p.chars().count() <= 201, "预览长度要有上限");
        assert!(p.ends_with('…'), "截断要有省略号");
        assert!(p.chars().all(|c| c == '中' || c == '…'), "不能出现替换字符");
    }

    #[test]
    fn preview_flattens_newlines() {
        assert_eq!(build_preview("a\n\n  b\tc"), "a b c");
    }
}
