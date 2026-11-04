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
//!
//! 内联样式（`style` 属性 + `<style>` 块）**放行但删减式清洗**（[`scrub_css`]）：
//! HTML 邮件的排版全在内联 CSS 里，全剥掉就只剩裸文字（对不齐主流客户端）。
//! 清洗是纯删除：`@import`/`expression(`/`position:fixed`/外呼 `url()` 一概
//! 掏掉，不引入任何字节。`<style>` 文本的清洗发生在 ammonia 输出后按
//! `</style>` 边界切段 —— 这是「不做事后修补」的唯一例外（那段只是文本、
//! 不是结构，且解析器保证段内不含 `</style>`），只删不加。与 `tauri.conf.json`
//! 的 CSP 成对：那边 `style-src` 需含 `'unsafe-inline'`（script 仍然没有）。

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
    "script", "iframe", "frame", "frameset", "object", "embed", "applet",
    "form", "input", "button", "select", "option", "textarea", "fieldset", "legend",
    "link", "meta", "base", "title", "head", "html", "body", "svg", "math",
    "template", "noscript", "canvas", "audio", "video", "source", "track", "portal",
];

/// 内容要连带丢掉的标签（不能只删标签留下里面的脚本）。
/// `style` 不在此列：邮件排版靠它，内容经 [`scrub_css`] 删减式清洗。
const DROP_CONTENT_TAGS: &[&str] = &["script"];

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
    // ⚠️ 用**整套替换**而不是 add_：ammonia 默认 clean_content_tags 里就有
    // `style`（默认连内容丢），我们要保留 style 内容，必须清空重设。
    b.clean_content_tags(DROP_CONTENT_TAGS.iter().copied().collect::<std::collections::HashSet<_>>());

    // `<style>` 放行（邮件排版靠它）。默认白名单不含，得显式加。
    b.add_tags(&["style", "center", "font"]);

    // HTML 邮件的排版属性（老式 table 布局全靠它们）。无脚本面：
    // 数值/枚举/颜色属性，浏览器只当排版用。
    b.add_tag_attributes("table", ["width", "height", "cellpadding", "cellspacing", "border", "bgcolor", "align"]);
    b.add_tag_attributes("td", ["valign", "bgcolor", "width", "height", "nowrap", "align"]);
    b.add_tag_attributes("th", ["valign", "bgcolor", "width", "height", "nowrap", "align"]);
    b.add_tag_attributes("tr", ["valign", "bgcolor", "align"]);
    b.add_tag_attributes("img", ["border", "hspace", "vspace", "align"]);
    b.add_tag_attributes("font", ["color", "face", "size"]);
    b.add_tag_attributes("p", ["align"]);
    b.add_tag_attributes("div", ["align"]);
    b.add_tag_attributes("span", ["align"]);
    for h in ["h1", "h2", "h3", "h4", "h5", "h6"] {
        b.add_tag_attributes(h, ["align"]);
    }
    b.add_tag_attributes("center", ["width"]);

    // style 属性**放行但清洗**：HTML 邮件的排版全在内联 CSS 里。清洗是
    // 删减式（scrub_css）：@import / expression( / position:fixed / 外呼 url()
    // 一概掏掉。⚠️ 和 tauri.conf.json 的 CSP 成对：style-src 需含
    // 'unsafe-inline'，否则内联样式画不出来。

    // ammonia 4 里 style 不在默认 generic_attributes（只有 lang/title）——
    // 显式放行，值的清洗交给下面的 attribute_filter。
    b.generic_attributes(["lang", "title", "style", "class"].into_iter().collect());

    // 相对 URL 一律拒绝。邮件 HTML 里的相对链接没有合理语义（相对于什么？
    // 我们没有 base），放行只会变成盲猜。
    b.url_relative(ammonia::UrlRelative::Deny);

    // cid: 给内嵌图片用；data: 给小图用——但 data 见下面的 href 掐断。
    b.add_url_schemes(&["cid", "data"]);

    // 关键钩子：在这里拦远程图片，同时统计数量。
    b.attribute_filter(move |element, attribute, value| {
        let lower = value.to_ascii_lowercase();

        // ---- style 属性：删减式 CSS 清洗 ------------------------------
        if attribute == "style" {
            return Some(Cow::Owned(scrub_css(
                value,
                allow_remote,
                &counter_for_filter,
            )));
        }

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
    // `<style>` 文本清洗（删减式）—— 见模块头「唯一例外」。
    let html = scrub_style_elements(&html, allow_remote, &counter);
    SanitizedBody {
        html,
        remote_image_count: counter.load(Ordering::Relaxed),
        remote_allowed: allow_remote,
    }
}

// ================================================================= CSS 清洗

/// CSS **删减式**清洗：只删不加，不引入任何字节。用于 `style` 属性值与
/// `<style>` 块文本。
///
/// 拦：`@import`（外呼 CSS 文件）、`expression(`/`-moz-binding`/`behavior:`
/// （老 IE/FF 代码执行面）、`position: fixed|sticky`（防盖应用界面的钓鱼层；
/// 另有 `.mail-body` 的合成层 containment 双保险）、`url()` 外呼地址
/// （同 `<img>` 远程图策略：默认掏掉并计数；`data:` 不发网络请求，保留）。
///
/// 已知残余：CSS 转义（如 `u\\72 l(`）能绕过关键字扫描 —— 绕过的代价只是
/// 一次后台请求（追踪像素级别），不涉代码执行；`position` 的绕过由
/// `.mail-body` 的 containment 兜底。主流客户端同级。
fn scrub_css(css: &str, allow_remote: bool, remote_counter: &AtomicUsize) -> String {
    // 1) 去注释：注释里藏关键字是绕过手法
    let mut s = String::with_capacity(css.len());
    let bytes = css.as_bytes();
    let (mut i, mut seg) = (0usize, 0usize);
    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'*' {
            s.push_str(&css[seg..i]);
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            i = (j + 2).min(bytes.len());
            seg = i;
        } else {
            i += 1;
        }
    }
    s.push_str(&css[seg..]);

    // 2) 关键字中和 + url() 分类（单趟扫描）
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if ascii_starts_with_ci(rest, b"@import") {
            out.push_str("@x-import"); // 未知 at-rule，浏览器丢弃
            i += 7;
        } else if ascii_starts_with_ci(rest, b"expression(") {
            out.push_str("x-expression(");
            i += 11;
        } else if ascii_starts_with_ci(rest, b"-moz-binding") {
            out.push_str("-x-moz-binding");
            i += 11;
        } else if ascii_starts_with_ci(rest, b"behavior:") {
            out.push_str("x-behavior:");
            i += 9;
        } else if ascii_starts_with_ci(rest, b"position") {
            // position: fixed|sticky → static；relative/absolute 等照留
            let after = &bytes[i + 8..];
            let mut k = 0;
            while k < after.len() && (after[k] as char).is_ascii_whitespace() {
                k += 1;
            }
            if k < after.len() && after[k] == b':' {
                k += 1;
                while k < after.len() && (after[k] as char).is_ascii_whitespace() {
                    k += 1;
                }
                let vs = k;
                while k < after.len() && (after[k].is_ascii_alphabetic() || after[k] == b'-') {
                    k += 1;
                }
                let word = &after[vs..k];
                if ascii_starts_with_ci(word, b"fixed") || ascii_starts_with_ci(word, b"sticky") {
                    out.push_str("position: static");
                    i += 8 + k;
                    continue;
                }
            }
            out.push_str("position");
            i += 8;
        } else if ascii_starts_with_ci(rest, b"url(") {
            let mut k = i + 4;
            while k < bytes.len() && (bytes[k] as char).is_ascii_whitespace() {
                k += 1;
            }
            let quote = if k < bytes.len() && (bytes[k] == b'\'' || bytes[k] == b'"') {
                let q = bytes[k];
                k += 1;
                Some(q)
            } else {
                None
            };
            let vstart = k;
            while k < bytes.len() {
                match quote {
                    Some(q) if bytes[k] == q => break,
                    None if bytes[k] == b')' || (bytes[k] as char).is_ascii_whitespace() => break,
                    _ => k += 1,
                }
            }
            let value = &s[vstart..k];
            let lower = value.to_ascii_lowercase();
            if lower.starts_with("data:") {
                out.push_str(&s[i..k]);
            } else if lower.starts_with("http://") || lower.starts_with("https://") {
                if allow_remote {
                    out.push_str(&s[i..k]);
                } else {
                    remote_counter.fetch_add(1, Ordering::Relaxed);
                    out.push_str("none");
                    while k < bytes.len() && bytes[k] != b')' {
                        k += 1;
                    }
                }
            } else {
                out.push_str("none");
                while k < bytes.len() && bytes[k] != b')' {
                    k += 1;
                }
            }
            i = k; // 指向右括号/结束，下轮把右括号原样带上
        } else {
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&s[i..i + ch_len]);
            i += ch_len;
        }
    }
    out
}

fn ascii_starts_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

/// 给样式表加**作用域前缀**：所有选择器套进 `.mail-body` 下。
///
/// `<style>` 是注入主文档的，邮件里的 `body`/`*`/`a`/`h1` 等选择器会匹配到
/// **应用界面的元素**（实测：整页颜色/字体被改、工具条按钮变空白）。
/// 前缀化后邮件样式只在正文容器内生效。`body`/`html`/`:root` 映射为
/// `.mail-body` 本体（它们描述的就是「邮件页面」）。
///
/// 这是对文本的**结构保持改写**（只在选择器位置加前缀，不动声明），
/// 与 [`scrub_css`] 同属清洗步骤的一部分。
fn scope_stylesheet(css: &str) -> String {
    let mut out = String::with_capacity(css.len() + 64);
    scope_block(css, &mut out, true);
    out
}

/// 递归处理一层规则块。`top` = 顶层（选择器要前缀化）。
fn scope_block(css: &str, out: &mut String, top: bool) {
    let bytes = css.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // 跳过空白原样带走
        let prelude_start = i;
        // 读 prelude（到 `{` 或 `;` 或尾）——跳过字符串/括号里的内容
        let mut depth = 0usize;
        let mut in_str: Option<u8> = None;
        while i < bytes.len() {
            let c = bytes[i];
            if let Some(q) = in_str {
                if c == b'\\' { i += 2; continue; }
                if c == q { in_str = None; }
            } else if c == b'\'' || c == b'"' {
                in_str = Some(c);
            } else if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth = depth.saturating_sub(1);
            } else if depth == 0 && (c == b'{' || c == b';') {
                break;
            }
            i += 1;
        }
        if i >= bytes.len() {
            // 尾部残留（不成规则）原样
            out.push_str(&css[prelude_start..]);
            return;
        }
        let prelude = &css[prelude_start..i];
        if bytes[i] == b';' {
            // @charset/@import 之类语句（@import 已被 scrub 中和）
            out.push_str(prelude);
            out.push(';');
            i += 1;
            continue;
        }
        // 到 `{`：找配对 `}`（递归计数 + 字符串）
        let body_start = i + 1;
        let mut j = body_start;
        let mut depth = 1usize;
        let mut in_str: Option<u8> = None;
        while j < bytes.len() && depth > 0 {
            let c = bytes[j];
            if let Some(q) = in_str {
                if c == b'\\' { j += 2; continue; }
                if c == q { in_str = None; }
            } else if c == b'\'' || c == b'"' {
                in_str = Some(c);
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
            }
            j += 1;
        }
        let body_end = j.saturating_sub(1).max(body_start); // 不含 `}`
        let body = &css[body_start..body_end];
        let prelude_trim = prelude.trim();
        let lower = prelude_trim.to_ascii_lowercase();
        if lower.starts_with("@media") || lower.starts_with("@supports") {
            // 嵌套块：头原样，里面的规则继续前缀化
            out.push_str(prelude);
            out.push('{');
            scope_block(body, out, true);
            out.push('}');
        } else if lower.starts_with("@") {
            // @keyframes / @font-face / @page 等：整体原样（内部不是选择器）
            out.push_str(prelude);
            out.push('{');
            out.push_str(body);
            out.push('}');
        } else if top {
            // 普通规则：选择器列表逐个套 .mail-body
            out.push_str(&scope_selectors(prelude));
            out.push('{');
            out.push_str(body);
            out.push('}');
        } else {
            out.push_str(prelude);
            out.push('{');
            out.push_str(body);
            out.push('}');
        }
        i = body_end + 1;
    }
}

/// 选择器列表（逗号分隔）→ 每个套进 `.mail-body`。
fn scope_selectors(list: &str) -> String {
    list.split(',')
        .map(|sel| {
            let t = sel.trim();
            if t.is_empty() {
                return String::new();
            }
            let low = t.to_ascii_lowercase();
            // body/html/:root 描述的就是「邮件页面」→ 映射到容器本体
            if low == "body" || low == "html" || low == ":root" || low == "html body" {
                return ".mail-body".to_string();
            }
            if let Some(rest) = t.strip_prefix("body ") {
                return format!(".mail-body {rest}");
            }
            format!(".mail-body {t}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// 净化产物里 `<style>` 元素的文本过 [`scrub_css`]（删减式）。
///
/// 这是模块「不做事后修补」的**唯一例外**：只对 `<style>…</style>` 段内的
/// 文本做删除式过滤，不碰任何标签/属性；且 ammonia 输出是解析器序列化的，
/// 段内文本不可能含 `</style>`（解析器遇到就闭合了），字符串定位安全。
fn scrub_style_elements(html: &str, allow_remote: bool, counter: &AtomicUsize) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open) = rest.find("<style") {
        let Some(tag_end_rel) = rest[open..].find('>') else {
            out.push_str(rest);
            return out;
        };
        let tag_end = open + tag_end_rel + 1;
        out.push_str(&rest[..tag_end]);
        if let Some(close) = rest[tag_end..].find("</style>") {
            let body = &rest[tag_end..tag_end + close];
            // 先删减清洗，再**作用域化**：邮件 CSS 的 body/a/h1 等选择器会匹配到
            // 应用界面（同一份 DOM），实测把工具条/标题颜色全改了。
            out.push_str(&scope_stylesheet(&scrub_css(body, allow_remote, counter)));
            out.push_str("</style>");
            rest = &rest[tag_end + close + "</style>".len()..];
        } else {
            out.push_str(&rest[tag_end..]);
            return out;
        }
    }
    out.push_str(rest);
    out
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
    fn keeps_inline_style_but_scrubs_dangerous_bits() {
        let raw = r#"<div style="color:red; position:fixed; background:url(https://t.com/x.png); margin:4px">x</div>"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains("margin"), "无害声明要留: {}", out.html);
        assert!(out.html.contains("color:red"), "无害声明要留: {}", out.html);
        assert!(!out.html.contains("position:fixed"), "fixed 必须中和: {}", out.html);
        assert!(!out.html.contains("t.com"), "外呼 url() 必须掏掉: {}", out.html);
        assert_eq!(out.remote_image_count, 1, "url() 外呼也要计数");
    }

    #[test]
    fn style_block_survives_with_dangerous_bits_scrubbed() {
        let raw = r#"<style>@import "http://evil.com/x.css"; .a{color:blue;position:STICKY;behavior:url(#x)}</style><p>x</p>"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains("<style"), "style 块要留: {}", out.html);
        assert!(out.html.contains("color:blue"), "无害规则要留: {}", out.html);
        assert!(out.html.contains("@x-import"), "@import 必须中和: {}", out.html);
        assert!(!out.html.contains("TICKY") && !out.html.contains("ticky"), "sticky 必须中和: {}", out.html);
        assert!(!out.html.contains("behavior:url"), "behavior 必须中和: {}", out.html);
    }

    #[test]
    fn css_comment_cannot_hide_keywords() {
        let raw = r#"<div style="/* position:fixed */ color:green">x</div>"#;
        let out = sanitize_html(raw, false);
        // 注释整个删掉；即便绕过，留下的也只是文本
        assert!(!out.html.contains("position:fixed"), "注释里的也要处理: {}", out.html);
    }

    #[test]
    fn remote_url_kept_when_images_allowed() {
        let raw = r#"<div style="background:url(https://cdn.example.com/bg.png)">x</div>"#;
        let out = sanitize_html(raw, true);
        assert!(out.html.contains("cdn.example.com"), "放行时 url() 要留: {}", out.html);
        let out2 = sanitize_html(raw, false);
        assert!(!out2.html.contains("cdn.example.com"), "拦截时 url() 要掏: {}", out2.html);
    }

    #[test]
    fn css_data_url_survives_scrub() {
        let raw = r#"<div style="background:url(data:image/gif;base64,R0lGOD)">x</div>"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains("data:image/gif"), "data: 不发网络，保留: {}", out.html);
    }

    #[test]
    fn style_block_selectors_are_scoped_to_mail_body() {
        // 邮件样式绝不能泄漏到应用界面（实测会把工具条/标题颜色全改掉）
        let raw = r#"<style>*{box-sizing:border-box}body{margin:0;color:red}a{color:#fff}h1{color:#eee}</style><p>x</p>"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains(".mail-body *{"), "选择器要作用域化: {}", out.html);
        assert!(out.html.contains(".mail-body{"), "body 要映射到容器: {}", out.html);
        assert!(out.html.contains(".mail-body a{"), "a 要作用域化: {}", out.html);
        assert!(!out.html.contains("}a{") && !out.html.contains(">a{"), "裸 a 选择器会泄漏: {}", out.html);
    }

    #[test]
    fn scoped_media_query_rules() {
        let raw = r#"<style>@media (max-width:600px){ body{margin:0} .x{color:green} }</style><p>x</p>"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains("@media (max-width:600px)"), "@media 头要留: {}", out.html);
        assert!(out.html.contains(".mail-body{"), "嵌套 body 也要映射: {}", out.html);
        assert!(out.html.contains(".mail-body .x{"), "嵌套选择器要作用域化: {}", out.html);
    }

    #[test]
    fn keyframes_left_alone() {
        let raw = r#"<style>@keyframes spin { from { transform: rotate(0) } to { transform: rotate(360deg) } }</style><p>x</p>"#;
        let out = sanitize_html(raw, false);
        assert!(out.html.contains("@keyframes spin"), "@keyframes 不动: {}", out.html);
        assert!(!out.html.contains(".mail-body from"), "keyframe 选择器不能被前缀: {}", out.html);
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
    fn style_attribute_is_scrubbed_not_stripped() {
        // 行为变了（对齐主流客户端）：style 属性**保留**（邮件排版靠它），
        // 但外呼 url() 掏掉、危险声明中和 —— 删减式清洗。
        let raw = r#"<p style="background:url('http://evil.com/x'); color:red">text</p>"#;
        let out = sanitize_html(raw, false);
        assert!(!out.html.contains("evil.com"), "style 里的外呼必须消失: {}", out.html);
        assert!(out.html.contains("style="), "无害 style 该保留: {}", out.html);
        assert!(out.html.contains("color:red"), "无害声明该保留: {}", out.html);
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
