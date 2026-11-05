// 撰写窗口
//
// 一个浮层盖在三栏界面上，不是第四栏：写信是「打断当前阅读、写完回来」的动作，
// 和「读信」并列会让人分不清现在在哪一屏。
//
// 没有框架、没有构建步骤，和 app.js 一个路子。
//
// ────────────────────────────────────────────────────────────────────────
// ## 这里是全项目第二个可以用 innerHTML 的地方
//
// 编辑区是 `contenteditable`，正文进进出出都是 HTML。**这些 HTML 是用户自己
// 写的，不是别人发来的**：
//
//   * 打字打出来的，由 `document.execCommand` 生成；
//   * 从草稿读回来的，是上一次自己写进去的。
//
// 净化（`core::sanitize`）是给「别人发来的 HTML」用的，套在这里会把用户自己的
// 格式吃掉。**但任何往编辑区塞外来 HTML 的功能（回复引用、邮件模板）都必须先
// 过一遍净化器** —— 那是这条口子的边界，不是可以往后推的事。
//
// ────────────────────────────────────────────────────────────────────────
// ## 为什么格式化用过时的表现层标签
//
// 工具条的粗体、字号、颜色都走 `document.execCommand`，并且显式关掉
// `styleWithCSS`。于是生成的是 `<b>` / `<font color=…>` / `<div align=…>`，
// **不是** `style="…"`。
//
// 这不是偷懒。CSP 的 `style-src` 只有 `'self'`（见 app.css 顶部的约定），
// 内联 style 会被浏览器拒掉 —— 用户点了「红色」，字却不红，是最难查的那种 bug。
// 要放开就得把 `style-src` 加上 `'unsafe-inline'`，而阅读页渲染的是**陌生人的**
// HTML，那个口子不能开。
//
// 所以这里选了过时的标签：它们不走 style，不受 CSP 管，而且每个邮件客户端都
// 还认（`<font>` 至今是富文本邮件的通用语）。代价是生成的 HTML 不好看，
// 以及 W3C 早就把它们标成 deprecated 了 —— 这个代价比放开 CSP 小得多。
//
// 想换成 CSS 的话，得先给撰写窗口单独一个 iframe + 单独的 CSP，别动阅读页。

import { node, clear } from "./dom.js";

const invoke = globalThis.__TAURI__?.core?.invoke;

// 自动保存的停顿。用户打字打到一半不该每敲一个字就写一次库。
const AUTOSAVE_MS = 1200;

// ---------------------------------------------------------------- 回复 / 转发的引用
//
// 安全红线（见文件顶部）：**外源 HTML 绝不进编辑区**。引用一律拿
// `body_text`（纯文本）用 `textContent` 拼到 DOM 上，绝不碰 `body_html`。
// 富文本正文（只给了 `body_html`）就不引用正文，只留一行说明。

/** `Re:` / `回复:` 前缀；已经有了就别再叠一层。按设置选中/英。 */
function reSubject(subj) {
  const s = subj || "";
  if (/^re:|^回复[:：]/i.test(s)) return s;
  const p = globalThis.__mailwaySettings?.reply_prefix === "cn" ? "回复: " : "Re: ";
  return `${p}${s}`.trim();
}

/** `Fwd:` / `转发:` 前缀。 */
function fwdSubject(subj) {
  const s = subj || "";
  if (/^fwd?:|^转发[:：]/i.test(s)) return s;
  const p = globalThis.__mailwaySettings?.reply_prefix === "cn" ? "转发: " : "Fwd: ";
  return `${p}${s}`.trim();
}

/** 按地址去重（大小写不敏感）—— 收件人堆里同一个人别出现两次。 */
function dedupeMailboxes(list) {
  const seen = new Set();
  const out = [];
  for (const m of list ?? []) {
    const key = (m.address || "").trim().toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  return out;
}

function mailboxListText(list) {
  if (!list || list.length === 0) return "";
  return list.map((m) => (m.display ? `${m.display} <${m.address}>` : m.address)).join("、");
}

function quoteDate(iso) {
  if (!iso) return "（无日期）";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(iso));
}

/**
 * 拼引用块。**只吃 `body_text`**（纯文本），逐行 `textContent` 落到 DOM ——
 * 外源 HTML 一个字节都不进编辑区（安全红线，见文件顶部）。
 */
function buildQuote(mode, source) {
  const s = source.summary;
  const bq = document.createElement("blockquote");
  bq.className = "quote";
  const push = (t, cls = "quote-line") => {
    const d = document.createElement("div");
    d.className = cls;
    d.textContent = t;
    bq.append(d);
  };

  if (mode === "forward") {
    push("---------- 转发的邮件 ----------", "quote-head");
    push(`发件人：${mailboxListText(s.from)}`);
    push(`日  期：${quoteDate(s.date)}`);
    push(`主  题：${s.subject || "（无主题）"}`);
    push(`收件人：${mailboxListText(s.to)}`);
    push("");
  } else {
    push(`在 ${quoteDate(s.date)}，${mailboxListText(s.from)} 写道：`, "quote-head");
  }

  const text = source.body_text;
  if (text && text.trim()) {
    const prefix = mode === "forward" ? "" : "> ";
    for (const ln of text.replace(/\r\n/g, "\n").split("\n")) {
      push(ln ? prefix + ln : prefix.trimEnd());
    }
  } else if (source.body_html) {
    push("（这封邮件的正文是富文本，回复时未引用。）", "quote-note");
  }
  return bq;
}

// ================================================================= 打开

/**
 * 打开撰写窗口。
 *
 * @param {object} opts
 * @param {object} opts.account  发件账号（`list_accounts` 的形状）
 * @param {number} [opts.draftId] 要继续改的草稿；不给就是新写一封
 * @param {string} [opts.replyMode] `reply` | `replyAll` | `forward` —— 回复/转发预填
 * @param {object} [opts.source]  被回复/转发的那封信（`open_message` 的完整形状）
 */
export function openCompose({
  account,
  draftId = null,
  replyMode = null,
  source = null,
  prefillTo = null,
} = {}) {
  closeCompose();
  const c = buildCompose(account);
  document.getElementById("app").append(c.root);
  if (replyMode && source) {
    c.startReply(replyMode, source);
  } else if (draftId === null) {
    c.startNew(prefillTo);
  } else {
    c.loadDraft(draftId);
  }
  return c;
}

let current = null;

export function closeCompose() {
  if (!current) return;
  current.flushSave();
  current.root.remove();
  current = null;
}

// ================================================================= 组装

function buildCompose(initialAccount) {
  // 发件人可切换（顶栏下拉）：`send` 用它的 id，签名跟着换
  let account = initialAccount;
  const state = {
    draftId: null,
    // 自动保存的版本号，单调递增。旧的保存不许盖掉新的，语义见
    // `core/src/store.rs` 的 `upsert_draft`。
    rev: 0,
    attachments: [],
    saveTimer: null,
    /// 有改动还没存
    dirty: false,
    /// 这封草稿刚被删了。删完再关窗口时那一下自动保存必须闭嘴
    removed: false,
  };

  // ---- 收件人 ---------------------------------------------------------
  const to = recipientField({ label: "收件人", placeholder: "回车或逗号分隔", onChange: markDirty });
  const cc = recipientField({ label: "抄送", placeholder: "可留空", onChange: markDirty });
  const bcc = recipientField({ label: "密送", placeholder: "收件人看不到", onChange: markDirty });

  // 抄送/密送默认收着（网易默认只有收件人/主题两行）
  const ccToggle = node("button", {
    class: "field-toggle", type: "button", text: "抄送",
    "aria-pressed": "false",
    onclick: () => {
      cc.el.hidden = !cc.el.hidden;
      ccToggle.setAttribute("aria-pressed", String(!cc.el.hidden));
      if (!cc.el.hidden) cc.focus();
    },
  });
  const bccToggle = node("button", {
    class: "field-toggle", type: "button", text: "密送",
    "aria-pressed": "false",
    onclick: () => {
      bcc.el.hidden = !bcc.el.hidden;
      bccToggle.setAttribute("aria-pressed", String(!bcc.el.hidden));
      if (!bcc.el.hidden) bcc.focus();
    },
  });
  cc.el.hidden = true;
  bcc.el.hidden = true;

  // ---- 主题 / 正文 ----------------------------------------------------
  const subject = node("input", {
    class: "compose-subject",
    type: "text",
    placeholder: "主题",
    "aria-label": "主题",
    oninput: markDirty,
  });
  const subjectRow = node("div", { class: "compose-field is-subject" },
    node("label", { class: "field-label", text: "主题" }),
    subject,
    node("div", { class: "subject-chips", role: "group", "aria-label": "常用主题" },
      ...["会议邀请", "周报", "请假", "通知"].map((t) =>
        node("button", {
          class: "subject-chip", type: "button", text: t,
          onclick: () => {
            subject.value = t;
            markDirty();
            subject.focus();
          },
        })),
    ),
  );

  // 内联 HTML 只从这里进出，理由见文件顶部
  const editor = node("div", {
    class: "compose-editor",
    contenteditable: "true",
    role: "textbox",
    "aria-multiline": "true",
    "aria-label": "正文",
    oninput: markDirty,
  });

  // ---- 附件 / 模板（按钮进工具条第一组，对齐网易的「添加附件 ▾ 插入 ▾」）--
  const attBox = node("div", { class: "compose-attachments" });
  const filePicker = node("input", { type: "file", multiple: "multiple", hidden: "hidden" });
  filePicker.addEventListener("change", async () => {
    for (const file of filePicker.files ?? []) await addAttachment(file);
    filePicker.value = "";
  });
  // 模板下拉（M6）：插入常用正文 / 管理模板。
  const tplMenu = node("div", { class: "more-menu", hidden: true, role: "menu" });
  const attachBtn = node("button", {
    class: "tool is-strong", type: "button", text: "📎 添加附件",
    title: "添加附件", "aria-label": "添加附件",
    onmousedown: (e) => e.preventDefault(),
    onclick: () => filePicker.click(),
  });
  const tools = buildTools(editor, markDirty, { attachBtn, tplMenu });

  // ---- 签名 ----------------------------------------------------------
  // 签名是**账号**设置，不是这一封的正文（拼信时才接在正文后面）。
  // 放在撰写窗口里改，是因为用户想起来要改签名通常就是在写信的时候。
  const sig = node("textarea", {
    class: "compose-signature",
    rows: "3",
    placeholder: "发信时拼在正文最后",
    "aria-label": "签名",
    onblur: saveSignature,
  });
  // 签名名片（对齐网易：正文底部常驻 头像+名字+邮箱+签名）。点卡片就地编辑。
  const sigAvatar = node("span", { class: "sig-avatar", "aria-hidden": "true", text: "?" });
  const sigName = node("strong", { class: "sig-name", text: "" });
  const sigMail = node("span", { class: "sig-mail", text: "" });
  const sigText = node("div", { class: "sig-text", text: "" });
  const sigLines = node("div", { class: "sig-lines" }, sigName, sigMail, sigText);
  const sigCard = node("div", {
    class: "compose-sigcard", role: "button", tabindex: "0",
    title: "点击编辑签名",
    onclick: enterSigEdit,
    onkeydown: (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        enterSigEdit();
      }
    },
  }, sigAvatar, sigLines);
  function renderSigCard() {
    const a = account;
    sigAvatar.textContent = ((a && (a.name || a.email)) || "?").trim().charAt(0).toUpperCase();
    sigName.textContent = (a && a.name) || "";
    sigMail.textContent = (a && a.email) || "";
    sigText.textContent = (sig.value || "").trim();
    sigName.hidden = !sigName.textContent;
  }
  function enterSigEdit() {
    clear(sigCard);
    sigCard.classList.add("is-editing");
    const doneBtn = node("button", {
      class: "btn btn-primary", type: "button", text: "完成",
      onclick: () => {
        saveSignature();
        exitSigEdit();
      },
    });
    sigCard.append(
      node("div", { class: "sig-lines" },
        node("p", { class: "muted", text: "签名拼在正文最后（发信时自动带上）" }),
        sig, doneBtn,
      ),
    );
    sig.focus();
  }
  function exitSigEdit() {
    sigCard.classList.remove("is-editing");
    clear(sigCard);
    sigCard.append(sigAvatar, sigLines);
    renderSigCard();
  }

  // ---- 顶栏（对齐网易邮箱大师：发送在左、发件人可切、自动保存时间戳在中，
  //      危险动作收右边）------------------------------------------------
  const status = node("span", { class: "compose-status", text: "" });
  const sendBtn = node("button", {
    class: "btn btn-primary compose-send", type: "button", text: "发送",
    title: "发送（Ctrl+Enter）", "aria-label": "发送这封信",
    onclick: () => send(),
  });
  const delBtn = node("button", {
    class: "btn compose-del", type: "button", text: "删除草稿",
    onclick: remove,
  });
  // ⋯ 更多：低频动作收起来，顶栏只留高频（对齐网易）
  const moreMenu = node("div", { class: "more-menu", hidden: true, role: "menu" },
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text: "立即保存草稿",
      onclick: () => { closeAllComposeMenus(); flushSave(); },
    }),
    node("button", {
      class: "more-item is-danger", type: "button", role: "menuitem", text: "删除草稿",
      onclick: () => { closeAllComposeMenus(); remove(); },
    }),
  );
  function toggleMoreMenu(btn) {
    const open = moreMenu.hidden;
    closeAllComposeMenus();
    if (!open) return;
    moreMenu.hidden = false;
    btn.setAttribute("aria-expanded", "true");
  }

  // 发件人显示：有名字用「名 <邮>」，没名字只显邮箱（别摆一对空尖括号）
  const fmtFrom = (a) => (a.name ? `${a.name} <${a.email}>` : a.email);

  // 发件人下拉：列出全部账号，点谁用谁发；签名跟着换
  const fromBtn = node("button", {
    class: "compose-from", type: "button",
    "aria-haspopup": "true", "aria-expanded": "false",
    title: "选择发件账号",
    onclick: (e) => { e.stopPropagation(); toggleFromMenu(e.currentTarget); },
  },
    node("span", { class: "from-text", text: account ? fmtFrom(account) : "选择发件账号" }),
    node("span", { class: "from-caret", "aria-hidden": "true", text: "▾" }),
  );
  const fromMenu = node("div", { class: "more-menu", hidden: true, role: "menu" });
  async function toggleFromMenu(btn) {
    const open = fromMenu.hidden;
    closeAllComposeMenus();
    if (!open) return;
    clear(fromMenu);
    let list = [];
    try {
      list = await invoke("list_accounts");
    } catch {
      list = [];
    }
    for (const a of list) {
      fromMenu.append(
        node("button", {
          class: "more-item", type: "button", role: "menuitem",
          text: `${a.name || ""} <${a.email}>`,
          onclick: () => {
            account = a;
            fromBtn.querySelector(".from-text").textContent = fmtFrom(a);
            if (sig.value !== (a.signature ?? "")) sig.value = a.signature ?? "";
            renderSigCard();
            fromMenu.hidden = true;
            btn.setAttribute("aria-expanded", "false");
            markDirty();
          },
        }),
      );
    }
    fromMenu.hidden = false;
    btn.setAttribute("aria-expanded", "true");
  }
  function closeAllComposeMenus() {
    fromMenu.hidden = true;
    fromBtn.setAttribute("aria-expanded", "false");
    moreMenu.hidden = true;
    tplMenu.hidden = true;
    document.querySelectorAll(".compose .more-wrap > button").forEach((b) => b.setAttribute("aria-expanded", "false"));
  }
  document.addEventListener("click", closeAllComposeMenus);

  const root = node("div", { class: "compose", role: "dialog", "aria-label": "写邮件" },
    node("header", { class: "compose-head" },
      sendBtn,
      node("div", { class: "more-wrap from-wrap" }, fromBtn, fromMenu),
      status,
      node("span", { class: "compose-head-gap", "aria-hidden": "true" }),
      node("div", { class: "more-wrap" },
        node("button", {
          class: "btn compose-del", type: "button", text: "⋯",
          title: "更多", "aria-label": "更多操作", "aria-haspopup": "true", "aria-expanded": "false",
          onclick: (e) => { e.stopPropagation(); toggleMoreMenu(e.currentTarget); },
        }),
        moreMenu,
      ),
      node("button", {
        class: "btn compose-close", type: "button", text: "×",
        title: "关闭（Esc）", "aria-label": "关闭写邮件",
        onclick: closeCompose,
      }),
    ),
    node("div", { class: "compose-fields" },
      node("div", { class: "compose-field" },
        node("label", { class: "field-label", text: "收件人" }),
        to.el.querySelector(".chips-wrap"),
        node("div", { class: "field-toggles" }, ccToggle, bccToggle),
      ),
      cc.el, bcc.el, subjectRow,
    ),
    tools.el,
    editor,
    sigCard,
    node("div", { class: "compose-atts" },
      attBox,
      filePicker,
    ),
  );

  // ================================================================ 行为

  function startNew(prefillTo) {
    state.draftId = null;
    state.rev = 0;
    state.attachments = [];
    state.dirty = false;
    state.removed = false;
    to.set(prefillTo || []);
    cc.set([]);
    bcc.set([]);
    subject.value = "";
    clear(editor);
    renderAtts();
    if (account) sig.value = account.signature ?? "";
    renderSigCard();
    to.focus();
    setStatus("");
  }

  /**
   * 回复 / 回复全部 / 转发的预填。引用内容由 `buildQuote` 纯文本拼出，
   * 外源 HTML 不进编辑区（安全红线）。
   *
   * 预填完不算「脏」：用户只是打开看看就关掉，不该凭空多出一封草稿。
   * 真改了才会 `markDirty`，那时才自动保存。
   */
  function startReply(mode, source) {
    state.draftId = null;
    state.rev = 0;
    state.attachments = [];
    state.dirty = false;
    state.removed = false;

    const s = source.summary;
    const self = (account?.email || "").trim().toLowerCase();
    const from = s.from ?? [];
    const replyTo = source.reply_to && source.reply_to.length > 0 ? source.reply_to : from;

    if (mode === "forward") {
      to.set([]);
      cc.set([]);
      subject.value = fwdSubject(s.subject);
    } else if (mode === "replyAll") {
      // 收件人 = 发件人 + 回复至；抄送 = 原收件人 + 原抄送，去掉自己。
      to.set(dedupeMailboxes([...from, ...replyTo]));
      cc.set(
        dedupeMailboxes([...(s.to ?? []), ...(source.cc ?? [])]).filter(
          (m) => (m.address || "").trim().toLowerCase() !== self,
        ),
      );
      subject.value = reSubject(s.subject);
    } else {
      to.set(dedupeMailboxes(replyTo));
      cc.set([]);
      subject.value = reSubject(s.subject);
    }

    clear(editor);
    editor.append(buildQuote(mode, source));
    if (account) sig.value = account.signature ?? "";
    renderSigCard();
    renderAtts();
    to.focus();
    setStatus("");
  }

  async function loadDraft(id) {
    setStatus("加载中…");
    try {
      const d = await invoke("get_draft", { draft_id: id });
      if (!d) {
        setStatus("这封草稿已经不在了，当新邮件写");
        return startNew();
      }
      state.draftId = d.id;
      state.rev = d.rev;
      state.removed = false;
      state.attachments = d.attachments.map((a) => ({ ...a, content_base64: null, dirty: false }));
      to.set(d.to);
      cc.set(d.cc);
      bcc.set(d.bcc);
      subject.value = d.subject;
      if (d.html !== null) {
        editor.innerHTML = d.html;
      } else {
        // 纯文本草稿：直接塞文本，不要包一层 <div>
        editor.textContent = d.text;
      }
      if (account) sig.value = account.signature ?? "";
    renderSigCard();
      renderAtts();
      state.dirty = false;
      setStatus(`草稿 ${fmtTime(d.updated_at)}`);
    } catch (err) {
      setStatus(`加载失败：${msg(err)}`);
    }
  }

  // ---- 自动保存 -------------------------------------------------------
  //
  // 保存**串成一条链**（`saving`），不并行。并行的两次保存会抢同一个 rev，
  // 而且后回来那次可能落在先回来那次之前 —— 那正是「旧的保存盖掉新的」
  // 那个 bug。串起来就没有这个窗口。
  let saving = Promise.resolve();

  function markDirty() {
    state.dirty = true;
    setStatus("未保存");
    if (state.saveTimer) clearTimeout(state.saveTimer);
    state.saveTimer = setTimeout(() => {
      state.saveTimer = null;
      flushSave();
    }, AUTOSAVE_MS);
  }

  /** 马上存一次。关闭窗口、点「保存草稿」时也走这里。 */
  function flushSave() {
    if (state.saveTimer) {
      clearTimeout(state.saveTimer);
      state.saveTimer = null;
    }
    saving = saving.then(save);
    return saving;
  }

  async function save() {
    // 删掉了就别再存。删完关窗口时那一下 flushSave 不该把草稿「复活」。
    if (state.removed) return;
    // 没改动就不写。关窗口时尤其如此 —— 每次都多一条 rev 是纯噪音。
    if (!state.dirty) return;

    const sentRev = state.rev + 1;

    setStatus("保存中…");
    try {
      const d = await invoke("save_draft", { draft: buildPayload(sentRev) });

      // 服务端可能把这个版本**丢掉**（有更新的保存先到了），也可能把这条草稿
      // 重新建了出来（原来的被删了）。两种都要照单收下 id / rev。
      state.draftId = d.id;
      state.rev = Math.max(state.rev, d.rev);

      if (d.rev === sentRev) {
        // 确实写进去了。附件内容不用再传，改动也算存下了。
        for (const a of state.attachments) a.dirty = false;
        state.dirty = false;
        setStatus(`自动保存于 ${fmtTime(d.updated_at)}`);
      } else {
        // 这一版被更新的盖过 / 丢掉了。**不要**用服务端那份覆盖编辑器 ——
        // 用户手上的字更新。下一次保存 rev 更大，会赢。
        setStatus("有更新的草稿先到了，这一版没写进去");
      }
    } catch (err) {
      // `dirty` 保持 true：下次再存
      setStatus(`保存失败：${msg(err)}`);
    }
  }

  /// 撰写窗口当前这一版。`save_draft` 和 `send_message` 共用一份。
  ///
  /// **发出去的和留底的必须是同一份**。两处各拼一遍，迟早有一处漏改 ——
  /// 哪天加个「优先级」只加进保存那份，发出去的信就没有它，而且没人会发现。
  function buildPayload(rev) {
    return {
      id: state.draftId,
      account_id: account.id,
      rev,
      subject: subject.value,
      to: to.get(),
      cc: cc.get(),
      bcc: bcc.get(),
      text: editorText(),
      // 存不存 `html` 由**编辑区现在长什么样**决定，不记「点过格式按钮」。
      // 理由见 `hasRichMarkup`：只记按钮会漏掉 Ctrl+B 和粘贴进来的格式，
      // 漏掉就是重新打开草稿时格式凭空消失。
      html: hasRichMarkup(editor) ? editor.innerHTML : null,
      in_reply_to: null,
      references: [],
      attachments: state.attachments.map((a) => ({
        id: a.id,
        filename: a.filename,
        mime_type: a.mime_type,
        content_id: a.content_id ?? null,
        content_base64: a.dirty ? a.content_base64 : null,
      })),
    };
  }

  // ---- 发送 ----------------------------------------------------------
  //
  // **和自动保存串在同一条链上**（`saving`），不另起一条：发送当中插进来的
  // 那次保存会在 `send_message` 删掉草稿之后把它「复活」，而复活的草稿是
  // 一封已经发出去的信 —— 用户会以为它没发，再点一次。
  function send() {
    if (state.removed) return;
    if ([...to.get(), ...cc.get(), ...bcc.get()].length === 0) {
      setStatus("还没有收件人");
      return;
    }
    saving = saving.then(doSend);
    return saving;
  }

  async function doSend() {
    sendBtn.disabled = true;
    delBtn.disabled = true;
    setStatus("发送中…");
    try {
      const r = await invoke("send_message", { draft: buildPayload(state.rev + 1) });

      // 先立旗再关窗口：closeCompose 会 flushSave 一次，那次必须闭嘴
      state.dirty = false;
      state.removed = r.draft_deleted;

      // `saved_to_sent` 说的是**自己这边留没留副本**，不是发没发出去。
      // 拿它当成败报，用户会在信已经到对方手里时再点一次。
      setStatus(r.saved_to_sent
        ? `已发送 ${r.message_id}`
        : "已发出去了，「已发送」里没存上副本 —— 草稿留着当底");
      closeCompose();
    } catch (err) {
      // 发送失败 = 信没出去。草稿原样留着，改改再发。
      setStatus(`发送失败：${msg(err)}`);
    } finally {
      sendBtn.disabled = false;
      delBtn.disabled = false;
    }
  }

  // ---- 附件 ----------------------------------------------------------
  async function addAttachment(file) {
    const content_base64 = await readAsBase64(file);
    state.attachments.push({
      id: newAttachmentId(),
      filename: file.name || "附件",
      mime_type: file.type || "application/octet-stream",
      content_id: null,
      size: file.size,
      content_base64,
      dirty: true,
    });
    renderAtts();
    markDirty();
  }

  function renderAtts() {
    const box = clear(attBox);
    if (state.attachments.length === 0) {
      // 空态不写文案：整条附件区由 CSS :has 收起（对齐网易）
      return;
    }
    for (const a of state.attachments) {
      box.append(
        node("span", { class: "chip att" },
          node("span", { class: "att-name", text: a.filename }),
          node("span", { class: "att-size muted", text: fmtSize(a.size) }),
          node("button", {
            class: "chip-x", type: "button", text: "✕", "aria-label": `移除 ${a.filename}`,
            onclick: () => {
              state.attachments = state.attachments.filter((x) => x.id !== a.id);
              renderAtts();
              markDirty();
            },
          }),
        ),
      );
    }
  }

  // ---- 签名 ----------------------------------------------------------
  async function saveSignature() {
    if (!account) return;
    if ((account.signature ?? "") === sig.value) return;
    try {
      const updated = await invoke("set_account_signature", {
        account_id: account.id,
        signature: sig.value,
      });
      account.signature = updated.signature;
      setStatus("签名已保存到账号设置");
    } catch (err) {
      setStatus(`签名保存失败：${msg(err)}`);
    }
  }

  // ---- 删除 / 关闭 ---------------------------------------------------
  async function remove() {
    if (state.draftId === null) {
      closeCompose();
      return;
    }
    if (!window.confirm("删掉这封草稿？")) return;
    try {
      await invoke("delete_draft", { draft_id: state.draftId });
    } catch (err) {
      setStatus(`删除失败：${msg(err)}`);
      return;
    }
    // 先立旗再关窗口：closeCompose 会 flushSave 一次，那次必须闭嘴
    state.removed = true;
    state.dirty = false;
    state.draftId = null;
    closeCompose();
  }

  function setStatus(text) {
    status.textContent = text;
  }

  function editorText() {
    // `innerText` 是「看见的文本」，含换行；`textContent` 会把换行吃掉
    return editor.innerText ?? editor.textContent ?? "";
  }

  // Esc = 关闭（会先自动保存）。放在 root 上听，因为焦点可能在编辑区、输入框、
  // 附件列表……任何一个地方。
  root.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeCompose();
    }
    // Ctrl+S = 立刻存一次，别等自动保存那 1.2 秒
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "s") {
      e.preventDefault();
      flushSave();
    }
    // Ctrl+Enter = 发送（邮件客户端通行手势）
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      send();
    }
  });

  // ---- 邮件模板（M6）：插入常用正文 / 管理模板 ---------------------------
  function closeTplMenu() {
    tplMenu.hidden = true;
  }

  async function toggleTplMenu(btn) {
    if (!tplMenu.hidden) {
      closeTplMenu();
      btn.setAttribute("aria-expanded", "false");
      return;
    }
    let tpls = [];
    try {
      tpls = await invoke("list_templates");
    } catch {
      /* 拉不到就只给「管理」 */
    }
    clear(tplMenu);
    for (const t of tpls) {
      tplMenu.append(
        node("button", {
          class: "more-item", type: "button", role: "menuitem", text: t.name || "（未命名）",
          onclick: () => { closeTplMenu(); insertTemplate(t); },
        }),
      );
    }
    if (tpls.length) tplMenu.append(node("div", { class: "more-sep", role: "separator" }));
    tplMenu.append(
      node("button", {
        class: "more-item", type: "button", role: "menuitem", text: "管理模板…",
        onclick: () => { closeTplMenu(); openTemplateManager(); },
      }),
    );
    tplMenu.hidden = false;
    btn.setAttribute("aria-expanded", "true");
  }

  /** 插入模板：主题空才填，正文**追加**（纯 textContent，模板不走 innerHTML）。 */
  function insertTemplate(t) {
    if (!subject.value.trim() && t.subject) subject.value = t.subject;
    if (t.body) {
      const div = document.createElement("div");
      div.textContent = t.body;
      editor.append(div);
    }
    markDirty();
    editor.focus();
  }

  current = {
    root,
    startNew,
    startReply,
    loadDraft,
    flushSave,
  };
  return current;
}

// ================================================================= 工具条

function buildTools(editor, onFormat, { attachBtn = null, tplMenu = null } = {}) {
  const run = (cmd, val = null) => {
    editor.focus();
    // 关键的一行：关掉 styleWithCSS，生成 `<font>` / `align` 而不是 `style=`。
    // 理由见文件顶部。
    document.execCommand("styleWithCSS", false, false);
    document.execCommand(cmd, false, val);
    onFormat();
  };

  const btn = (text, title, cmd, val = null) =>
    node("button", {
      class: "tool", type: "button", text, title, "aria-label": title,
      // 按钮按下会抢走编辑区焦点，先 preventDefault 再 exec
      onmousedown: (e) => e.preventDefault(),
      onclick: () => run(cmd, val),
    });

  // 字号按邮件习惯标 px（execCommand 只认 1-7 档，映射过去）
  const sizeSel = node("select", {
    class: "tool", title: "字号", "aria-label": "字号",
    onchange: (e) => run("fontSize", e.target.value),
  },
    node("option", { value: "3", text: "14px" }),
    node("option", { value: "2", text: "12px" }),
    node("option", { value: "4", text: "16px" }),
    node("option", { value: "5", text: "18px" }),
    node("option", { value: "6", text: "24px" }),
  );

  const colorSel = node("select", {
    class: "tool is-color", title: "文字颜色", "aria-label": "文字颜色",
    onchange: (e) => {
      if (e.target.value) run("foreColor", e.target.value);
      e.target.value = "";
    },
  },
    node("option", { value: "", text: "A 颜色" }),
    node("option", { value: "#b42318", text: "红" }),
    node("option", { value: "#b54708", text: "橙" }),
    node("option", { value: "#067647", text: "绿" }),
    node("option", { value: "#2f6feb", text: "蓝" }),
    node("option", { value: "#6941c6", text: "紫" }),
    node("option", { value: "#1c1f26", text: "黑" }),
    node("option", { value: "#6b7280", text: "灰" }),
  );

  const hiSel = node("select", {
    class: "tool is-color", title: "高亮颜色", "aria-label": "高亮颜色",
    onchange: (e) => {
      if (e.target.value) run("backColor", e.target.value);
      e.target.value = "";
    },
  },
    node("option", { value: "", text: "🖊 高亮" }),
    node("option", { value: "#fef08a", text: "黄" }),
    node("option", { value: "#bbf7d0", text: "绿" }),
    node("option", { value: "#bfdbfe", text: "蓝" }),
    node("option", { value: "#fbcfe8", text: "粉" }),
    node("option", { value: "#e5e7eb", text: "灰" }),
  );

  // 链接不再用 window.prompt（WebKitGTK 弹窗抢焦点，全项目禁用）——
  // 同款小对话框输入地址，选中文字当链接文字。
  const link = node("button", {
    class: "tool", type: "button", text: "链接", title: "插入链接",
    "aria-label": "插入链接",
    onmousedown: (e) => e.preventDefault(),
    onclick: () => {
      const sel = String(document.getSelection?.() ?? "");
      openLinkDialog(sel, (url) => run("createLink", url));
    },
  });

  const imgPicker = node("input", { type: "file", accept: "image/*", hidden: "hidden" });
  imgPicker.addEventListener("change", async () => {
    const file = imgPicker.files?.[0];
    imgPicker.value = "";
    if (!file) return;
    const dataUrl = await readAsDataURL(file);
    // 正文里的图用 `data:` 存着。拼 MIME 时才换成 `cid:` + 内嵌附件
    // （见 compose.rs）—— 撰写窗口要能就地看见图，`cid:` 在这里渲染不出来。
    editor.focus();
    document.execCommand("styleWithCSS", false, false);
    document.execCommand("insertHTML", false, `<img src="${dataUrl}" alt="">`);
    onFormat();
  });

  const imgBtn = node("button", {
    class: "tool", type: "button", text: "图片", title: "插入图片",
    "aria-label": "插入图片",
    onmousedown: (e) => e.preventDefault(),
    onclick: () => imgPicker.click(),
  });

  const tableBtn = node("button", {
    class: "tool", type: "button", text: "表格", title: "插入表格",
    "aria-label": "插入表格",
    onmousedown: (e) => e.preventDefault(),
    onclick: () => {
      // 边框用属性不用 style —— 同样的 CSP 理由
      const row = "<tr><td><br></td><td><br></td><td><br></td></tr>";
      run("insertHTML", `<table border="1" cellpadding="4"><tbody>${row}${row}</tbody></table><p><br></p>`);
    },
  });

  // 字体（execCommand fontName → <font face>，同样不走 style）
  const fontSel = node("select", {
    class: "tool", title: "字体", "aria-label": "字体",
    onchange: (e) => {
      if (e.target.value) run("fontName", e.target.value);
      e.target.value = "";
    },
  },
    node("option", { value: "", text: "字体" }),
    node("option", { value: "宋体", text: "宋体" }),
    node("option", { value: "黑体", text: "黑体" }),
    node("option", { value: "楷体", text: "楷体" }),
    node("option", { value: "微软雅黑", text: "微软雅黑" }),
    node("option", { value: "Arial", text: "Arial" }),
    node("option", { value: "Verdana", text: "Verdana" }),
  );

  // 下拉按钮（对齐网易的 ▾ 形态：把低频动作收进菜单，工具条一行放得下）
  const dropdown = (text, title, items, extraClass = "") => {
    const menu = node("div", { class: "more-menu", hidden: true, role: "menu" }, ...items);
    const wrap = node("div", { class: `more-wrap tool-wrap${extraClass ? ` ${extraClass}` : ""}` });
    const button = node("button", {
      class: "tool", type: "button", text, title, "aria-label": title,
      "aria-haspopup": "true", "aria-expanded": "false",
      onmousedown: (e) => e.preventDefault(),
      onclick: (e) => {
        e.stopPropagation();
        const open = menu.hidden;
        document.querySelectorAll(".compose .more-menu").forEach((m) => { m.hidden = true; });
        document.querySelectorAll(".compose .more-wrap > button").forEach((b) => b.setAttribute("aria-expanded", "false"));
        if (!open) return;
        menu.hidden = false;
        button.setAttribute("aria-expanded", "true");
      },
    });
    wrap.append(button, menu);
    return wrap;
  };
  const menuItem = (text, title, fn) =>
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text, title,
      onclick: () => {
        document.querySelectorAll(".compose .more-menu").forEach((m) => { m.hidden = true; });
        fn();
      },
    });

  // 「＋插入 ▾」：链接/图片/表格/常用模板（模板菜单挂同一位置展开）
  const insertItems = [
    menuItem("链接…", "插入链接", () => link.click()),
    menuItem("图片…", "插入图片", () => imgBtn.click()),
    menuItem("表格", "插入表格", () => tableBtn.click()),
  ];
  if (tplMenu) {
    insertItems.push(
      node("div", { class: "more-sep" }),
      node("button", {
        class: "more-item", type: "button", role: "menuitem", text: "常用模板 ▸",
        title: "插入常用正文模板",
        onclick: (e) => {
          e.stopPropagation();
          e.currentTarget.closest(".more-menu").hidden = true;
          tplMenu.hidden = false;
        },
      }),
    );
  }
  const insertDrop = dropdown("＋ 插入 ▾", "插入", insertItems);
  if (tplMenu) insertDrop.append(tplMenu);

  const alignDrop = dropdown("☰ 对齐 ▾", "对齐", [
    menuItem("左对齐", "左对齐", () => run("justifyLeft")),
    menuItem("居中", "居中", () => run("justifyCenter")),
    menuItem("右对齐", "右对齐", () => run("justifyRight")),
  ]);
  const listDrop = dropdown("•≡ 列表 ▾", "列表", [
    menuItem("• 无序列表", "无序列表", () => run("insertUnorderedList")),
    menuItem("1. 有序列表", "有序列表", () => run("insertOrderedList")),
    menuItem("❝ 引用", "引用", () => run("formatBlock", "<blockquote>")),
  ]);

  const el = node("div", { class: "compose-tools", role: "toolbar", "aria-label": "格式" },
    attachBtn,
    insertDrop,
    node("span", { class: "tool-gap", "aria-hidden": "true" }),
    sizeSel,
    fontSel,
    colorSel,
    hiSel,
    node("span", { class: "tool-gap", "aria-hidden": "true" }),
    btn("B", "粗体", "bold"),
    btn("I", "斜体", "italic"),
    btn("U", "下划线", "underline"),
    btn("S", "删除线", "strikeThrough"),
    node("span", { class: "tool-gap", "aria-hidden": "true" }),
    alignDrop,
    listDrop,
    node("span", { class: "tool-gap", "aria-hidden": "true" }),
    btn("↶", "撤销", "undo"),
    btn("↷", "重做", "redo"),
    imgPicker,
  );

  // ARIA 工具条模式：整条工具条只有**一个**按钮在 Tab 序里，左右键在里面走。
  //
  // 不这么做的话，从「主题」按 Tab 到正文要按 16 下 —— 每个格式按钮都占一格。
  // 真实用户（尤其只用键盘的）一样受不了，不是只有自动化才在乎这个。
  const items = [...el.querySelectorAll("button, select")];
  items.forEach((x, i) => {
    x.tabIndex = i === 0 ? 0 : -1;
  });
  let idx = 0;
  el.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    e.preventDefault();
    items[idx].tabIndex = -1;
    idx = (idx + (e.key === "ArrowRight" ? 1 : -1) + items.length) % items.length;
    items[idx].tabIndex = 0;
    items[idx].focus();
  });

  return { el };
}

/** 插入链接的小对话框（同文件夹命名那套：Enter 确认 / Esc 取消，无 prompt）。 */
function openLinkDialog(selectedText, onSubmit) {
  const input = node("input", {
    class: "form-input", type: "url", placeholder: "https://…",
    "aria-label": "链接地址",
  });
  const status = node("p", { class: "dialog-status", text: "" });
  let busy = false;
  const close = () => {
    if (busy) return;
    root.remove();
    editor0?.focus?.();
  };
  const okBtn = node("button", { class: "btn btn-primary", type: "submit", text: "确定" });
  const cancelBtn = node("button", { class: "btn", type: "button", text: "取消", onclick: close });
  const submit = () => {
    const url = input.value.trim();
    if (!/^https?:\/\//i.test(url)) {
      status.textContent = "链接要以 http:// 或 https:// 开头";
      status.classList.add("is-error");
      return;
    }
    onSubmit(url);
    root.remove();
    editor0?.focus?.();
  };
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      submit();
    } else if (ev.key === "Escape") {
      ev.preventDefault();
      close();
    }
  });
  const editor0 = document.activeElement;
  const root = node(
    "div", { class: "scrim", role: "dialog", "aria-label": "插入链接" },
    node("form", {
      class: "dialog is-narrow",
      onsubmit: (ev) => { ev.preventDefault(); submit(); },
    },
      node("header", { class: "dialog-head" }, node("h2", { class: "dialog-title", text: "插入链接" })),
      node("div", { class: "dialog-body" },
        node("p", { class: "muted", text: selectedText ? `链接文字：「${selectedText.slice(0, 30)}」` : "选中文字后再点可给文字加链接" }),
        input, status,
      ),
      node("footer", { class: "dialog-foot" }, cancelBtn, okBtn),
    ),
  );
  root.addEventListener("mousedown", (ev) => { if (ev.target === root) close(); });
  document.getElementById("app").append(root);
  input.focus();
}

// ================================================================= 收件人

/**
 * 一个收件人输入框：回车 / 逗号切出一个 chip，退格删最后一个。
 *
 * 用 chip 而不是一个大文本框，是因为「谁收到了这封信」必须一眼看得清 ——
 * 尤其是密送，塞在一长串逗号里最容易看漏。
 */
function recipientField({ label, placeholder, onChange }) {
  const list = [];
  const touch = () => {
    render();
    if (onChange) onChange();
  };

  const input = node("input", {
    class: "chip-input", type: "text", placeholder,
    "aria-label": label,
    oninput: () => suggestContacts(input.value),
    onkeydown: (e) => {
      if (e.key === "Enter" || e.key === "," || e.key === ";") {
        e.preventDefault();
        commit();
      } else if (e.key === "Backspace" && input.value === "" && list.length > 0) {
        list.pop();
        touch();
      } else if (e.key === "Escape") {
        hideSuggest();
      }
    },
    onblur: () => {
      commit();
      // 延后藏，给 mousedown 选中留个缝
      setTimeout(hideSuggest, 150);
    },
    onpaste: (e) => {
      // 粘一串地址进来要拆开，不能变成一个巨长的 chip
      const text = e.clipboardData?.getData("text") ?? "";
      if (/[,;\n]/.test(text)) {
        e.preventDefault();
        for (const part of text.split(/[,;\n]+/)) push(part);
        touch();
      }
    },
  });

  // 联系人自动补全（M4）：敲名字 → 列出匹配联系人；用 mousedown 抢在 blur 之前选中。
  const suggest = node("div", { class: "suggest", hidden: true, role: "listbox" });
  async function suggestContacts(q) {
    q = (q || "").trim();
    if (!q) return hideSuggest();
    let matches = [];
    try {
      const contacts = await invoke("list_contacts", { query: q });
      matches = contacts.filter((c) => c.email).slice(0, 6);
    } catch {
      /* 补全拉不到不影响写信 */
    }
    clear(suggest);
    if (matches.length === 0) return hideSuggest();
    for (const c of matches) {
      suggest.append(
        node("button", {
          class: "suggest-item",
          type: "button",
          role: "option",
          onmousedown: (e) => {
            e.preventDefault(); // 抢在 input blur 之前
            push({ display: c.name || null, address: c.email });
            input.value = "";
            hideSuggest();
            touch();
            input.focus();
          },
        },
          node("span", { class: "sg-name", text: c.name || c.email }),
          node("span", { class: "sg-email", text: c.email }),
        ),
      );
    }
    suggest.hidden = false;
  }
  function hideSuggest() {
    suggest.hidden = true;
    clear(suggest);
  }

  const box = node("div", { class: "chips", role: "list" }, input);
  const el = node("div", { class: "compose-field" },
    node("label", { class: "field-label", text: label }),
    node("div", { class: "chips-wrap" }, box, suggest),
  );

  function push(raw) {
    const m = parseMailbox(raw);
    if (m) list.push(m);
  }

  // `render()` 会把 input 从 DOM 里拔出来再插回去 —— 拔出来那一刻浏览器会发
  // blur，blur 的处理器又是 commit，于是自旋。而且焦点会掉：打完一个收件人
  // 按回车，接下来敲的主题全都不知道敲到哪去了。
  //
  // 两件事一起解决：`committing` 挡住重入，`render()` 把焦点放回去。
  let committing = false;

  function commit() {
    if (committing) return;
    const v = input.value.trim();
    if (!v) return;
    committing = true;
    try {
      push(v);
      input.value = "";
      touch();
    } finally {
      committing = false;
    }
  }

  function render() {
    const hadFocus = document.activeElement === input;
    clear(box);
    for (const [i, m] of list.entries()) {
      box.append(
        node("span", { class: `chip${looksLikeAddress(m.address) ? "" : " is-bad"}`, role: "listitem" },
          node("span", { text: formatMailbox(m) }),
          node("button", {
            class: "chip-x", type: "button", text: "✕",
            "aria-label": `移除 ${formatMailbox(m)}`,
            onclick: () => {
              list.splice(i, 1);
              touch();
              input.focus();
            },
          }),
        ),
      );
    }
    box.append(input);
    if (hadFocus) input.focus();
    input.placeholder = list.length ? "" : placeholder;
  }

  render();

  return {
    el,
    get: () => {
      // 失焦没触发的话，输入框里那半个也要算进去
      commit();
      return [...list];
    },
    set: (v) => {
      list.length = 0;
      for (const m of v ?? []) list.push(m);
      render();
    },
    focus: () => input.focus(),
  };
}

/** `张三 <a@b.com>` → `{display, address}`。认不出就整串当地址。 */
function parseMailbox(raw) {
  const s = (raw ?? "").trim();
  if (!s) return null;
  const m = s.match(/^(.*?)<([^<>]+)>\s*$/);
  if (m) {
    const display = m[1].trim().replace(/^["']|["']$/g, "");
    return { display: display || null, address: m[2].trim() };
  }
  return { display: null, address: s };
}

function formatMailbox(m) {
  return m.display ? `${m.display} <${m.address}>` : m.address;
}

function looksLikeAddress(a) {
  return /^[^\s@<>]+@[^\s@<>]+$/.test(a);
}

// ================================================================= 小工具

/**
 * 编辑区里有没有「纯文本表达不了的东西」—— 有的话才存 `html`，
 * 否则这封信就是纯文本，不该因为编辑器是 contenteditable 就自动变成
 * `multipart/alternative`。
 *
 * **看 DOM，不记「点过格式按钮」**。格式标记有三个来源，只记按钮会漏两个：
 *   * 工具条（能记）；
 *   * 浏览器自带的 Ctrl+B / Ctrl+I / Ctrl+U —— 不经过工具条；
 *   * 粘贴进来的富文本 —— 也不经过工具条。
 * 漏掉的后果是存盘时 `html` 被丢成 null，重新打开草稿格式就没了。
 *
 * 判据：`div` / `p` / `br` / `span` 是 contenteditable 打字自带的骨架
 * （`<div>一行</div>`、光秃秃的 `<span>`），不算格式；骨架标签身上挂了
 * 属性（`<div align="center">`）或者出现别的标签（`<b>` `<font>` `<table>`
 * `<img>` …），都是纯文本表达不了的。
 */
function hasRichMarkup(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
  for (let el = walker.nextNode(); el; el = walker.nextNode()) {
    const bare = el.tagName === "DIV" || el.tagName === "P" || el.tagName === "BR" || el.tagName === "SPAN";
    if (!bare || el.attributes.length > 0) return true;
  }
  return false;
}

function newAttachmentId() {
  // 只允许 [A-Za-z0-9_-]：这个 id 会变成磁盘上的文件名（见 store.rs）
  return `a${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`.replace(/[^A-Za-z0-9_-]/g, "");
}

function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const s = String(r.result);
      resolve(s.slice(s.indexOf(",") + 1));
    };
    r.onerror = () => reject(r.error ?? new Error("读文件失败"));
    r.readAsDataURL(file);
  });
}

function readAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(r.error ?? new Error("读文件失败"));
    r.readAsDataURL(file);
  });
}

function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString("zh-CN", { hour12: false });
}

/** 错误 → 一句话。服务端已经是 `user_message` 了，别再拼内部细节。 */
function msg(err) {
  return err instanceof Error ? err.message : String(err);
}

// ================================================================= 邮件模板管理（M6）

let tplManager = null;

/** 打开模板管理浮层：列表 + 新建/改/删（就地表单）。 */
export function openTemplateManager() {
  if (tplManager) {
    tplManager.remove();
    tplManager = null;
  }
  tplManager = buildTemplateManager();
  document.getElementById("app").append(tplManager);
}

function closeTemplateManager() {
  if (!tplManager) return;
  tplManager.remove();
  tplManager = null;
}

function buildTemplateManager() {
  let editing = null; // 当前在改的模板（null = 只看列表）
  let selected = null;

  const list = node("div", { class: "tpl-list", role: "list" });
  const formBox = node("div", { class: "tpl-form" });

  const render = async () => {
    const tpls = await invoke("list_templates").catch(() => []);
    clear(list);
    if (!tpls.length) list.append(node("p", { class: "empty", text: "还没有模板" }));
    for (const t of tpls) {
      list.append(
        node(
          "div",
          { class: `tpl-row${selected === t.id ? " is-sel" : ""}` },
          node(
            "button",
            {
              class: "tpl-pick", type: "button",
              onclick: () => { selected = t.id; editing = { ...t }; renderForm(); render(); },
            },
            node("span", { class: "tpl-name", text: t.name || "（未命名）" }),
            node("span", { class: "tpl-subj", text: t.subject || "" }),
          ),
        ),
      );
    }
  };

  const renderForm = () => {
    clear(formBox);
    const e = editing;
    if (!e) {
      formBox.append(node("p", { class: "empty", text: "选一个模板查看，或点「新建」。" }));
      return;
    }
    const fields = {};
    const tf = (key, label, val, area) => {
      const el = area
        ? node("textarea", { class: "form-input", rows: "8", placeholder: label })
        : node("input", { class: "form-input", type: "text", placeholder: label });
      el.value = val || "";
      fields[key] = el;
      return node("div", { class: "form-field" }, node("label", { class: "field-label", text: label }), el);
    };
    formBox.append(
      node("h3", { class: "tpl-form-title", text: e.id ? "编辑模板" : "新建模板" }),
      tf("name", "模板名", e.name),
      tf("subject", "预填主题（可空）", e.subject),
      tf("body", "正文（纯文本，插入时进编辑区）", e.body, true),
      node(
        "div",
        { class: "contact-actions" },
        node("button", {
          class: "btn btn-primary", type: "button", text: "保存",
          onclick: async () => {
            const input = {
              id: e.id ?? null,
              name: fields.name.value.trim(),
              subject: fields.subject.value.trim(),
              body: fields.body.value,
            };
            if (!input.name) return;
            const id = await invoke("save_template", { input });
            editing = null;
            selected = id;
            await render();
            renderForm();
          },
        }),
        node("button", {
          class: "btn", type: "button", text: "取消",
          onclick: () => { editing = null; renderForm(); },
        }),
        e.id
          ? node("button", {
              class: "btn btn-danger", type: "button", text: "删除",
              onclick: async () => {
                await invoke("delete_template", { id: e.id });
                editing = null;
                selected = null;
                await render();
                renderForm();
              },
            })
          : null,
      ),
    );
    fields.name.focus();
  };

  const root = node(
    "div",
    { class: "scrim", role: "dialog", "aria-label": "邮件模板" },
    node(
      "div",
      { class: "dialog tpl-dialog" },
      node(
        "header",
        { class: "dialog-head" },
        node("h2", { class: "dialog-title", text: "邮件模板" }),
        node("button", {
          class: "btn", type: "button", text: "＋ 新建",
          onclick: () => { editing = { id: null, name: "", subject: "", body: "" }; renderForm(); },
        }),
        node("button", { class: "btn", type: "button", text: "关闭", onclick: closeTemplateManager }),
      ),
      node("div", { class: "tpl-body" }, list, formBox),
    ),
  );
  render();
  renderForm();
  // 点外面关掉（同账号弹窗，恢复通路）。
  root.addEventListener("mousedown", (e) => {
    if (e.target === root) closeTemplateManager();
  });
  return root;
}
