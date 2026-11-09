// 账号录入
//
// M2 的「最小版」：一张表单，把一个账号加进库、把授权码存进钥匙串，然后切到
// 这个账号。**只做加，不做改** —— 多账号的「选哪个」在左栏账号列表、「删哪个」
// 是列表底下那个两步确认的按钮（都在 `app.js`），这张表单还是「填完就走」。
//
// 是浮层对话框，不是设置页：和撰写窗口一个道理，填完就走，不该另占一屏。
//
// ────────────────────────────────────────────────────────────────────────
// ## 授权码只在这里过手一次
//
// 表单里的授权码是**明文**（`type=password` 只是不显示，值还是明文），它只去
// 一个地方：`create_account`。后者把它写进钥匙串（`secrets::set`），库里那一行
// 只存 `keyring_key` 这个指针。所以：
//
//   * 不进模块状态，不回显，不塞进错误提示；
//   * `create_account` 的错误文本也不会带密码（`Error::Secret` 的载荷里只有
//     钥匙串条目的元数据），界面上可以直接显示它；
//   * 别的字段校验失败时**不清空**这个框 —— 重填一遍十几位的授权码最招人烦。
//
// ────────────────────────────────────────────────────────────────────────
// ## 端口跟着加密方式走
//
// 加密方式一换，端口就换成那个方式的默认值（IMAP 993/143，SMTP 465/587/25），
// 除非用户自己填过一个不相干的端口 —— 那是他特意要的，别自作聪明地改掉。
//
// 加密方式用一组**单选**而不是下拉：下拉在 WebKitGTK 里弹的是原生菜单，抢焦点
// 也抢键盘，纯键盘操作（包括截图验证时的按键注入）就不好走了。单选组用方向键
// 就能换，中间没有弹窗。

import { node } from "./dom.js";

const invoke = globalThis.__TAURI__?.core?.invoke;

/// 每种加密方式的默认端口。和 `core/src/types.rs` 的 `Security` 对应，
/// 值就是它序列化出来的那些（`plain` / `ssl` / `start_tls`）。
const IMAP_PORTS = { plain: 143, ssl: 993, start_tls: 143 };
const POP3_PORTS = { plain: 110, ssl: 995, start_tls: 110 };
const SMTP_PORTS = { plain: 25, ssl: 465, start_tls: 587 };

// 供应商速选（对照 wyemail 添加页的 163/126/QQ/Gmail 快捷按钮）：
// 点了填域名 → 自动配置，顺便给一句该家的登录提醒。
const PROVIDERS = [
  ["Gmail", "gmail.com", "Gmail 推荐点「使用 Google 登录」；密码登录需开 IMAP 并用应用专用密码"],
  ["163", "163.com", "163 需在网页版设置里开启 IMAP/POP3/SMTP，并生成授权码"],
  ["126", "126.com", "126 同 163：网页版开启服务并生成授权码"],
  ["QQ", "qq.com", "QQ 邮箱需在设置里开启服务并生成授权码"],
  ["Outlook", "outlook.com", ""],
  ["Yahoo", "yahoo.com", ""],
  ["139", "139.com", ""],
  ["189", "189.cn", ""],
  ["iCloud", "icloud.com", "iCloud 用 App 专用密码登录"],
  ["自定义", "", "自己填收发服务器"],
];

/// 单选上那几个字。键就是 `Security` 序列化出来的值。
const LABELS = { plain: "明文", ssl: "SSL", start_tls: "STARTTLS" };

// ================================================================= 打开

let current = null;

/**
 * 打开账号录入对话框。
 *
 * @param {object} [opts]
 * @param {(account: object) => void} [opts.onSaved] 建好之后调用，参数是
 *   `create_account` 返回的账号。界面切到新账号是调用方的事。
 */
export function openAccountForm({ onSaved } = {}) {
  closeAccountForm();
  const f = buildForm(onSaved);
  document.getElementById("app").append(f.root);
  f.focus();
  return f;
}

/**
 * 构建「嵌入主区」的添加账号页（方案 A：与设置页同构，不再是弹窗）。
 * 由调用方挂进 stage；`onClose` 负责离开本页（返回邮件视图）。
 */
export function buildAccountPage({ onSaved, onClose, edit } = {}) {
  return buildForm(onSaved, {
    page: { onClose },
    ...(edit ? { edit } : {}),
  }).root;
}

export function closeAccountForm() {
  if (!current) return;
  current.root.remove();
  current = null;
}

// ================================================================= 组装

function buildForm(onSaved, opts = {}) {
  // 两种容器：对话框（scrim 小窗）或嵌入主区的页面（方案 A，同设置页架构）。
  // 页面模式没有「点外面关掉」——返回键/✕/取消负责退出。
  const asPage = !!opts.page;
  // 编辑模式：预填现有账号，保存走 update_account（授权码留空 = 不动）
  const editing = opts.edit ?? null;
  const dismiss = () => {
    if (asPage) opts.page.onClose?.();
    else closeAccountForm();
  };
  // 登录方式：默认授权码；「Google 登录」后改 `xoauth2`（`password` 里放的是 token）。
  let authType = "password";
  // 收信协议：IMAP（默认）或 POP3。收发服务器字段两套协议共用，
  // POP3 的主机/端口也填在「收信」那组里。
  let recvProto = "imap";
  // ---- 账号本身 -------------------------------------------------------
  const name = textInput("acc-name", "text", "发信时显示的名字");
  const alias = textInput("acc-alias", "text", "如：工作（留空用名称）");
  const email = textInput("acc-email", "email", "you@example.com");
  // 用户名不再单独配置：各家都认「用户名 = 邮箱」，少一个必填项。
  // 授权码：见文件头。type=password 但它不是「登录密码」，见下面那行提示。
  const password = textInput("acc-pass", "password", "授权码");

  // ---- 收发服务器 -----------------------------------------------------
  const imapHost = textInput("acc-imap-host", "text", "imap.example.com");
  const imapPort = textInput("acc-imap-port", "number", "993");
  const smtpHost = textInput("acc-smtp-host", "text", "smtp.example.com");
  const smtpPort = textInput("acc-smtp-port", "number", "465");
  imapPort.value = "993";
  smtpPort.value = "465";

  const imapSec = securityRadios(
    "imap_security",
    () => (recvProto === "pop3" ? POP3_PORTS : IMAP_PORTS),
    imapPort,
    "ssl",
  );
  const smtpSec = securityRadios("smtp_security", SMTP_PORTS, smtpPort, "ssl");

  // ---- 底栏 -----------------------------------------------------------
  const status = node("span", { class: "dialog-status muted", text: "加完自动切到该账号。" });

  // ---- 域名自动配置（M6）：填了邮箱就把收发服务器补上（可改）-----------
  let lastAuto = null;
  const setSecurity = (name, value) => {
    root.querySelectorAll(`input[name="${name}"]`).forEach((r) => {
      r.checked = r.value === value;
    });
  };
  const applyAutoconfig = async () => {
    const v = email.value.trim();
    if (!v.includes("@")) return;
    let cfg;
    try {
      cfg = await invoke("autoconfig", { email: v });
    } catch {
      return; // 自动配置挂了不影响手填
    }
    if (!cfg) return;
    // 只补空的、或之前自动填过（没被手改）的，别盖掉用户手动填的。
    // 「自动填过」两套都算：字段里可能是上个协议（IMAP↔POP3）留下的自动值。
    const fillRecv = (input, val, ...prevs) => {
      const cur = input.value.trim();
      const auto = prevs.some((p) => p != null && String(p) === cur);
      if (cur === "" || (lastAuto && auto)) input.value = val;
    };
    const fill = (input, val, prev) => {
      const cur = input.value.trim();
      if (cur === "" || (lastAuto && String(cur) === String(prev))) input.value = val;
    };
    const recvHost = recvProto === "pop3" ? cfg.pop3_host : cfg.imap_host;
    const recvPort = recvProto === "pop3" ? cfg.pop3_port : cfg.imap_port;
    const recvSec = recvProto === "pop3" ? cfg.pop3_security : cfg.imap_security;
    fillRecv(imapHost, recvHost, lastAuto?.imap_host, lastAuto?.pop3_host);
    fillRecv(imapPort, String(recvPort), lastAuto?.imap_port, lastAuto?.pop3_port);
    fill(smtpHost, cfg.smtp_host, lastAuto?.smtp_host);
    fill(smtpPort, String(cfg.smtp_port), String(lastAuto?.smtp_port));
    setSecurity("imap_security", recvSec);
    setSecurity("smtp_security", cfg.smtp_security);
    lastAuto = cfg;
    status.textContent = `已按 @${v.split("@")[1]} 自动填好收发服务器（可改）`;
  };
  email.addEventListener("blur", applyAutoconfig);
  let autoTimer = 0;
  email.addEventListener("input", () => {
    clearTimeout(autoTimer);
    autoTimer = setTimeout(applyAutoconfig, 500);
  });
  // `type="submit"` **不带** onclick：点了就走表单的 submit，和「在输入框里按
  // 回车」同一条路。两条路各挂一次就会存两遍。
  const saveBtn = node("button", {
    class: "btn btn-primary",
    type: "submit",
    text: "登录",
  });



  // ---- 收信协议切换（IMAP / POP3，对照 wyemail 的收信类型选择）----------
  const protoHint = node("p", { class: "form-hint", text: "" });
  const mkProtoBtn = (value, label) => {
    const b = node("button", {
      // 用设置页同款 .seg 分段组件（暗色主题已验证），不用自制 proto-btn ——
      // 它在 WebKitGTK 的 focus/hover 下有无法复现的配色异常。
      class: "seg-btn", type: "button", text: label,
      onclick: () => setProto(value),
    });
    b.dataset.value = value;
    return b;
  };
  // 一行式：[IMAP|POP3] + 主机 + 端口。切换协议时主机前缀/端口/提示跟着转。
  const protoRow = node("div", { class: "form-row proto-line" },
    node("div", { class: "seg", role: "group", "aria-label": "收信协议" },
      mkProtoBtn("imap", "IMAP"),
      mkProtoBtn("pop3", "POP3"),
    ),
    node("div", { class: "host-input" }, imapHost),
    node("span", { class: "port-tag", text: "端口" }),
    node("div", { class: "port-input" }, imapPort),
  );
  function setProto(value) {
    recvProto = value;
    protoRow.querySelectorAll(".seg-btn").forEach((b) => {
      const on = b.dataset.value === value;
      b.classList.toggle("is-on", on);
      b.setAttribute("aria-pressed", String(on));
    });
    // 跟随协议转换：自动/占位主机换前缀 imap.↔pop.，端口按当前加密方式重置
    const host = imapHost.value.trim();
    if (/^(imap|pop)\./i.test(host)) {
      imapHost.value = value === "pop3"
        ? host.replace(/^imap\./i, "pop.")
        : host.replace(/^pop\./i, "imap.");
    }
    imapHost.placeholder = value === "pop3" ? "pop.example.com" : "imap.example.com";
    imapPort.value = String((value === "pop3" ? POP3_PORTS : IMAP_PORTS)[imapSec.value()]);
    protoHint.textContent = value === "pop3"
      ? "POP3 只收信：已读/标星仅本地保存，邮件保留在服务器上不删。"
      : "IMAP 全功能：多文件夹，已读/星标同步到服务器。";
  }
  setProto("imap");

  // ---- 编辑模式：把现有账号信息预填进去 -------------------------------
  // 顺序有讲究：setProto 会按加密方式重置端口，所以端口最后填。
  if (editing) {
    name.value = editing.name || "";
    alias.value = editing.alias || "";
    email.value = editing.email || "";
    imapSec.set(editing.imap_security || "ssl");
    smtpSec.set(editing.smtp_security || "ssl");
    setProto(editing.protocol === "pop3" ? "pop3" : "imap");
    imapHost.value = editing.imap_host || "";
    imapPort.value = String(editing.imap_port || "");
    smtpHost.value = editing.smtp_host || "";
    smtpPort.value = String(editing.smtp_port || "");
    password.placeholder = "留空则不修改授权码";
  }

  // ---- 真实服务器登录测试（不保存）-------------------------------------
  const testBtn = node("button", {
    class: "btn", type: "button", text: "测试登录",
    title: "真的连一遍收发服务器，不保存",
    onclick: testLogin,
  });

  function buildInput() {
    return {
      name: name.value.trim(),
      alias: alias.value.trim(),
      email: email.value.trim(),
      imap_host: imapHost.value.trim(),
      imap_port: Number(imapPort.value),
      imap_security: imapSec.value(),
      smtp_host: smtpHost.value.trim(),
      smtp_port: Number(smtpPort.value),
      smtp_security: smtpSec.value(),
      username: email.value.trim(), // 用户名 = 邮箱（见上）
      password: password.value,
      auth_type: authType,
      protocol: recvProto,
    };
  }

  async function testLogin() {
    status.textContent = "正在连接服务器…";
    testBtn.disabled = true;
    try {
      status.textContent = await invoke("test_account_login", { input: buildInput() });
    } catch (err) {
      status.textContent = String(err instanceof Error ? err.message : err);
    } finally {
      testBtn.disabled = false;
    }
  }

  // 高级设置（默认收起）：整行可点，语汇同侧栏行——左边 muted 标签 + 右边
  // 箭头，hover 行底亮，不是一颗突兀的加粗按钮。
  const adv = node("div", { class: "adv-box", hidden: true },
    node("fieldset", { class: "form-group" },
      node("legend", { class: "form-legend", text: "收信" }),
      protoRow,
      protoHint,
      imapSec.el,
    ),
    node("fieldset", { class: "form-group" },
      node("legend", { class: "form-legend", text: "发信（SMTP）" }),
      hostPortRow("SMTP 主机", smtpHost, "端口", smtpPort),
      smtpSec.el,
    ),
    testBtn,
  );
  const advArrow = node("span", { class: "adv-arrow", "aria-hidden": "true", text: "▾" });
  const advToggle = node("button", {
    class: "adv-toggle", type: "button", id: "btn-adv",
    "aria-expanded": "false",
    onclick: () => {
      adv.hidden = !adv.hidden;
      advToggle.setAttribute("aria-expanded", String(!adv.hidden));
      advArrow.textContent = adv.hidden ? "▾" : "▴";
    },
  },
    node("span", { class: "adv-toggle-label", text: "高级设置" }),
    advArrow,
  );

  // 主按钮统一「登录」：Gmail 域名时同位置变「使用 Google 登录」（OAuth），
  // 不再有独立的 Google 按钮。
  const isGmail = () => /@(gmail|googlemail)\.com$/i.test(email.value.trim());
  const updateLoginBtn = () => {
    saveBtn.textContent = editing ? "保存" : (isGmail() ? "使用 Google 登录" : "登录");
  };
  email.addEventListener("input", updateLoginBtn);
  updateLoginBtn();

  // ---- 供应商速选 -----------------------------------------------------
  // 对话框里是一排胶囊；页面里是同侧栏行语汇的行列表（hover 底 / 选中高亮 /
  // 右侧域名提示）。选哪家都一样：补邮箱后缀 + 提示语。
  const pickProvider = (domain, hint) => {
    if (domain) {
      const local = email.value.split("@")[0].trim();
      email.value = local ? `${local}@${domain}` : `@${domain}`;
      updateLoginBtn();
      applyAutoconfig();
    }
    status.textContent = hint || "";
    email.focus();
  };
  const markPicked = (btn) => {
    btn.parentElement?.querySelectorAll(".is-on").forEach((b) => b.classList.remove("is-on"));
    btn.classList.add("is-on");
  };
  const providerChips = node("div", { class: "acc-chips", role: "group", "aria-label": "常用邮箱" },
    PROVIDERS.map(([label, domain, hint]) =>
      node("button", {
        class: "btn acc-chip", type: "button", text: label,
        onclick: (e) => { markPicked(e.currentTarget); pickProvider(domain, hint); },
      }),
    ),
  );
  // 页面模式：下拉列表（同设置页 customSelect 语汇：输入框形态 + ▾ + more-menu）。
  // accounts.js 引不到 app.js 的 customSelect（循环依赖），这里做一个同款的
  // 轻量版——样式类完全复用 .custom-select / .more-menu / .more-wrap。
  const provMenu = node("div", { class: "more-menu", hidden: true, role: "listbox", "aria-label": "常用邮箱" },
    PROVIDERS.map(([label, domain, hint]) =>
      node("button", {
        class: "more-item", type: "button", role: "option", text: label,
        onclick: () => {
          provMenu.hidden = true;
          provBtn.setAttribute("aria-expanded", "false");
          provBtn.querySelector(".cs-label").textContent = label;
          pickProvider(domain, hint);
        },
      }),
    ),
  );
  const provBtn = node("button", {
    class: "form-input custom-select", type: "button",
    "aria-haspopup": "listbox", "aria-expanded": "false",
    onclick: (e) => {
      e.stopPropagation();
      const open = provMenu.hidden;
      provMenu.hidden = !open;
      provBtn.setAttribute("aria-expanded", String(open));
    },
  },
    node("span", { class: "cs-label", text: "选择邮箱" }),
    node("span", { class: "cs-caret", "aria-hidden": "true", text: "▾" }),
  );
  const providerSelect = node("div", { class: "more-wrap acc-prov-wrap" }, provBtn, provMenu);

  const root = asPage
    ? node("div", { class: "acc-page" },
        node("header", { class: "pane-head" },
          node("button", {
            class: "btn acc-back", type: "button", text: "←",
            title: "返回", "aria-label": "返回",
            onclick: () => opts.page.onClose?.(),
          }),
          node("span", { text: editing ? "编辑账号" : "添加账号" }),
          node("span", { class: "acc-head-gap", "aria-hidden": "true" }),
          node("button", {
            class: "btn acc-close", type: "button", text: "✕",
            title: "关闭（Esc）", "aria-label": "关闭",
            onclick: () => opts.page.onClose?.(),
          }),
        ),
        node("div", { class: "acc-page-body" },
          node("form", { class: "acc-page-form", onsubmit: onSubmit },
            // 编辑模式不显示供应商速选（邮箱已定，选供应商会覆盖手填的值）
            editing ? null : node("div", { class: "dlg-sec", text: "选择邮箱" }),
            editing ? null : providerSelect,
            node("div", { class: "dlg-sec", text: "账号信息" }),
            node("div", { class: "form-grid" },
              field("acc-name", "名称", name),
              field("acc-alias", "别名", alias),
              field("acc-email", "邮箱", email),
              field("acc-pass", "授权码", password),
              node("p", {
                class: "form-hint",
                text: "授权码不是登录密码：各家邮箱要先在网页版单独生成（Gmail 无需授权码，直接登录）。别名显示在聚合邮件列表的账号标签里。",
              }),
            ),
            advToggle,
            adv,
            node("div", { class: "acc-page-foot" },
              status,
              node("button", {
                class: "btn", type: "button", text: "取消",
                onclick: () => opts.page.onClose?.(),
              }),
              saveBtn,
            ),
          ),
        ),
      )
    : node("div", { class: "scrim", role: "dialog", "aria-label": "添加账号" },
    node("form", { class: "dialog acc-dialog", onsubmit: onSubmit },
      node("header", { class: "dialog-head" },
        node("h2", { class: "dialog-title", text: "添加账号" }),
      ),
      node("div", { class: "dialog-body" },
        // 分区标签：同侧栏 side-sec 的语汇（muted 小字 + 留白分区，不画线）
        node("div", { class: "dlg-sec", text: "常用邮箱" }),
        providerChips,
        node("div", { class: "dlg-sec", text: "账号信息" }),
        node("div", { class: "form-grid" },
          field("acc-name", "名称", name),
          field("acc-alias", "别名", alias),
          field("acc-email", "邮箱", email),
          field("acc-pass", "授权码", password),
          node("p", {
            class: "form-hint",
            text: "授权码不是登录密码：各家邮箱要先在网页版单独生成（Gmail 无需授权码，直接登录）。别名显示在聚合邮件列表的账号标签里。",
          }),
        ),
        advToggle,
        adv,
      ),
      node("footer", { class: "dialog-foot" },
        status,
        node("button", {
          class: "btn", type: "button", text: "取消",
          onclick: closeAccountForm,
        }),
        saveBtn,
      ),
    ),
  );

  // ================================================================ 行为

  // Esc = 不存就走。放在 root 上听，因为焦点可能在任何一个输入框里。
  // 不像撰写窗口那样「关之前存一下」—— 这里没有半成品草稿，关了就关了。
  root.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      dismiss();
    }
  });

  // 页面模式没有「点外面关掉整页」，但供应商下拉的菜单要收——
  // 点在下拉以外任何地方都关。
  if (asPage) {
    root.addEventListener("mousedown", (e) => {
      if (!e.target.closest || !e.target.closest(".acc-prov-wrap")) {
        provMenu.hidden = true;
        provBtn.setAttribute("aria-expanded", "false");
      }
    });
  } else {
    root.addEventListener("mousedown", (e) => {
      if (e.target === root) closeAccountForm();
    });
  }

  function onSubmit(e) {
    // 表单用 <form> 是为了「回车就提交」；真提交得拦掉，页面不能跳走。
    e.preventDefault();
    save();
  }

  async function save() {
    // Gmail 且没填授权码 → 先走统一「登录」里的 OAuth（webview），拿到令牌再存。
    // 编辑模式不走这分支：令牌在钥匙串里原样保留。
    if (!editing && isGmail() && !password.value.trim()) {
      await googleLogin();
      if (!password.value.trim()) return; // 用户取消了授权
    }
    const input = buildInput();
    // 编辑且授权码留空：登录方式保持原样（钥匙串里可能是 xoauth2 令牌，
    // 被翻成 password 就再也连不上了）；填了新授权码才按新值走。
    if (editing && !input.password.trim()) input.auth_type = editing.auth_type;

    const bad = validate(input, { email, password, imapHost, smtpHost, imapPort, smtpPort }, editing != null);
    if (bad) {
      // 校验失败只说哪一项，不动已填的东西 —— 尤其是授权码。
      status.textContent = bad.message;
      bad.field?.focus();
      return;
    }

    saveBtn.disabled = true;
    status.textContent = "正在保存…";
    try {
      if (editing) {
        // 编辑：更新连接信息；授权码只有填了新值才写钥匙串
        const account = await invoke("update_account", { account_id: editing.id, input });
        dismiss();
        onSaved?.(account);
        return;
      }
      const account = await invoke("create_account", { input });
      dismiss();
      onSaved?.(account);
    } catch (err) {
      // 这段文本来自 `create_account`，那边保证不含密码（见文件头）。
      status.textContent = String(err instanceof Error ? err.message : err);
      saveBtn.disabled = false;
    }
  }

  function focus() {
    name.focus();
  }

  // ---- Google 登录（XOAUTH2）--------------------------------------------
  // 应用内 webview 跳 Google 授权 → 换 token → 把**令牌包**放进「授权码」框，
  // 并把登录方式切成 `xoauth2`。凭据写死在客户端内。
  //
  // 令牌包 JSON 格式同后端 tokens::pack：access_token 一小时就过期，
  // 没有 refresh_token 的话隔天就登不上了 —— 所以整包存（含 refresh/过期时刻）。
  async function googleLogin() {
    status.textContent = "正在打开 Google 授权…（应用内弹窗，授权完自动回来）";
    try {
      const token = await invoke("google_oauth_login");
      password.value = JSON.stringify({
        access: token.access_token,
        refresh: token.refresh_token || "",
        exp: Math.floor(Date.now() / 1000) + (token.expires_in || 3600) - 120,
      });
      authType = "xoauth2";
      status.textContent = "已用 Google 授权，凭据已就位（可直接「添加」）";
    } catch (err) {
      status.textContent = `Google 登录失败：${err instanceof Error ? err.message : err}`;
    }
  }

  current = { root, focus };
  return current;
}

// ================================================================= 校验

/**
 * 填得对不对。**只挡住「填完肯定连不上」的那几种**（空的、不是个邮箱、端口
 * 不是个端口号），服务器是不是真有这台机器、密码对不对，只有连一次才知道 ——
 * 在这儿猜只会挡住本来就填对的人。
 *
 * 返回 `{ message, field }` 或 `null`。
 */
function validate(input, els, passOptional = false) {
  if (!input.email.includes("@") || /\s/.test(input.email)) {
    return { message: "邮箱地址看起来不对", field: els.email };
  }
  for (const [label, v, f] of [
    ["授权码", input.password, els.password],
    ["IMAP 主机", input.imap_host, els.imapHost],
    ["SMTP 主机", input.smtp_host, els.smtpHost],
  ]) {
    // 编辑模式允许授权码留空（= 不改钥匙串里那份）
    if (label === "授权码" && passOptional) continue;
    if (!v) return { message: `${label}还没填`, field: f };
  }
  for (const [label, p, f] of [
    ["IMAP 端口", input.imap_port, els.imapPort],
    ["SMTP 端口", input.smtp_port, els.smtpPort],
  ]) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      return { message: `${label}该是 1–65535 之间的整数`, field: f };
    }
  }
  return null;
}

// ================================================================= 零件

function field(id, label, input) {
  return node("div", { class: "form-row" },
    node("label", { class: "form-label", for: id, text: label }),
    input,
  );
}

function hostPortRow(hostLabel, host, portLabel, port) {
  return node("div", { class: "form-row is-split" },
    node("label", { class: "form-label", for: host.id, text: hostLabel }),
    host,
    node("label", { class: "form-label", for: port.id, text: portLabel }),
    port,
  );
}

function textInput(id, type, placeholder) {
  return node("input", {
    class: "form-input",
    id,
    type,
    placeholder,
    autocomplete: "off",
    spellcheck: "false",
  });
}

/**
 * 一组加密方式单选，外加「换方式就换默认端口」。
 *
 * 端口只在它**还空着或还停在某个默认值**时才动；用户自己填的数字一次都不碰。
 */
function securityRadios(name, ports, portInput, checked) {
  // `ports` 可以是表，也可以是「按当前收信协议取表」的函数 —— 收信那组的
  // 端口要随 IMAP/POP3 切换（993/143 ↔ 995/110）。
  const portsMap = () => (typeof ports === "function" ? ports() : ports);

  const inputs = Object.keys(portsMap()).map((value) => {
    const el = node("input", { type: "radio", id: `${name}-${value}`, name, value });
    if (value === checked) el.checked = true;
    el.addEventListener("change", () => {
      const map = portsMap();
      // 判「是不是用户自己填的」用整张表，不用单个值：明文和 STARTTLS 常同端口，
      // 来回切还得认得出来。
      const known = new Set(Object.values(map).map(String));
      if (el.checked && (portInput.value === "" || known.has(portInput.value))) {
        portInput.value = String(map[value]);
      }
    });
    return node("label", { for: el.id }, el, node("span", { text: LABELS[value] }));
  });

  const box = node("div", { class: "form-radios", role: "group", "aria-label": `${name} 加密方式` },
    inputs,
  );

  return {
    el: node("div", { class: "form-row" },
      node("span", { class: "form-label", text: "加密" }),
      box,
    ),
    value: () => box.querySelector(`input[name="${name}"]:checked`)?.value ?? "ssl",
    /** 编辑账号预填用：选中指定加密方式（不触发换端口的 change 逻辑）。 */
    set: (v) => {
      const r = box.querySelector(`input[name="${name}"][value="${v}"]`);
      if (r) r.checked = true;
    },
  };
}
