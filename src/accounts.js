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

export function closeAccountForm() {
  if (!current) return;
  current.root.remove();
  current = null;
}

// ================================================================= 组装

function buildForm(onSaved) {
  // 登录方式：默认授权码；「Google 登录」后改 `xoauth2`（`password` 里放的是 token）。
  let authType = "password";
  // 收信协议：IMAP（默认）或 POP3。收发服务器字段两套协议共用，
  // POP3 的主机/端口也填在「收信」那组里。
  let recvProto = "imap";
  // ---- 账号本身 -------------------------------------------------------
  const name = textInput("acc-name", "text", "发信时显示的名字");
  const email = textInput("acc-email", "email", "you@example.com");
  const username = textInput("acc-user", "text", "登录用户名，多半就是邮箱");
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
  const status = node("span", { class: "dialog-status muted", text: "" });

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
    text: "添加",
  });

  // ---- 收信协议切换（IMAP / POP3，对照 wyemail 的收信类型选择）----------
  const protoHint = node("p", {
    class: "form-hint",
    text: "POP3 只收信：已读/标星仅保存在本地；邮件保留在服务器上不删。",
  });
  const mkProtoBtn = (value, label) => {
    const b = node("button", {
      class: "btn proto-btn", type: "button", text: label,
      onclick: () => setProto(value),
    });
    b.dataset.value = value;
    return b;
  };
  const protoRow = node("div", { class: "form-row" },
    node("span", { class: "form-label", text: "收信协议" }),
    node("div", { class: "form-radios", role: "group", "aria-label": "收信协议" },
      mkProtoBtn("imap", "IMAP"),
      mkProtoBtn("pop3", "POP3"),
    ),
    protoHint,
  );
  function setProto(value) {
    recvProto = value;
    protoRow.querySelectorAll(".proto-btn").forEach((b) => {
      const on = b.dataset.value === value;
      b.classList.toggle("is-on", on);
      b.setAttribute("aria-pressed", String(on));
    });
    // 换协议就把收信主机/端口换成对应那套（手填过就不盖）
    applyAutoconfig();
  }
  setProto("imap");

  // ---- 真实服务器登录测试（不保存）-------------------------------------
  const testBtn = node("button", {
    class: "btn", type: "button", text: "测试登录",
    title: "真的连一遍收发服务器，不保存",
    onclick: testLogin,
  });

  function buildInput() {
    return {
      name: name.value.trim(),
      email: email.value.trim(),
      imap_host: imapHost.value.trim(),
      imap_port: Number(imapPort.value),
      imap_security: imapSec.value(),
      smtp_host: smtpHost.value.trim(),
      smtp_port: Number(smtpPort.value),
      smtp_security: smtpSec.value(),
      username: username.value.trim(),
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

  const root = node("div", { class: "scrim", role: "dialog", "aria-label": "添加账号" },
    node("form", { class: "dialog", onsubmit: onSubmit },
      node("header", { class: "dialog-head" },
        node("h2", { class: "dialog-title", text: "添加账号" }),
      ),
      node("div", { class: "dialog-body" },
        node("div", { class: "acc-chips", role: "group", "aria-label": "常用邮箱" },
          PROVIDERS.map(([label, domain, hint]) =>
            node("button", {
              class: "btn acc-chip", type: "button", text: label,
              onclick: () => {
                if (domain) {
                  const local = email.value.split("@")[0].trim();
                  email.value = local ? `${local}@${domain}` : `@${domain}`;
                  applyAutoconfig();
                }
                status.textContent = hint || "";
                email.focus();
              },
            }),
          ),
        ),
        node("div", { class: "form-grid" },
          field("acc-name", "名称", name),
          field("acc-email", "邮箱", email),
          field("acc-user", "用户名", username),
          field("acc-pass", "授权码", password),
          node("button", {
            class: "btn", type: "button", id: "btn-google-login", text: "使用 Google 登录",
            title: "Gmail 走 OAuth，不用填授权码",
            onclick: googleLogin,
          }),
          node("p", {
            class: "form-hint",
            text: "授权码不是登录密码：各家邮箱都要先在网页上单独生成一个，只给客户端用。Gmail 可直接「使用 Google 登录」。",
          }),
        ),
        node("fieldset", { class: "form-group" },
          node("legend", { class: "form-legend", text: "收信" }),
          protoRow,
          hostPortRow("收信主机", imapHost, "端口", imapPort),
          imapSec.el,
        ),
        node("fieldset", { class: "form-group" },
          node("legend", { class: "form-legend", text: "发信（SMTP）" }),
          hostPortRow("SMTP 主机", smtpHost, "端口", smtpPort),
          smtpSec.el,
        ),
        node("p", { class: "form-hint", text: "加完直接切过去。" }),
      ),
      node("footer", { class: "dialog-foot" },
        status,
        node("button", {
          class: "btn", type: "button", text: "取消",
          onclick: closeAccountForm,
        }),
        testBtn,
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
      closeAccountForm();
    }
  });

  // 点弹窗外面 = 关掉（焦点丢了也能一下解脱，不会卡在弹窗上）；
  // 点弹窗里面不关（靠 `e.target === root` 判定，不用子元素 stopPropagation）。
  root.addEventListener("mousedown", (e) => {
    if (e.target === root) closeAccountForm();
  });

  function onSubmit(e) {
    // 表单用 <form> 是为了「回车就提交」；真提交得拦掉，页面不能跳走。
    e.preventDefault();
    save();
  }

  async function save() {
    const input = buildInput();

    const bad = validate(input, { email, username, password, imapHost, smtpHost, imapPort, smtpPort });
    if (bad) {
      // 校验失败只说哪一项，不动已填的东西 —— 尤其是授权码。
      status.textContent = bad.message;
      bad.field?.focus();
      return;
    }

    saveBtn.disabled = true;
    status.textContent = "正在保存…";
    try {
      const account = await invoke("create_account", { input });
      closeAccountForm();
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
  // 应用内 webview 跳 Google 授权 → 换 token → 把 token 放进「授权码」框
  // （就是它的凭据），并把登录方式切成 `xoauth2`。凭据写死在客户端内。
  async function googleLogin() {
    status.textContent = "正在打开 Google 授权…（应用内弹窗，授权完自动回来）";
    try {
      const token = await invoke("google_oauth_login");
      password.value = token.access_token;
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
function validate(input, els) {
  if (!input.email.includes("@") || /\s/.test(input.email)) {
    return { message: "邮箱地址看起来不对", field: els.email };
  }
  for (const [label, v, f] of [
    ["用户名", input.username, els.username],
    ["授权码", input.password, els.password],
    ["IMAP 主机", input.imap_host, els.imapHost],
    ["SMTP 主机", input.smtp_host, els.smtpHost],
  ]) {
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
  };
}
