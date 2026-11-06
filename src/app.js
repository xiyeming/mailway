// mailway 前端
//
// 没有框架、没有构建步骤：M1 的交互就是「选文件夹 → 选信 → 读」，
// 一个模块比一套构建链好读好改。等状态真开始互相打架再考虑别的。
//
// ⚠️ 安全约定：全项目只有**两处** `innerHTML`，都在别的模块里，各自写明了
// 为什么可以：
//   * `.mail-body`（阅读页）—— 内容是 `core::sanitize` 净化过的
//   * `.compose-editor`（撰写窗口）—— 内容是用户自己写的，见 compose.js
// 其余一律 `textContent`（或 `node()`，它故意不提供 `html` 这个口子）。
// 加新界面时别破例——一个 `innerHTML` 就能把净化器绕过去。
//
// IPC 参数名走 snake_case（`rename_all = "snake_case"`），和 Rust 完全一致。
// Tauri 默认转 camelCase，那会在两份代码之间多一层对不上的名字。

import { node, clear, flipMenuOverflow, placeMenuAt } from "./dom.js";
import { openCompose } from "./compose.js";
import { openAccountForm } from "./accounts.js";

const invoke = globalThis.__TAURI__?.core?.invoke;

const app = document.getElementById("app");

if (typeof invoke !== "function") {
  app.replaceChildren(
    node("p", { class: "error" }, "Tauri IPC 不可用：这个页面必须跑在 mailway 窗口里。"),
  );
  throw new Error("tauri ipc unavailable");
}

// ================================================================= 状态

const state = {
  account: null,
  /** 折叠的文件夹 id（子文件夹树）。 */
  collapsedFolders: new Set(),
  /** 全部账号。M3 起左栏并排显示它们，点哪个切哪个（见 `renderAccount`）。 */
  accounts: [],
  folders: [],
  messages: [],
  /** 草稿箱里的草稿。和 `messages` 分开存：形状不一样，混在一起每处都得判一下。 */
  drafts: [],
  folderId: null,
  messageId: null,
  detail: null,
  /** 来信分类规则（每账号），在设置→邮箱设置→来信分类里管理。 */
  rules: [],
  /** 规则表单开着没（就地一行，同文件夹那套）。 */
  ruleOp: false,
  /** 非空 = 搜索模式：`messages` 里放的是搜索结果，不是当前文件夹的信。 */
  searchQuery: "",
  /** 只看未读（列表头的筛选图标切换）。 */
  unreadOnly: false,
  /** 所有账号的文件夹（侧栏账号树）。 */
  allFolders: [],
  /** 多选：选中的是 thread key（行），动作时展开成 message id。 */
  selected: new Set(),
  selectMode: false,
  /** `smart_counts()` 的结果（侧栏角标）。 */
  counts: null,
  /** 侧栏当前高亮项的 key（文件夹/智能箱/快捷箱）。 */
  activeKey: "",
  /** 当前「智能箱/快捷箱」视图；null = 普通文件夹视图（走 `folderId`）。 */
  smart: null,
  /** 当前打开的会话（同 `thread_key` 的信，跨文件夹）；null = 未开。 */
  thread: null,
  /** 顶层模式：`mail` / `contacts` / `calendar`（左侧图标栏切）。 */
  mode: "mail",
  /** 联系人视图状态。 */
  contacts: { list: [], query: "", selected: null, editing: null },
  /** 日历视图状态。 */
  calendar: { year: 0, month: 0, events: [], selectedDay: null, editing: null },
  /** 设置（键值，来自 `get_settings`）。 */
  settings: {},
  /** 设置页当前分区。 */
  settingsSection: "system",
  /** 邮箱设置：选中账号 + 当前 tab（info/signature/template/rules）。 */
  mailboxSel: null,
  mailboxTab: "info",
};

// ================================================================= 格式化

function fmtRowDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return new Intl.DateTimeFormat("zh-CN", {
    year: sameYear ? undefined : "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(d);
}

function fmtFullDate(iso) {
  if (!iso) return "（无日期）";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "long",
    day: "numeric",
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(iso));
}

function fmtSize(n) {
  if (n === null || n === undefined) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtAddr(list) {
  if (!list || list.length === 0) return "—";
  return list.map((m) => (m.display ? `${m.display} <${m.address}>` : m.address)).join("、");
}

function fmtSender(m) {
  return m.display || m.address || "（未知发件人）";
}

// ================================================================= 侧栏：角标辅助

/** 折叠/展开子文件夹树。 */
function toggleFolderCollapse(id) {
  if (state.collapsedFolders.has(id)) state.collapsedFolders.delete(id);
  else state.collapsedFolders.add(id);
  renderSidebar();
}

function folderUnread(id) {
  return (state.counts?.folder_unread || []).find(([k]) => k === id)?.[1] ?? 0;
}
function accountUnread(id) {
  return (state.counts?.account_unread || []).find(([k]) => k === id)?.[1] ?? 0;
}
function accountFlagged(id) {
  return (state.counts?.account_flagged || []).find(([k]) => k === id)?.[1] ?? 0;
}

/** 所有账号的本地草稿拼一份（快捷「所有草稿箱」用）。带 `_account` 好开撰写窗。 */
async function allDrafts() {
  const out = [];
  for (const a of state.accounts) {
    const ds = await invoke("list_drafts", { account_id: a.id });
    for (const d of ds) out.push({ ...d, _account: a });
  }
  return out;
}

// ================================================================= 启动

async function boot() {
  try {
    const pong = await invoke("core_ping");
    if (pong !== "pong") throw new Error(`core_ping 返回了 ${pong}`);

    await fetchSettings();

    const accounts = await invoke("list_accounts");
    state.accounts = accounts;
    if (accounts.length === 0) {
      renderNoAccount();
      return;
    }
    await useAccount(accounts[0]);
  } catch (err) {
    renderError(err);
  }
}

/**
 * 切到这个账号：重读文件夹和列表，左栏那张卡片也换掉。
 *
 * 刚建好的账号在服务器上还什么都没有，所以「一个服务器文件夹都没有」要单独
 * 处理：`withDraftsFolder` 无论如何都会补一条本地草稿箱，拿它当「选中的文件夹」
 * 会让人看见「没有草稿」——那说的是草稿箱空，不是你的账号刚建好还没收过信。
 */
/** 重载侧栏数据：全部账号 + 全部文件夹 + 各种计数。 */
async function refreshSidebarData() {
  state.accounts = await invoke("list_accounts");
  state.allFolders = await invoke("list_all_folders");
  state.counts = await invoke("smart_counts");
}

async function useAccount(account) {
  resetSelect();
  state.account = account;
  state.folderId = null;
  state.messageId = null;
  state.detail = null;
  state.messages = [];
  state.drafts = [];
  // 半截的规则表单同理
  state.ruleOp = false;
  // 搜索也是上一个账号的搜索：结果是按 account_id 查的，留着会串台
  state.searchQuery = "";
  const searchBox = document.getElementById("search-box");
  if (searchBox) searchBox.value = "";
  await refreshSidebarData();
  state.folders = withDraftsFolder(state.allFolders.filter((f) => f.account_id === account.id && f.id !== 0));
  renderAccount();
  renderSidebar();
  // 上一个账号的同步状态别跟着过来：「收到 5 封」说的是**那个**账号的事，
  // 留在这儿会被当成这个账号的。
  const status = document.getElementById("sync-status");
  if (status) status.textContent = "";

  const server = state.folders.filter((f) => f.id !== 0);
  if (server.length > 0) {
    const inbox = state.folders.find((f) => f.kind === "inbox") ?? state.folders[0];
    await selectFolder(inbox.id);
  } else {
    renderMessageList([], "还没有邮件 —— 点右上角「收信」从服务器拉下来");
    renderReader();
    updateListCount();
  }
}

/// 一个账号都没有：别摆个空三栏让人自己找路，直接把「添加账号」摆到中间。
/// 连中栏标题也一起换掉 —— 这时候没有「收件箱」，标题写着收件箱是骗人。
function renderNoAccount() {
  state.account = null;
  renderAccount();
  renderSidebar();

  document.getElementById("list-title").textContent = "邮件";
  document.getElementById("list-count").textContent = "";
  clear(document.getElementById("messages")).append(
    node("p", { class: "empty", text: "还没有账号" }),
    node("div", { class: "empty-actions" },
      node("button", {
        class: "btn btn-primary",
        type: "button",
        text: "添加账号",
        onclick: addAccount,
      }),
    ),
  );

  document.getElementById("reader-title").textContent = "阅读";
  clear(document.getElementById("reader")).append(
    node("p", { class: "empty", text: "添加账号后就可以收发邮件了。" }),
  );
}

/**
 * 添加账号。加完切过去，顺手收一次信 —— 建完账号还得自己想起来点「收信」
 * 才看得到邮件，是新用户最容易卡住的一步。
 */
function addAccount() {
  openAccountForm({
    onSaved: async (account) => {
      // 重新拉一遍而不是 push：库里那行才是真的（id、时间都是它给的），
      // 而且万一哪天 create_account 顺手做了点别的（补默认文件夹之类），
      // 这里不用跟着改。
      state.accounts = await invoke("list_accounts");
      await useAccount(account);
      syncNow();
    },
  });
}

function renderError(err) {
  clear(app).append(
    node(
      "p",
      { class: "error" },
      `启动失败：${err instanceof Error ? err.message : String(err)}`,
    ),
  );
}

// ================================================================= 骨架

function renderShell() {
  clear(app).append(
    node("div", { class: `shell mode-${state.mode}` },
      renderRail(),
      node("main", { class: "stage", id: "stage" }),
    ),
  );
  renderStage();
}

/** 只重画左侧图标栏（设置里开关日历入口用，不动主区）。 */
function refreshRail() {
  const old = document.querySelector(".rail");
  if (old) old.replaceWith(renderRail());
}

/** 左侧图标栏：邮件 / 联系人 / 日历（参考图 1 的图标栏）+ 底部主题开关。 */
function renderRail() {
  return node(
    "nav",
    { class: "rail", "aria-label": "主导航" },
    railBtn("mail", "mail", "邮件"),
    railBtn("contacts", "users", "联系人"),
    // 「启用日历」关掉就不出这个入口（设置→日历）
    state.settings?.enable_calendar !== "off" ? railBtn("calendar", "calendar", "日历") : null,
    themeBtn(),
    node("div", { class: "rail-spacer" }),
    railBtn("settings", "gear", "设置"),
  );
}

/** 明/暗主题开关（图标栏底部）。 */
function themeBtn() {
  const dark = document.documentElement.dataset.theme === "dark";
  return node(
    "button",
    {
      class: "rail-btn",
      type: "button",
      title: dark ? "切换到亮色" : "切换到暗色",
      "aria-label": "切换主题",
      onclick: toggleTheme,
    },
    svgIcon(dark ? "sun" : "moon", "rail-icon rail-theme-icon"),
    node("span", { class: "rail-label", text: "主题" }),
  );
}

/** 应用主题（只切 `data-theme` 属性，变量由 CSS 覆盖）。 */
function applyTheme(theme) {
  if (theme === "dark") document.documentElement.dataset.theme = "dark";
  else delete document.documentElement.dataset.theme;
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try {
    localStorage.setItem("mailway.theme", next);
  } catch {
    /* 存不了也不影响本次会话 */
  }
  const icon = document.querySelector(".rail-theme-icon");
  if (icon && icon.parentElement) {
    icon.replaceWith(svgIcon(next === "dark" ? "sun" : "moon", "rail-icon rail-theme-icon"));
  }
}

function railBtn(mode, icon, label) {
  return node(
    "button",
    {
      class: `rail-btn${state.mode === mode ? " is-active" : ""}`,
      type: "button",
      title: label,
      "aria-label": label,
      "aria-current": state.mode === mode ? "page" : "false",
      onclick: () => switchMode(mode),
    },
    svgIcon(icon, "rail-icon"),
    node("span", { class: "rail-label", text: label }),
  );
}

function renderStage() {
  const stage = document.getElementById("stage");
  if (!stage) return;
  clear(stage);
  if (state.mode === "contacts") return buildContacts(stage);
  if (state.mode === "calendar") return buildCalendar(stage);
  if (state.mode === "settings") return buildSettings(stage);
  return buildMail(stage);
}

/** 切模式：重画壳（图标栏高亮 + 舞台），再填当前模式内容。 */
async function switchMode(mode) {
  if (state.mode === mode) return;
  state.mode = mode;
  renderShell();
  if (mode === "mail") {
    renderAccount();
    renderSidebar();
    repaintList();
    renderReader();
  } else if (mode === "contacts") {
    await loadContacts();
  } else if (mode === "calendar") {
    await loadCalendar();
  } else if (mode === "settings") {
    await loadSettings();
  }
}

/** 邮件三栏（原有的 folders / list / reader）。 */
function buildMail(stage) {
  stage.append(
    node("aside", { class: "pane pane-folders" },
      node("div", { class: "side-top" },
        node("div", { class: "side-actions" },
          node("button", {
            class: "icon-btn", id: "btn-compose", type: "button",
            title: "写邮件（Ctrl+N）", "aria-label": "写邮件", onclick: composeNew,
          }, node("span", { "aria-hidden": "true", text: "✎" }), node("span", { text: "写信" })),
          node("button", {
            class: "icon-btn", id: "btn-sync", type: "button",
            title: "收信（F5）", "aria-label": "收信", onclick: syncNow,
          }, node("span", { class: "spin-icon", "aria-hidden": "true", text: "↻" }), node("span", { text: "收信" })),
          node("span", { class: "muted sync-status", id: "sync-status" }),
        ),
        node("input", {
          class: "search-box side-search",
          id: "search-box",
          type: "search",
          placeholder: "搜索邮件",
          "aria-label": "搜索邮件",
          onkeydown: (ev) => {
            if (ev.key === "Enter") runSearch(ev.target.value);
            else if (ev.key === "Escape") exitSearch();
          },
        }),
      ),
      node("nav", { class: "folder-list", id: "folders", "aria-label": "文件夹" }),
    ),
    node("section", { class: "pane pane-list" },
      node("header", { class: "pane-head" },
        node("button", {
          class: "btn-filter",
          type: "button",
          title: "只看未读",
          "aria-label": "只看未读邮件",
          "aria-pressed": "false",
          text: "⏷",
          onclick: (e) => toggleFilter(e.currentTarget),
        }),
        node("span", { id: "list-title", text: "收件箱" }),
        node("span", { class: "muted", id: "list-count" }),
        node("button", {
          class: "btn-readall",
          type: "button",
          id: "btn-read-all",
          text: "全标已读",
          title: "把这个文件夹里的未读邮件全部标为已读",
          hidden: true,
          onclick: markAllRead,
        }),
        node("button", {
          class: "btn-readall",
          type: "button",
          id: "btn-select",
          text: "多选",
          title: "多选邮件（全选/反选/批量操作）",
          onclick: toggleSelectMode,
        }),
      ),
      node("div", { class: "select-bar", id: "select-bar", hidden: true }),
      node("div", { class: "message-list", id: "messages", role: "list" }),
    ),
    node("section", { class: "pane pane-reader" },
      node("header", { class: "pane-head" },
        node("span", { id: "reader-title", text: "阅读" }),
      ),
      node("div", { class: "reader", id: "reader" }),
    ),
  );
}

/**
 * 文件夹的显示顺序。
 *
 * 服务端按 `imap_name` 排（`&XfJT0ZAB-` 会排到 `INBOX` 前面），那是给
 * 协议用的顺序，不是给人看的。人要看的是收件箱在最上面，所以这里按
 * **语义**排，同语义的再按名字兜底。
 */
const FOLDER_ORDER = ["inbox", "sent", "drafts", "junk", "trash", "archive", "normal"];

function sortFolders(list) {
  return [...list].sort((a, b) => {
    const d = FOLDER_ORDER.indexOf(a.kind) - FOLDER_ORDER.indexOf(b.kind);
    return d !== 0 ? d : a.display_name.localeCompare(b.display_name, "zh-CN");
  });
}

/**
 * 补一条「草稿」，然后排好序。
 *
 * 草稿是**本地**的（见 `selectFolder`）：写了一半的信存在本地库，不等服务器。
 * 所以它必须一直看得见 —— 服务器没给草稿箱（假 IMAP 就没有）时更要自己补一条，
 * 否则草稿存进去就再也点不开，等于白存。
 *
 * `id: 0` 是个撞不上真文件夹的哨兵（`folders.id` 从 1 自增），而且草稿分支
 * 从来不会拿它去查 `list_messages`。服务器自己有草稿箱时用它那条，不重复。
 */
function withDraftsFolder(folders) {
  return sortFolders(
    folders.some((f) => f.kind === "drafts")
      ? folders
      : [...folders, { id: 0, kind: "drafts", display_name: "草稿" }],
  );
}

/**
 * 左栏顶部的账号列表。
 *
 * M3 起账号可以有好几个，这里并排列出来，点哪个切哪个。当前账号用
 * `aria-current` 标出来 —— 不靠颜色单打，读屏和键盘也得知道「现在是哪个」。
 *
 * 「添加账号」一直在列表底下（一个账号都没有时它就是唯一的东西）；
 * 「删除当前账号」要点两次才真删（见 [`deleteActiveAccount`]）。
 */
/**
 * 账号管理已移到侧栏（「邮箱」分区「＋」添加、账号行「⋮」删除）。
 * 这里保留一个空壳，让历史调用点（`renderAccount()`）不用改；真正渲染在 `renderSidebar`。
 */
function renderAccount() {}

/** 账号行右侧「⋮」菜单：删除这个账号（两步确认）。 */
function accountMenu(a) {
  const label = `删除「${a.name || a.email}」`;
  const menu = node("div", { class: "more-menu", hidden: true, role: "menu" });
  menu.append(
    node("button", {
      class: "more-item is-danger", type: "button", role: "menuitem", text: label,
      onclick: (e) => armAccountDelete(e, a),
    }),
  );
  const btn = node("button", {
    class: "icon-btn acct-more", type: "button", title: "账号操作",
    "aria-label": `${a.name || a.email} 账号操作`, "aria-haspopup": "true", "aria-expanded": "false",
    text: "⋮",
    onclick: (e) => {
      e.stopPropagation();
      if (openMore && openMore.menu === menu) closeMore();
      else showMore(btn, menu);
    },
  });
  return node("div", { class: "more-wrap acct-more-wrap" }, btn, menu);
}

/** 删除账号的两步确认（第一下待命，第二下真删）。 */
function armAccountDelete(e, a) {
  e.stopPropagation();
  const btn = e.currentTarget;
  if (btn.dataset.armed === "1") {
    closeMore();
    removeAccount(a.id);
    return;
  }
  btn.dataset.armed = "1";
  btn.textContent = "再点一次确认删除";
  setTimeout(() => {
    if (btn.isConnected && btn.dataset.armed === "1") {
      btn.dataset.armed = "";
      btn.textContent = `删除「${a.name || a.email}」`;
    }
  }, 3000);
}

/** 删掉某个账号；删的是当前账号就切到下一个。 */
async function removeAccount(id) {
  try {
    await invoke("delete_account", { account_id: id });
    await refreshSidebarData();
    if (state.account && state.account.id === id) {
      const next = state.accounts[0];
      if (next) await useAccount(next);
      else renderNoAccount();
    } else {
      renderSidebar();
    }
    statusNote("账号已删除");
  } catch (err) {
    statusNote(`删除账号失败：${err instanceof Error ? err.message : err}`);
  }
}

/** [`deleteActiveAccount`] 的「已经点过一次」状态和它的复位定时器。 */
let delArmed = false;
let delTimer = 0;

/**
 * 删掉当前账号。**要点两次**：第一次把按钮换成「再点一次确认删除」，
 * 五秒内第二下才真删，之后回到初始状态。
 *
 * 两步确认不用 `confirm()`：WebKitGTK 的 JS 弹窗抢焦点（M0 踩过）、
 * 键盘走不进，而且删除的代价是账号 + 钥匙串里的授权码一起没，误触太贵。
 *
 * 钥匙串里的授权码由 `delete_account` **先**删掉再删库（顺序在它那边定死，
 * 见 `commands.rs`）。删完挑下一个账号接上；一个都不剩就回到「还没有账号」。
 */
async function deleteActiveAccount() {
  const a = state.account;
  if (!a) return;
  const btn = document.getElementById("btn-del-account");

  if (!delArmed) {
    delArmed = true;
    if (btn) btn.textContent = "再点一次确认删除";
    clearTimeout(delTimer);
    delTimer = setTimeout(() => {
      delArmed = false;
      const b = document.getElementById("btn-del-account");
      if (b) b.textContent = "删除当前账号";
    }, 5000);
    return;
  }

  clearTimeout(delTimer);
  delArmed = false;
  await invoke("delete_account", { account_id: a.id });
  state.accounts = await invoke("list_accounts");
  if (state.accounts.length > 0) await useAccount(state.accounts[0]);
  else renderNoAccount();
}

// ================================================================= 左栏

// ---- 侧栏：快捷文件夹 + 账号文件夹树（对照参考图） --------------------

const QUICK = [
  { filter: "inbox", icon: "inbox", name: "所有收件箱", countKey: "inbox_unread" },
  { filter: "unread", icon: "envelope", name: "所有未读", countKey: "all_unread" },
  { filter: "flagged", icon: "star", name: "所有标星", countKey: "all_flagged" },
  { filter: "drafts", icon: "doc", name: "所有草稿箱", countKey: "all_drafts", isDrafts: true },
  { filter: "sent", icon: "send", name: "所有已发送", countKey: "all_sent_unread" },
];
const ACCOUNT_SMART = [
  { filter: "unread", icon: "envelope", name: "未读邮件" },
  { filter: "flagged", icon: "star", name: "标星邮件" },
];
const FOLDER_ICON = { inbox: "inbox", sent: "send", drafts: "doc", junk: "spam", trash: "trash", archive: "archive", normal: "folder" };

function sidebarRow({ key, icon, name, count = 0, onclick, ctx, depth = 0, hasKids = false, collapsed = false, ontoggle = null }) {
  return node(
    "button",
    {
      class: `side-row${state.activeKey === key ? " is-active" : ""}`,
      type: "button",
      "aria-current": state.activeKey === key ? "true" : "false",
      ...(depth > 0 ? { "data-depth": String(Math.min(depth, 4)) } : {}),
      onclick,
      ...(ctx ? { oncontextmenu: ctx } : {}),
    },
    // 展开/收起：有子文件夹才画（没有留空位对齐）
    hasKids
      ? node("span", {
          class: `side-caret${collapsed ? "" : " is-open"}`,
          role: "button",
          tabindex: "0",
          text: collapsed ? "▸" : "▾",
          title: collapsed ? "展开子文件夹" : "收起子文件夹",
          onclick: (e) => {
            e.stopPropagation();
            if (ontoggle) ontoggle();
          },
        })
      : node("span", { class: "side-caret is-empty", "aria-hidden": "true" }),
    typeof icon === "string" && ICONS[icon] ? svgIcon(icon, "side-icon") : node("span", { class: "side-icon", text: icon }),
    node("span", { class: "side-name", text: name }),
    count > 0 ? node("span", { class: "side-count", text: String(count) }) : null,
  );
}

function renderSidebar() {
  const box = clear(document.getElementById("folders"));
  const c = state.counts || {};

  // 快捷文件夹（跨账号聚合；设置里可关）
  if (state.settings?.show_quick_folders !== "off") {
    box.append(node("div", { class: "side-sec", text: "快捷文件夹" }));
    for (const q of QUICK) {
      box.append(
        sidebarRow({
          key: `quick:${q.filter}`,
          icon: q.icon,
          name: q.name,
          count: c[q.countKey] ?? 0,
          onclick: () => openSmart(q.filter, null, q.name, !!q.isDrafts),
          ctx: (e) => openSmartCtxMenu(e, state.account || state.accounts[0]),
        }),
      );
    }
  }

  // 设为快捷文件夹的文件夹（右键文件夹可置顶）
  const quicks = state.allFolders.filter((f) => f.quick);
  if (quicks.length > 0) {
    for (const f of quicks) {
      box.append(
        sidebarRow({
          key: `folder:${f.id}`,
          icon: FOLDER_ICON[f.kind] || "📁",
          name: f.display_name,
          count: folderUnread(f.id),
          onclick: () => selectFolder(f.id),
          ctx: (e) => {
            const acc = state.accounts.find((a) => a.id === f.account_id);
            if (acc) openFolderCtxMenu(e, acc, f);
          },
        }),
      );
    }
  }

  // 邮箱（每账号一棵文件夹树 + 智能箱）；标题右「＋」= 添加账号（对照原型）
  box.append(
    node("div", { class: "side-sec" },
      node("span", { text: "邮箱" }),
      node("button", {
        class: "sec-add", type: "button", text: "＋", title: "添加账号",
        "aria-label": "添加账号", onclick: addAccount,
      }),
    ),
  );
  for (const a of state.accounts) {
    box.append(
      node("div", {
        class: "side-acct",
        // 右键账号行 = 这个账号下新建文件夹
        oncontextmenu: (e) => openFolderCtxMenu(e, a, null),
      },
        node("span", { class: "side-acct-name", text: a.name || a.email }),
        node("span", { class: "side-acct-mail", text: a.email }),
        accountMenu(a),
      ),
    );
    const fs = sortFolders(state.allFolders.filter((f) => f.account_id === a.id && f.id !== 0));
    const hasServerDrafts = fs.some((f) => f.kind === "drafts");
    // 子文件夹树：parent_id 分组；父不在列表里的当根（防悬空丢行）
    const byParent = new Map();
    for (const f of fs) {
      const key = f.parent_id != null && fs.some((p) => p.id === f.parent_id) ? f.parent_id : 0;
      if (!byParent.has(key)) byParent.set(key, []);
      byParent.get(key).push(f);
    }
    let smartDone = false;
    const renderLevel = (parent, depth) => {
      for (const f of sortFolders(byParent.get(parent) || [])) {
        const kids = byParent.get(f.id) || [];
        const collapsed = state.collapsedFolders.has(f.id);
        box.append(
          sidebarRow({
            key: `folder:${f.id}`,
            icon: FOLDER_ICON[f.kind] || "📁",
            name: f.display_name,
            count: folderUnread(f.id),
            depth,
            hasKids: kids.length > 0,
            collapsed,
            ontoggle: () => toggleFolderCollapse(f.id),
            onclick: () => selectFolder(f.id),
            // 右键文件夹行 = 新建/重命名/删除
            ctx: (e) => openFolderCtxMenu(e, a, f),
          }),
        );
        if (f.kind === "inbox" && !smartDone) {
        for (const s of ACCOUNT_SMART) {
          const n = s.filter === "unread" ? accountUnread(a.id) : accountFlagged(a.id);
          box.append(
            sidebarRow({
              key: `smart:${s.filter}:${a.id}`,
              icon: s.icon,
              name: s.name,
              count: n,
              onclick: () => openSmart(s.filter, a.id, s.name, false),
              ctx: (e) => openSmartCtxMenu(e, a),
            }),
          );
        }
        smartDone = true;
      }
        if (kids.length > 0 && !collapsed) renderLevel(f.id, depth + 1);
      }
    };
    renderLevel(0, 0);
    // 本地草稿箱（服务器没给草稿箱时补一条；按账号，不共用 id:0 哨兵）
    if (!hasServerDrafts) {
      box.append(
        sidebarRow({
          key: `drafts:${a.id}`,
          icon: "📄",
          name: "草稿箱",
          onclick: () => openSmart("drafts", a.id, "草稿箱", true),
        }),
      );
    }
  }
}

/** 打开智能箱 / 快捷箱。`account_id=null` = 跨账号聚合（快捷）。 */
async function openSmart(filter, account_id, title, isDrafts) {
  resetSelect();
  state.smart = { filter, account_id, title, isDrafts };
  state.folderId = null;
  state.activeKey = account_id == null ? `quick:${filter}` : `smart:${filter}:${account_id}`;
  state.searchQuery = "";
  const sb = document.getElementById("search-box");
  if (sb) sb.value = "";
  state.messageId = null;
  state.detail = null;
  state.unreadOnly = false;
  if (isDrafts) {
    state.messages = [];
    state.drafts = account_id == null ? await allDrafts() : await invoke("list_drafts", { account_id });
  } else {
    state.drafts = [];
    state.messages = await invoke("list_smart", { filter, account_id: account_id ?? null });
  }
  document.getElementById("list-title").textContent = title;
  renderSidebar();
  repaintList();
  renderReader();
  updateListCount();
  document.querySelector(".shell")?.classList.remove("is-reading");
}

// ---------------------------------------------------------------- 文件夹管理
//
// 新建 / 重命名 / 删除走**文件夹右键菜单**（对照 wyemail）：右键侧栏里的
// 文件夹行（或账号行）弹出操作菜单。收件箱和本地草稿箱（id: 0）不给改名/删
// —— RFC 3501 §6.3.4 收件箱不可删，改名是「搬空自己」的特殊语义。
// 「新建/改名」用小对话框输入名字（Enter 确定 / Esc 取消），不用 prompt()；
// 删除是**两步确认**（菜单项就地变「再点一次确认删除」，五秒内第二下才动手）。

let openFolderCtx = null;
let folderDelArmed = false;
let folderDelTimer = 0;

function closeFolderCtx() {
  if (!openFolderCtx) return;
  clearTimeout(folderDelTimer);
  folderDelArmed = false;
  openFolderCtx.remove();
  openFolderCtx = null;
}

// 菜单向右渲染，贴屏幕右缘自动翻转（防出屏）
document.addEventListener("click", () => requestAnimationFrame(flipMenuOverflow), true);
window.addEventListener("resize", flipMenuOverflow);

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeFolderCtx();
});

/** 右键智能箱（快捷区/未读/标星）：全标已读 + 新建文件夹。 */
function openSmartCtxMenu(e, account) {
  if (!account) return;
  e.preventDefault();
  e.stopPropagation();
  closeAllMenus();
  const overlay = node("div", { class: "menu-overlay", role: "presentation" });
  overlay.addEventListener("mousedown", (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
  const menu = node("div", { class: "more-menu is-fixed", role: "menu" });
  menu.addEventListener("click", (ev) => ev.stopPropagation());
  menu.append(
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text: "全标已读",
      onclick: () => {
        overlay.remove();
        smartMarkAllRead();
      },
    }),
    node("div", { class: "more-sep" }),
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text: "新建文件夹",
      onclick: () => {
        overlay.remove();
        openFolderNameDialog("新建文件夹", "", async (name) => {
          const f = await invoke("create_folder", { account_id: account.id, name });
          await afterFolderChange(f.id);
        });
      },
    }),
  );
  menu.style.right = "auto";
  overlay.append(menu);
  document.body.append(overlay);
  placeMenuAt(menu, e.clientX, e.clientY);
}

/** 智能箱「全标已读」：当前视图里所有未读批量标已读。 */
async function smartMarkAllRead() {
  const ids = state.messages.filter((m) => !m.flags.seen).map((m) => m.id);
  if (ids.length === 0) {
    toast("都已读了");
    return;
  }
  try {
    await invoke("batch_set_flags", { message_ids: ids, seen: true, flagged: null });
    for (const m of state.messages) if (ids.includes(m.id)) m.flags.seen = true;
    repaintList();
    updateListCount();
    renderSidebar();
    renderReader();
    toast(`已标为已读 ${ids.length} 封`);
  } catch (err) {
    toast(`操作失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 右键文件夹/账号行：光标处弹操作菜单（对齐网易邮箱大师）。
 *  `folder=null` = 账号行（只有新建）。 */
function openFolderCtxMenu(e, account, folder) {
  e.preventDefault();
  e.stopPropagation();
  closeAllMenus();
  const canManage = !!folder && folder.id !== 0 && folder.kind !== "inbox";
  const overlay = node("div", { class: "menu-overlay", role: "presentation" });
  overlay.addEventListener("mousedown", (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
  const menu = node("div", { class: "more-menu is-fixed", role: "menu" });
  menu.addEventListener("click", (ev) => ev.stopPropagation());
  const item = (text, fn, opts = {}) =>
    node("button", {
      class: opts.danger ? "more-item is-danger" : "more-item",
      type: "button",
      role: "menuitem",
      text,
      ...(opts.id ? { id: opts.id } : {}),
      ...(opts.off ? { disabled: true, title: opts.title || "" } : {}),
      onclick: () => fn(),
    });
  const sep = () => node("div", { class: "more-sep" });

  menu.append(
    item("全标已读", () => {
      overlay.remove();
      folderMarkAllRead(folder);
    }, { off: !folder, title: "先选一个文件夹" }),
    sep(),
  );
  if (folder && canManage) {
    menu.append(
      item(folder.quick ? "取消快捷文件夹" : "设为快捷文件夹", () => {
        overlay.remove();
        toggleQuickFolder(folder);
      }),
      sep(),
    );
  }
  menu.append(
    item("新建文件夹", () => {
      overlay.remove();
      openFolderNameDialog("新建文件夹", "", async (name) => {
        const f = await invoke("create_folder", { account_id: account.id, name });
        await afterFolderChange(f.id);
      });
    }),
    item("新建子文件夹", () => {
      overlay.remove();
      openFolderNameDialog(`在「${folder ? folder.display_name : account.name}」下新建`, "", async (name) => {
        const f = await invoke("create_folder", {
          account_id: account.id,
          name,
          parent_folder_id: folder ? folder.id : null,
        });
        await afterFolderChange(f.id);
      });
    }, { off: !canManage, title: "先选一个可管理的文件夹" }),
    sep(),
  );
  if (folder && canManage) {
    menu.append(
      item(folder.remind ? "✓ 新邮件提醒" : "新邮件提醒", () => {
        overlay.remove();
        toggleRemind(folder);
      }, { title: "新信落进这个箱时弹桌面通知" }),
      sep(),
      item("邮件批量删除", () => {
        // 两步确认（清空整个箱，危险）
        const btn = menu.querySelector("#ctx-clear");
        if (btn.dataset.armed !== "1") {
          btn.dataset.armed = "1";
          btn.textContent = "再点一次确认清空";
          return;
        }
        overlay.remove();
        clearFolderMails(folder);
      }, { danger: true, id: "ctx-clear", title: "清空这个文件夹里的全部邮件" }),
      item("对本地邮件执行来信分类", () => {
        overlay.remove();
        applyRulesToFolder(folder);
      }, { title: "把已收的信逐封过一遍规则（挪箱/标已读/标星/贴标签）" }),
      sep(),
      item("重命名", () => {
        overlay.remove();
        openFolderNameDialog("重命名文件夹", folder.display_name, async (name) => {
          await invoke("rename_folder", { folder_id: folder.id, new_name: name });
          await afterFolderChange(folder.id);
        });
      }),
      item("删除", () => {
        const btn = menu.querySelector("#ctx-del");
        if (btn.dataset.armed !== "1") {
          btn.dataset.armed = "1";
          btn.textContent = "再点一次确认删除";
          return;
        }
        overlay.remove();
        invoke("delete_folder", { folder_id: folder.id })
          .then(() => afterFolderChange(null))
          .catch((err) => toast(`删除失败：${err instanceof Error ? err.message : err}`));
      }, { danger: true, id: "ctx-del" }),
    );
  }

  // 光标处弹出（量真实尺寸再摆，别猜高度——九项菜单猜 320px 必裁底）
  menu.style.right = "auto";
  overlay.append(menu);
  document.body.append(overlay);
  placeMenuAt(menu, e.clientX, e.clientY);
}

/** 文件夹「全标已读」：本地一条 UPDATE + 后台推服务器。 */
async function folderMarkAllRead(folder) {
  if (!folder || folder.id == null) return;
  try {
    const n = await invoke("mark_folder_read", { folder_id: folder.id });
    await refreshSidebarData();
    renderSidebar();
    if (state.folderId === folder.id) {
      repaintList();
      updateListCount();
    }
    toast(n > 0 ? `已标为已读 ${n} 封` : "都已读了");
  } catch (err) {
    toast(`操作失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 快捷文件夹开关（侧栏置顶）。 */
async function toggleQuickFolder(folder) {
  try {
    const on = !folder.quick;
    await invoke("set_folder_quick", { folder_id: folder.id, on });
    folder.quick = on;
    await refreshSidebarData();
    renderSidebar();
    toast(on ? `「${folder.display_name}」已加入快捷文件夹` : `「${folder.display_name}」已移出快捷文件夹`);
  } catch (err) {
    toast(`操作失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 新邮件提醒开关（文件夹级）。 */
async function toggleRemind(folder) {
  try {
    const on = !folder.remind;
    await invoke("set_folder_remind", { folder_id: folder.id, on });
    folder.remind = on;
    toast(on ? `「${folder.display_name}」新邮件提醒已开启` : `「${folder.display_name}」新邮件提醒已关闭`);
  } catch (err) {
    toast(`操作失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 邮件批量删除（清空文件夹；已两步确认）。 */
async function clearFolderMails(folder) {
  try {
    const n = await invoke("clear_folder_mails", { folder_id: folder.id });
    await afterFolderChange(folder.id);
    toast(n > 0 ? `已清空「${folder.display_name}」${n} 封` : "这个箱是空的");
  } catch (err) {
    toast(`清空失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 对本地邮件执行来信分类。 */
async function applyRulesToFolder(folder) {
  try {
    const msg = await invoke("apply_rules_to_folder", { folder_id: folder.id });
    await afterFolderChange(folder.id);
    toast(msg);
  } catch (err) {
    toast(`执行失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 删除的两步确认：第一下待命，五秒内第二下才真删。 */
function folderCtxDelete(folder) {
  const btn = openFolderCtx?.querySelector("#folder-ctx-del");
  if (!folderDelArmed) {
    folderDelArmed = true;
    if (btn) btn.textContent = "再点一次确认删除";
    clearTimeout(folderDelTimer);
    folderDelTimer = setTimeout(() => {
      folderDelArmed = false;
      const b = openFolderCtx?.querySelector("#folder-ctx-del");
      if (b) b.textContent = "删除";
    }, 5000);
    return;
  }
  clearTimeout(folderDelTimer);
  folderDelArmed = false;
  // 真删：菜单先变「处理中」（慢网下要几秒）
  const items = openFolderCtx ? [...openFolderCtx.querySelectorAll(".more-item")] : [];
  items.forEach((b) => (b.disabled = true));
  const delBtn = openFolderCtx?.querySelector("#folder-ctx-del");
  if (delBtn) delBtn.textContent = "正在删除…";
  nextFrame().then(() => {
    invoke("delete_folder", { folder_id: folder.id })
      .then(() => {
        closeFolderCtx();
        return afterFolderChange(null);
      })
      .catch((err) => {
        // 失败就恢复菜单，让用户重试或改点别的
        items.forEach((b) => (b.disabled = false));
        if (delBtn) delBtn.textContent = "删除";
        statusNote(`删除失败：${err instanceof Error ? err.message : err}`);
      });
  });
}

/** 增删改之后：重读文件夹、刷侧栏，选中停到 `selectId`（null=收件箱/第一个）。 */
async function afterFolderChange(selectId) {
  await refreshSidebarData();
  if (state.account) {
    state.folders = withDraftsFolder(
      state.allFolders.filter((f) => f.account_id === state.account.id && f.id !== 0),
    );
  }
  renderSidebar();
  if (selectId != null) {
    await selectFolder(selectId);
  } else if (state.account) {
    const inbox = state.folders.find((f) => f.kind === "inbox") ?? state.folders[0];
    if (inbox) await selectFolder(inbox.id);
  }
}

/** 文件夹列表重读一遍。草稿哨兵照旧由 `withDraftsFolder` 补。 */
async function reloadFolders() {
  state.folders = withDraftsFolder(
    await invoke("list_folders", { account_id: state.account.id }),
  );
}

/** 新建/重命名的小对话框：Enter 确定、Esc/点外面 关闭。
 *  提交期间**禁用按钮 + 显示进行中**——每个操作都要新建 IMAP 连接（TLS 握手
 *  + LOGIN + 往返），代理/慢网下要好几秒，没有反馈就像卡死。 */
function openFolderNameDialog(title, initial, onSubmit) {
  const input = node("input", {
    class: "form-input", type: "text", value: initial ?? "",
    placeholder: "文件夹名", "aria-label": "文件夹名",
  });
  const status = node("p", { class: "dialog-status", text: "" });
  const setStatus = (text, kind) => {
    status.textContent = text;
    status.classList.toggle("is-busy", kind === "busy");
    status.classList.toggle("is-error", kind === "error");
  };
  let busy = false;
  const close = () => {
    if (busy) return;
    root.remove();
  };
  const okBtn = node("button", { class: "btn btn-primary", type: "submit", text: "确定" });
  const cancelBtn = node("button", { class: "btn", type: "button", text: "取消", onclick: close });
  const submit = async () => {
    if (busy) return;
    const name = input.value.trim();
    if (!name) {
      setStatus("文件夹名不能空着", "error");
      return;
    }
    busy = true;
    input.disabled = true;
    okBtn.disabled = true;
    cancelBtn.disabled = true;
    okBtn.textContent = "请稍候…";
    setStatus(
      title.includes("重命名")
        ? "正在重命名…（连服务器，慢网时可能要几秒）"
        : "正在创建…（连服务器，慢网时可能要几秒）",
      "busy",
    );
    await nextFrame(); // busy 先上屏，再开网络请求
    try {
      await onSubmit(name);
      root.remove();
    } catch (err) {
      busy = false;
      input.disabled = false;
      okBtn.disabled = false;
      cancelBtn.disabled = false;
      okBtn.textContent = "确定";
      setStatus(String(err instanceof Error ? err.message : err), "error");
      input.focus();
    }
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
  const root = node(
    "div", { class: "scrim", role: "dialog", "aria-label": title },
    node("form", {
      class: "dialog is-narrow",
      onsubmit: (ev) => { ev.preventDefault(); submit(); },
    },
      node("header", { class: "dialog-head" }, node("h2", { class: "dialog-title", text: title })),
      node("div", { class: "dialog-body" }, input, status),
      node("footer", { class: "dialog-foot" }, cancelBtn, okBtn),
    ),
  );
  root.addEventListener("mousedown", (ev) => { if (ev.target === root) close(); });
  document.getElementById("app").append(root);
  input.focus();
  input.select();
}

// ---------------------------------------------------------------- 来信分类

/**
 * 条件/动作的选项。值就是 `rules` 模块 serde 那套（snake_case）——
 * 前端拼 JSON 直接发，中间没有第二套命名。
 */
const RULE_FIELDS = [
  ["from", "发件人"],
  ["to", "收件人"],
  ["subject", "主题"],
  ["body", "正文"],
];
const RULE_OPS = [
  ["contains", "包含"],
  ["not_contains", "不包含"],
  ["equals", "等于"],
];

function ruleSummary(r) {
  const field = Object.fromEntries(RULE_FIELDS);
  const op = Object.fromEntries(RULE_OPS);
  const conds = (r.conditions || [])
    .map((c) => `${field[c.field] ?? c.field} ${op[c.op] ?? c.op}「${c.value}」`)
    .join("，且 ");
  const acts = (r.actions || [])
    .map((a) => {
      if (a.kind === "move") {
        const f = state.allFolders.find((x) => x.id === a.folder_id);
        return `移到「${f ? f.display_name : `文件夹 ${a.folder_id}`}」`;
      }
      if (a.kind === "mark_read") return "标为已读";
      if (a.kind === "mark_flagged") return "加星标";
      if (a.kind === "add_labels") return `贴标签 ${a.labels.join("、")}`;
      return a.kind;
    })
    .join("，");
  return `${conds} → ${acts}`;
}

/**
 * 来信分类（每账号）：规则列表 + 新建表单 + 启停/删除。
 * 规则是**每账号配置**，归在「设置 → 邮箱设置 → 来信分类」，不占侧栏。
 */
async function renderRuleManager(container, account) {
  clear(container);
  container.append(node("div", { class: "settings-sub", text: "收件箱新信自动分" }));
  if (state.ruleOp) {
    container.append(ruleForm(account));
    document.getElementById("rule-value")?.focus();
    return;
  }
  const rules = (await invoke("list_rules", { account_id: account.id }).catch(() => [])) || [];
  if (rules.length === 0) {
    container.append(node("p", { class: "muted", text: "还没有规则。新建后，收件箱新信会自动按条件处理。" }));
  }
  for (const r of rules) {
    container.append(
      node("div", { class: "setting-row" },
        node("div", { class: "setting-text" },
          node("span", { class: "setting-label", text: ruleSummary(r) }),
        ),
        node("div", { class: "contact-actions" },
          node("button", {
            class: "btn", type: "button", text: r.enabled ? "停用" : "启用",
            "aria-pressed": r.enabled ? "true" : "false",
            onclick: () => toggleRule(r),
          }),
          node("button", { class: "btn btn-danger", type: "button", text: "删除", onclick: () => deleteRule(r) }),
        ),
      ),
    );
  }
  container.append(
    node("div", { class: "contact-actions" },
      node("button", {
        class: "btn btn-primary", type: "button", text: "＋ 新建规则",
        onclick: () => { state.ruleOp = true; renderSettings(); },
      }),
      node("span", { class: "muted folder-status", id: "rule-status" }),
    ),
  );
}

function ruleForm(account) {
  const field = node(
    "select",
    { class: "rule-select", id: "rule-field", "aria-label": "条件看哪一块" },
    ...RULE_FIELDS.map(([v, label]) => node("option", { value: v, text: label })),
  );
  const op = node(
    "select",
    { class: "rule-select", id: "rule-op", "aria-label": "条件怎么比" },
    ...RULE_OPS.map(([v, label]) => node("option", { value: v, text: label })),
  );
  const value = node("input", {
    class: "folder-input rule-value", id: "rule-value", type: "text",
    placeholder: "关键词", "aria-label": "条件关键词",
    onkeydown: (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); submitRule(account); }
      else if (ev.key === "Escape") { ev.preventDefault(); cancelRule(); }
    },
  });

  // 移动的目标不给收件箱（往「来信」里挪没意义）和本地草稿箱（id 0，没服务器一端）
  const move = node(
    "select",
    { class: "rule-select", id: "rule-move", "aria-label": "移到文件夹" },
    node("option", { value: "", text: "不移动" }),
    ...state.allFolders
      .filter((f) => f.account_id === account.id && f.id !== 0 && f.kind !== "inbox")
      .map((f) => node("option", { value: String(f.id), text: f.display_name })),
  );
  const read = node("input", { type: "checkbox", id: "rule-read" });
  const flag = node("input", { type: "checkbox", id: "rule-flag" });
  const labels = node("input", {
    class: "folder-input rule-value", id: "rule-labels", type: "text",
    placeholder: "标签（逗号分隔）", "aria-label": "加标签",
    onkeydown: (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); submitRule(account); }
      else if (ev.key === "Escape") { ev.preventDefault(); cancelRule(); }
    },
  });

  return node(
    "div",
    { class: "rule-form" },
    node("div", { class: "rule-line" },
      node("span", { class: "rule-label", text: "条件" }),
      field, op, value,
    ),
    node("div", { class: "rule-line" },
      node("span", { class: "rule-label", text: "动作" }),
      move,
      node("label", { class: "rule-check" }, read, node("span", { text: " 标记已读" })),
      node("label", { class: "rule-check" }, flag, node("span", { text: " 加星标" })),
      labels,
    ),
    node("div", { class: "rule-line" },
      node("button", { class: "btn btn-primary", type: "button", text: "确定", onclick: () => submitRule(account) }),
      node("button", { class: "btn", type: "button", text: "取消", onclick: cancelRule }),
      node("span", { class: "muted folder-status", id: "rule-status" }),
    ),
  );
}

function cancelRule() {
  state.ruleOp = false;
  renderSettings();
}

function ruleError(err) {
  const st = document.getElementById("rule-status");
  if (st) st.textContent = err instanceof Error ? err.message : String(err);
}

async function submitRule(account) {
  const fieldEl = document.getElementById("rule-field");
  const opEl = document.getElementById("rule-op");
  const valueEl = document.getElementById("rule-value");
  const moveEl = document.getElementById("rule-move");
  const readEl = document.getElementById("rule-read");
  const flagEl = document.getElementById("rule-flag");
  const labelsEl = document.getElementById("rule-labels");

  const value = (valueEl?.value ?? "").trim();
  if (!value) { ruleError(new Error("条件的关键词不能空着")); return; }

  const conditions = [{ field: fieldEl.value, op: opEl.value, value }];
  const actions = [];
  if (moveEl?.value) actions.push({ kind: "move", folder_id: Number(moveEl.value) });
  if (readEl?.checked) actions.push({ kind: "mark_read" });
  if (flagEl?.checked) actions.push({ kind: "mark_flagged" });
  const labels = (labelsEl?.value ?? "").split(/[,，、\s]+/).map((s) => s.trim()).filter(Boolean);
  if (labels.length > 0) actions.push({ kind: "add_labels", labels });

  if (actions.length === 0) { ruleError(new Error("至少选一个动作")); return; }

  const fieldName = RULE_FIELDS.find(([v]) => v === fieldEl.value)?.[1] ?? fieldEl.value;
  const opName = RULE_OPS.find(([v]) => v === opEl.value)?.[1] ?? opEl.value;
  const name = `${fieldName}${opName} ${value}`;

  try {
    await invoke("create_rule", { account_id: account.id, name, conditions, actions });
    state.ruleOp = false;
    renderSettings();
  } catch (err) {
    ruleError(err);
  }
}

async function toggleRule(r) {
  try {
    await invoke("set_rule_enabled", { rule_id: r.id, enabled: !r.enabled });
    renderSettings();
  } catch (err) {
    ruleError(err);
  }
}

async function deleteRule(r) {
  try {
    await invoke("delete_rule", { rule_id: r.id });
    renderSettings();
  } catch (err) {
    ruleError(err);
  }
}

// ================================================================= 中栏

/**
 * 读这个文件夹的列表行，并把中栏的标题/数量标上。
 *
 * 草稿箱看的是**本地**草稿，不是 IMAP 上那个文件夹。两回事：IMAP 的草稿箱是
 * 服务器上已存的信，本地草稿是撰写窗口自动保存的那些（可能还没上传过）。
 * M2 先只做后者 —— 前者要等 APPEND 那条链路。
 */
async function loadList(folder) {
  const isDrafts = folder?.kind === "drafts";
  if (isDrafts) {
    state.messages = [];
    state.drafts = await invoke("list_drafts", { account_id: state.account.id });
  } else {
    state.drafts = [];
    state.messages = folder
      ? await invoke("list_messages", { folder_id: folder.id, limit: 500, offset: 0 })
      : [];
  }
  document.getElementById("list-title").textContent = folder ? folder.display_name : "邮件";
  updateListCount();
}

/**
 * 列表头的「N 封 · M 未读」计数和「全标已读」按钮。
 *
 * 草稿箱不算未读（草稿没有「读没读」这回事）；搜索模式下结果跨文件夹，
 * 「全标已读」没有单一目标，所以藏起来。
 */
// ================================================================ 多选 / 右键菜单

/** 多选模式开关。退出时清空选择。 */
function toggleSelectMode() {
  state.selectMode = !state.selectMode;
  if (!state.selectMode) state.selected.clear();
  repaintList();
  renderSelectBar();
}

/** 选中操作条（列表头上方）：全选/反选 + 批量动作 + 取消。 */
function renderSelectBar() {
  const bar = document.getElementById("select-bar");
  if (!bar) return;
  clear(bar);
  const btn = document.getElementById("btn-select");
  if (btn) btn.textContent = state.selectMode ? "退出多选" : "多选";
  if (!state.selectMode) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  const n = state.selected.size;
  // 注意：node() 不跳过 false —— disabled: false 会被 setAttribute 变成真禁用
  const act = (text, fn, danger) =>
    node("button", {
      class: danger ? "btn btn-danger" : "btn",
      type: "button",
      text,
      ...(n === 0 ? { disabled: true } : {}),
      onclick: fn,
    });
  bar.append(
    node("span", { class: "sel-count", text: n > 0 ? `已选 ${n} 项` : "点选邮件" }),
    node("button", { class: "btn", type: "button", text: "全选", onclick: selectAll }),
    node("button", { class: "btn", type: "button", text: "反选", onclick: invertSelect }),
    node("span", { class: "sel-sep" }),
    act("标为已读", () => batchMark(true)),
    act("标星", () => batchStar(true)),
    act("删除", batchDelete, true),
    act("移动 ▾", batchMoveMenu),
  );
}

function togglePick(t) {
  if (state.selected.has(t.key)) state.selected.delete(t.key);
  else state.selected.add(t.key);
  repaintList();
  renderSelectBar();
}

function selectAll() {
  for (const t of groupIntoThreads(state.messages)) state.selected.add(t.key);
  repaintList();
  renderSelectBar();
}

function invertSelect() {
  const cur = new Set(state.selected);
  state.selected.clear();
  for (const t of groupIntoThreads(state.messages)) {
    if (!cur.has(t.key)) state.selected.add(t.key);
  }
  repaintList();
  renderSelectBar();
}

/** 选中的 thread key → 全部 message id（动作作用到每一封信）。 */
function selectedMessageIds() {
  const keys = state.selected;
  return groupIntoThreads(state.messages)
    .filter((t) => keys.has(t.key))
    .flatMap((t) => t.messages.map((x) => x.id));
}

/** 批量改标志：本地 立刻刷，服务器由后端按箱批量 UID STORE。 */
async function batchSetFlags(seen, flagged) {
  const ids = selectedMessageIds();
  if (ids.length === 0) return;
  try {
    await invoke("batch_set_flags", { message_ids: ids, seen: seen ?? null, flagged: flagged ?? null });
    for (const m of state.messages) {
      if (ids.includes(m.id)) {
        if (seen != null) m.flags.seen = seen;
        if (flagged != null) m.flags.flagged = flagged;
      }
    }
    toast(seen != null ? `已标为${seen ? "已读" : "未读"} ${ids.length} 封` : `已标星 ${ids.length} 封`);
    state.selected.clear();
    repaintList();
    updateListCount();
    renderSelectBar();
    renderReader();
  } catch (err) {
    toast(`操作失败：${err instanceof Error ? err.message : err}`);
  }
}

const batchMark = (seen) => batchSetFlags(seen, null);
const batchStar = (flagged) => batchSetFlags(null, flagged);

/** 批量删除（去废纸篓；POP3 账号删本地行）。 */
async function batchDelete() {
  const ids = selectedMessageIds();
  if (ids.length === 0) return;
  try {
    await invoke("batch_delete", { message_ids: ids, permanent: false });
    state.messages = state.messages.filter((m) => !ids.includes(m.id));
    toast(`已删除 ${ids.length} 封`);
    state.selected.clear();
    repaintList();
    updateListCount();
    renderSelectBar();
    renderReader();
  } catch (err) {
    toast(`删除失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 批量移动：弹出文件夹选单。 */
function batchMoveMenu(e) {
  const ids = selectedMessageIds();
  if (ids.length === 0) return;
  const targets = (state.folders || []).filter((f) => f.id !== 0);
  openMoveMenu(e, async (toId) => {
    try {
      await invoke("batch_move", { message_ids: ids, to_folder_id: toId });
      state.messages = state.messages.filter((m) => !ids.includes(m.id));
      toast(`已挪动 ${ids.length} 封`);
      state.selected.clear();
      repaintList();
      updateListCount();
      renderSelectBar();
      renderReader();
    } catch (err) {
      toast(`挪箱失败：${err instanceof Error ? err.message : err}`);
    }
  }, targets);
}

/** 关掉所有浮层菜单：右键浮层 + **内联下拉**（自绘 select/⋯/插入/厂商…）+ 阅读页更多。
 *  开新菜单前先清场；document 点外也走这里（下拉失焦不收的老问题）。 */
function closeAllMenus() {
  closeFolderCtx();
  closeMore();
  document.querySelectorAll(".menu-overlay").forEach((el) => el.remove());
  document.querySelectorAll(".more-menu").forEach((m) => {
    m.hidden = true;
  });
  document.querySelectorAll('[aria-haspopup="true"]').forEach((b) => {
    b.setAttribute("aria-expanded", "false");
  });
}

// 点**外面**任何地方收起全部浮层。toggle 按钮自己 stopPropagation / 带
// aria-haspopup，菜单内点击不冒泡 —— 都跳过，交给各自处理器。
document.addEventListener("click", (e) => {
  const t = e.target;
  if (t && t.closest && t.closest(".more-menu, .more-wrap, .menu-overlay, [aria-haspopup]")) return;
  closeAllMenus();
});

/** 文件夹选单浮层（批量移动 / 右键「移动」共用）。 */
function openMoveMenu(e, onPick, targets) {
  closeAllMenus();
  const overlay = node("div", { class: "menu-overlay", role: "presentation" });
  overlay.addEventListener("mousedown", (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
  const menu = node("div", { class: "more-menu is-fixed", role: "menu" });
  menu.addEventListener("click", (ev) => ev.stopPropagation());
  if (targets.length === 0) {
    menu.append(node("div", { class: "more-item is-off", text: "没有可挪到的文件夹" }));
  } else {
    for (const f of targets) {
      menu.append(node("button", {
        class: "more-item", type: "button", role: "menuitem",
        text: `挪到「${f.display_name}」`,
        onclick: () => {
          overlay.remove();
          onPick(f.id);
        },
      }));
    }
  }
  menu.style.right = "auto";
  menu.style.left = `${Math.max(8, Math.min(e.clientX ?? window.innerWidth - 220, window.innerWidth - 190))}px`;
  menu.style.top = `${Math.max(8, Math.min(e.clientY ?? 160, window.innerHeight - 150))}px`;
  overlay.append(menu);
  document.body.append(overlay);
}

// --------------------------------------------------------------- 行右键菜单

/** 邮件右键菜单（对齐网易邮箱大师）：回复/转发、置顶/已读/星标、移动、删除。 */
function openMessageCtxMenu(e, t) {
  e.preventDefault();
  e.stopPropagation();
  closeAllMenus();
  const m = t.latest;
  const unread = t.messages.some((x) => !x.flags.seen);
  const ids = t.messages.map((x) => x.id);
  const overlay = node("div", { class: "menu-overlay", role: "presentation" });
  overlay.addEventListener("mousedown", (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
  const menu = node("div", { class: "more-menu is-fixed", role: "menu" });
  menu.addEventListener("click", (ev) => ev.stopPropagation());
  const item = (text, fn, danger, id) =>
    node("button", {
      class: danger ? "more-item is-danger" : "more-item",
      type: "button",
      role: "menuitem",
      text,
      ...(id ? { id } : {}),
      onclick: () => fn(),
    });

  menu.append(
    item("回复", () => { overlay.remove(); composeFromMessage(m.id, "reply"); }),
    item("回复全部", () => { overlay.remove(); composeFromMessage(m.id, "replyAll"); }),
    item("转发", () => { overlay.remove(); composeFromMessage(m.id, "forward"); }),
    node("div", { class: "more-sep" }),
    item(m.pinned ? "取消置顶" : "置顶", () => { overlay.remove(); togglePin(m.id); }),
    item(unread ? "标为已读" : "标为未读", () => {
      overlay.remove();
      quickMarkRead(t, unread);
    }),
    item(m.flags.flagged ? "取消标星" : "标星", () => { overlay.remove(); toggleFlag(m.id); }),
    node("div", { class: "more-sep" }),
    item("移动 ▸", () => {
      // 二级：换成文件夹选单（同一个浮层换内容）
      clear(menu);
      menu.append(
        item("◂ 返回", () => {
          clear(menu);
          menu.append(...buildItems());
        }),
        node("div", { class: "more-sep" }),
      );
      const targets = (state.folders || []).filter((f) => f.id !== 0 && f.id !== m.folder_id);
      if (targets.length === 0) {
        menu.append(node("div", { class: "more-item is-off", text: "没有可挪到的文件夹" }));
      } else {
        for (const f of targets) {
          menu.append(item(`挪到「${f.display_name}」`, async () => {
            overlay.remove();
            try {
              await invoke("batch_move", { message_ids: ids, to_folder_id: f.id });
              state.messages = state.messages.filter((x) => !ids.includes(x.id));
              repaintList();
              updateListCount();
              renderReader();
              toast(`已挪到「${f.display_name}」`);
            } catch (err) {
              toast(`挪箱失败：${err instanceof Error ? err.message : err}`);
            }
          }));
        }
      }
    }),
    node("div", { class: "more-sep" }),
    item("删除", () => {
      overlay.remove();
      batchDeleteIds(ids);
    }),
    item("彻底删除", () => {
      // 两步确认：第一下变文案，第二下真删
      const btn = menu.querySelector("#ctx-purge");
      if (btn.dataset.armed !== "1") {
        btn.dataset.armed = "1";
        btn.textContent = "再点一次确认彻底删除";
        return;
      }
      overlay.remove();
      purgeIds(ids);
    }, true, "ctx-purge"),
    node("div", { class: "more-sep" }),
    item("导出邮件", () => {
      overlay.remove();
      exportMessage(m.id);
    }),
    item("按发件人搜索", () => {
      overlay.remove();
      const addr = m.from?.[0]?.address || "";
      if (addr) runSearch(addr);
    }),
  );

  // 供「移动 ▸」的返回用（重建一级项）
  function buildItems() {
    // 简化：返回时重新打开整个菜单最省事
    setTimeout(() => {
      overlay.remove();
      openMessageCtxMenu(
        { preventDefault() {}, stopPropagation() {}, clientX: e.clientX, clientY: e.clientY },
        t,
      );
    }, 0);
    return [];
  }

  menu.style.right = "auto";
  overlay.append(menu);
  document.body.append(overlay);
  placeMenuAt(menu, e.clientX, e.clientY);
}

/** 从列表行发起 回复/回复全部/转发（先取详情再开撰写窗）。 */
async function composeFromMessage(messageId, mode) {
  try {
    const d = await invoke("open_message", { message_id: messageId });
    const account = state.accounts.find((a) => a.id === d.summary.account_id) || state.account;
    openCompose({ account, replyMode: mode, source: d });
  } catch (err) {
    toast(`打开失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 批量删除（右键菜单用；本地删行 + 后端批量推）。 */
async function batchDeleteIds(ids) {
  if (ids.length === 0) return;
  try {
    await invoke("batch_delete", { message_ids: ids, permanent: false });
    state.messages = state.messages.filter((m) => !ids.includes(m.id));
    repaintList();
    updateListCount();
    renderReader();
    toast(`已删除 ${ids.length} 封`);
  } catch (err) {
    toast(`删除失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 彻底删除（已两步确认）。 */
async function purgeIds(ids) {
  if (ids.length === 0) return;
  try {
    await invoke("batch_delete", { message_ids: ids, permanent: true });
    state.messages = state.messages.filter((m) => !ids.includes(m.id));
    repaintList();
    updateListCount();
    renderReader();
    toast(`已彻底删除 ${ids.length} 封`);
  } catch (err) {
    toast(`删除失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 导出 .eml 到下载目录。 */
async function exportMessage(messageId) {
  try {
    const path = await invoke("export_message", { message_id: messageId });
    toast(`已导出到 ${path}`);
  } catch (err) {
    toast(`导出失败：${err instanceof Error ? err.message : err}`);
  }
}

function updateListCount() {
  const el = document.getElementById("list-count");
  const readAll = document.getElementById("btn-read-all");
  const isDrafts = state.smart?.isDrafts || state.folders.find((f) => f.id === state.folderId)?.kind === "drafts";
  const n = isDrafts ? state.drafts.length : state.messages.length;
  const unread = isDrafts ? 0 : state.messages.filter((m) => !m.flags.seen).length;
  if (el) el.textContent = n > 0 ? (unread > 0 ? `${n} 封 · ${unread} 未读` : `${n} 封`) : "";
  // 「全标已读」是文件夹动作；智能箱/搜索没有单一目标，藏起来
  const isFolderView = state.folderId != null && !state.smart;
  if (readAll) {
    readAll.hidden = unread === 0 || !!state.searchQuery || !isFolderView;
    readAll.disabled = unread === 0;
  }
}

/** 轻量状态提示（写进列表头的 `sync-status`）。不弹窗、不抢焦点。 */
function statusNote(msg) {
  toast(msg);
}

/** 浮动 toast（右下角，自动消失）。状态类提示统一走这里。 */
function toast(msg) {
  let wrap = document.querySelector(".toast-wrap");
  if (!wrap) {
    wrap = node("div", { class: "toast-wrap", "aria-live": "polite" });
    document.body.append(wrap);
  }
  const t = node("div", { class: "toast", text: msg });
  wrap.append(t);
  setTimeout(() => {
    t.classList.add("is-out");
    setTimeout(() => t.remove(), 320);
  }, 2800);
}

async function selectFolder(folderId) {
  resetSelect();
  // 点的是别的账号的文件夹 → 先切到那个账号（撰写/回复才用对的账号）
  const folder = state.allFolders.find((f) => f.id === folderId);
  if (folder && (!state.account || state.account.id !== folder.account_id)) {
    const acc = state.accounts.find((a) => a.id === folder.account_id);
    if (acc) {
      await refreshSidebarData();
      state.account = acc;
      state.folders = withDraftsFolder(
        state.allFolders.filter((f) => f.account_id === acc.id && f.id !== 0),
      );
      renderAccount();
    }
  }
  state.folderId = folderId;
  state.smart = null;
  state.activeKey = `folder:${folderId}`;
  state.unreadOnly = false;
  // 点文件夹 = 回到「这一箱」的信。搜索是跨文件夹的，留着不放会让人
  // 以为搜出来的就是这一箱的内容。
  state.searchQuery = "";
  const searchBox = document.getElementById("search-box");
  if (searchBox) searchBox.value = "";

  await loadList(folder);
  renderSidebar();
  repaintList();

  // 换文件夹就回到空阅读视图，别让人看着上一封的正文以为那是这一箱的
  state.messageId = null;
  state.detail = null;
  renderReader();
  document.querySelector(".shell")?.classList.remove("is-reading");
}

/**
 * 搜索。跨文件夹、纯本地（搜的是已经收下来的缓存，不连服务器）。
 *
 * 结果就放在 `state.messages` 里 —— 行的渲染、点开、标已读全都复用
 * 列表那套，不给搜索结果单写一份。`state.searchQuery` 非空是「现在显示
 * 的是搜索结果」的唯一记号，`repaintList` 靠它分辨。
 */
async function runSearch(query) {
  if (!state.account) return;
  const q = query.trim();
  if (!q) {
    // 空查询不是「什么都匹配」，是「退出搜索」
    await exitSearch();
    return;
  }
  try {
    const results = await invoke("search_messages", {
      account_id: state.account.id,
      query: q,
      limit: 200,
    });
    state.searchQuery = q;
    state.messages = results;
    state.messageId = null;
    state.detail = null;
    document.getElementById("list-title").textContent = `搜索：${q}`;
    updateListCount();
    renderMessageList(results, `没有找到「${q}」`);
    renderReader();
    document.querySelector(".shell")?.classList.remove("is-reading");
  } catch (err) {
    renderMessageList([], `搜索失败：${err instanceof Error ? err.message : err}`);
  }
}

/// 退出搜索，回当前文件夹的列表。
async function exitSearch() {
  const searchBox = document.getElementById("search-box");
  const hadQuery = state.searchQuery;
  state.searchQuery = "";
  if (searchBox) searchBox.value = "";
  // 连搜索都没进过：只是把没按回车的输入清掉，列表本来就是文件夹的
  if (!hadQuery) return;
  const folder = state.folders.find((f) => f.id === state.folderId);
  await loadList(folder);
  repaintList();
}

function renderDraftList() {
  const box = clear(document.getElementById("messages"));
  if (state.drafts.length === 0) {
    box.append(node("p", { class: "empty", text: "没有草稿" }));
    return;
  }
  for (const d of state.drafts) {
    box.append(renderDraftRow(d));
  }
}

function renderDraftRow(d) {
  return node(
    "button",
    {
      class: "row row-draft",
      type: "button",
      role: "listitem",
      onclick: () => {
        const acc = d._account || state.accounts.find((a) => a.id === d.account_id) || state.account;
        openCompose({ account: acc, draftId: d.id });
      },
    },
    node("span", { class: "avatar avatar-draft", "aria-hidden": "true", text: "✎" }),
    node(
      "div",
      { class: "row-main" },
      node(
        "div",
        { class: "row-l1" },
        node("span", { class: "dot is-off", "aria-hidden": "true" }),
        node("span", { class: "from", text: d.to.length ? `致 ${fmtAddr(d.to)}` : "（没写收件人）" }),
      ),
      node("span", { class: "subject", text: d.subject || "（无主题）" }),
      node(
        "div",
        { class: "row-l3" },
        node("span", { class: "preview", text: "草稿" }),
        node(
          "span",
          { class: "row-status" },
          d.attachment_count > 0 ? node("span", { class: "ic", text: `${d.attachment_count} 附件` }) : null,
        ),
        node("span", { class: "date", text: fmtRowDate(d.updated_at) }),
      ),
    ),
  );
}

function composeNew() {
  if (!state.account) return;
  openCompose({ account: state.account });
}

function renderMessageList(list, emptyText = "这个文件夹是空的") {
  const box = clear(document.getElementById("messages"));
  const shown = state.unreadOnly ? list.filter((m) => !m.flags.seen) : list;
  if (shown.length === 0) {
    box.append(node("p", { class: "empty", text: state.unreadOnly ? "没有未读邮件" : emptyText }));
    return;
  }
  // 会话/主题聚合：同 thread_key 的信折成一条（参考图 4 的计数徽标）。
  for (const t of groupIntoThreads(shown)) {
    box.append(renderThreadRow(t));
  }
}

/**
 * 按 `thread_key`（主题归一，见 `thread.rs`）把信聚成会话。
 * 每个会话：代表信 = 最新那封，`count` = 封数，`messages` = 全体（按时间正序）。
 */
function groupIntoThreads(list) {
  // 关了「按主题聚合」就每封自成一条（设置页可切）。
  if (state.settings?.thread_aggregate === "off") {
    return list.map((m) => ({ key: m.thread_key || String(m.id), count: 1, latest: m, messages: [m] }));
  }
  const map = new Map();
  for (const m of list) {
    const key = m.thread_key || m.subject || String(m.id);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(m);
  }
  const threads = [...map.values()].map((msgs) => {
    msgs.sort((a, b) => new Date(a.date || a.received_at) - new Date(b.date || b.received_at));
    return { key: msgs[0].thread_key, count: msgs.length, latest: msgs[msgs.length - 1], messages: msgs };
  });
  threads.sort((a, b) => new Date(b.latest.date || b.latest.received_at) - new Date(a.latest.date || a.latest.received_at));
  return threads;
}

/** 一条会话行（代表信 + 封数徽标）。多封时徽标标出聚合数。 */
function renderThreadRow(t) {
  const m = t.latest;
  const unread = t.messages.some((x) => !x.flags.seen);
  const sel =
    (state.thread && state.thread.key === t.key) ||
    (state.messageId != null && t.messages.some((x) => x.id === state.messageId));
  const picked = state.selectMode && state.selected.has(t.key);
  return node(
    "button",
    {
      class: `row${unread ? " is-unread" : ""}${sel ? " is-sel" : ""}${picked ? " is-picked" : ""}`,
      type: "button",
      role: "listitem",
      "aria-current": sel ? "true" : "false",
      onclick: () => {
        // 多选模式：点行 = 勾选/取消，不打开
        if (state.selectMode) {
          togglePick(t);
          return;
        }
        openMessage(m.id);
      },
      oncontextmenu: (e) => openMessageCtxMenu(e, t),
    },
    state.selectMode
      ? node("span", { class: `row-pick${picked ? " is-on" : ""}`, "aria-hidden": "true", text: picked ? "✓" : "" })
      : null,
    renderAvatar(m.from?.[0] ?? {}),
    node(
      "div",
      { class: "row-main" },
      node(
        "div",
        { class: "row-l1" },
        node("span", { class: `dot${unread ? "" : " is-off"}`, "aria-hidden": "true" }),
        node("span", { class: "from", text: fmtSender(m.from[0] ?? {}) }),
        m.thread_count > 1 ? node("span", { class: "thread-count", text: String(m.thread_count) }) : null,
      ),
      node("span", { class: "subject", text: m.subject || "（无主题）" }),
      node(
        "div",
        { class: "row-l3" },
        node("span", { class: "preview", text: m.preview || "" }),
        node(
          "span",
          { class: "row-status" },
          ...m.labels.map((l) => node("span", { class: "tag", text: l })),
          m.has_attachments ? node("span", { class: "ic", text: "附件" }) : null,
          m.flags.flagged ? node("span", { class: "ic ic-star", text: "★" }) : null,
          m.pinned ? node("span", { class: "ic ic-pin", text: "📌" }) : null,
        ),
        node("span", { class: "date", text: fmtRowDate(m.date || m.received_at) }),
      ),
    ),
    // 快速已读/未读：不打开邮件就改标志（会话整会话一起），并推回服务器。
    node("span", {
      class: `row-quick${unread ? "" : " is-seen"}`,
      role: "button",
      tabindex: "0",
      title: unread ? "标为已读（同步到服务器）" : "标为未读（同步到服务器）",
      "aria-label": unread ? "标为已读" : "标为未读",
      text: unread ? "✓" : "○",
      onclick: (e) => {
        e.stopPropagation();
        e.preventDefault();
        // 有未读 → 全标已读；全已读 → 全标未读（会话整会话一起）
        quickMarkRead(t, unread);
      },
    }),
  );
}

/** 快速已读/未读：不打开邮件就改标志。会话行整会话一起改；
 *  每封都走 `set_message_flags`（后台线程推回 IMAP 服务器）。 */
async function quickMarkRead(thread, seen) {
  const targets = thread.messages.filter((x) => x.flags.seen !== seen);
  if (targets.length === 0) return;
  for (const x of targets) {
    const flags = { ...x.flags, seen };
    await invoke("set_message_flags", { message_id: x.id, flags });
    x.flags = flags;
    const row = state.messages.find((y) => y.id === x.id);
    if (row) row.flags = flags;
    if (state.detail && state.detail.summary.id === x.id) state.detail.summary.flags = flags;
  }
  repaintList();
  updateListCount();
  if (state.detail && targets.some((x) => x.id === state.detail.summary.id)) renderReader();
}

/** 列表头筛选图标：只看未读 / 看全部。就地切 class，不重画整个头部。 */
function toggleFilter(btn) {
  state.unreadOnly = !state.unreadOnly;
  btn.setAttribute("aria-pressed", state.unreadOnly ? "true" : "false");
  btn.classList.toggle("is-on", state.unreadOnly);
  repaintList();
}

/**
 * 发件人头像：取名字首字，配色由发件人确定性哈希到几个预设里挑一个。
 * 配色走 CSS class（`avatar-c0..7`），不写内联 style —— CSP 的 `style-src`
 * 只有 `'self'`，内联背景会被浏览器拒掉（见 app.css 顶部约定）。
 */
function renderAvatar(mailbox) {
  // 关了「显示头像」就给个素圈占位。
  if (state.settings?.show_avatars === "off") {
    return node("span", { class: "avatar avatar-none", "aria-hidden": "true" });
  }
  const name = mailbox?.display || mailbox?.address || "";
  const ch = name.trim().charAt(0).toUpperCase() || "?";
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return node("span", { class: `avatar avatar-c${h % 8}`, "aria-hidden": "true", text: ch });
}

function repaintList() {
  // 搜索模式：`messages` 里是搜索结果，跟当前文件夹（可能还是草稿箱）无关
  if (state.searchQuery) {
    renderMessageList(state.messages, `没有找到「${state.searchQuery}」`);
    return;
  }
  // 看当前文件夹是什么，别看「草稿数组里有没有东西」—— 空草稿箱也得显示空列表
  const isDrafts = state.smart?.isDrafts || state.folders.find((f) => f.id === state.folderId)?.kind === "drafts";
  if (isDrafts) renderDraftList();
  else renderMessageList(state.messages);
  renderSelectBar();
}

/** 换视图/换文件夹时退出多选（选择不该跨视图残留）。 */
function resetSelect() {
  state.selectMode = false;
  state.selected.clear();
}

// ================================================================= 右栏

async function openMessage(messageId) {
  state.messageId = messageId;
  repaintList();
  document.querySelector(".shell")?.classList.add("is-reading");

  const reader = clear(document.getElementById("reader"));
  reader.append(node("p", { class: "empty", text: "加载中…" }));

  try {
    const detail = await invoke("open_message", { message_id: messageId });
    state.detail = detail;

    // 打开就算读。用户点了才改，不在列表预取时偷偷置已读。
    if (!detail.summary.flags.seen) {
      const flags = { ...detail.summary.flags, seen: true };
      await invoke("set_message_flags", { message_id: messageId, flags });
      const row = state.messages.find((x) => x.id === messageId);
      if (row) row.flags = flags;
      detail.summary.flags = flags;
      repaintList();
    }

    // 加载会话（同 thread_key，跨文件夹）—— 阅读页把同话题的信堆一起。
    const tk = detail.summary.thread_key;
    const acc = detail.summary.account_id;
    let members = [detail.summary];
    if (tk != null && tk !== "" && acc != null) {
      try {
        const threadMsgs = await invoke("thread_messages", { account_id: acc, thread_key: tk });
        if (threadMsgs.length > 0) members = threadMsgs;
      } catch {
        /* 会话拉不到就退化成单封 */
      }
    }
    state.thread = { key: tk, messages: members };
    renderReader();
  } catch (err) {
    clear(reader).append(
      node("p", { class: "error" }, `打不开这封邮件：${err instanceof Error ? err.message : err}`),
    );
  }
}

/** 等一帧再干活：把 busy DOM 先画上屏，再发网络请求。
 *  （后端已改 spawn_blocking 不堵主线程，这里是双保险 —— WebKitGTK 里
 *  同任务内的 DOM 改动偶尔要一个合成帧才落屏。） */
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => r()));

/** 邮件里的链接：在系统浏览器里打开（后端有 scheme 白名单）。 */
async function openExternal(url) {
  try {
    await invoke("open_external_url", { url });
    statusNote("已在浏览器里打开链接");
  } catch (err) {
    statusNote(String(err instanceof Error ? err.message : err));
  }
}

function renderReader() {
  const reader = clear(document.getElementById("reader"));
  const title = document.getElementById("reader-title");

  const msgs = state.thread?.messages?.length
    ? state.thread.messages
    : state.detail
      ? [state.detail.summary]
      : [];
  const active = state.detail;
  if (!active && msgs.length === 0) {
    title.textContent = "阅读";
    reader.append(node("p", { class: "empty" }, "左侧选一封邮件开始阅读。"));
    return;
  }

  const subject = active?.summary.subject || msgs[0]?.subject || "（无主题）";
  title.textContent = subject;

  // 读信工具条（作用于当前展开的那封）：回复 / 回复全部 / 转发 / 删除 / 置顶 / 整理 / 更多▾
  if (active) reader.append(renderReaderActions(active.summary));

  // 会话：主题 + 堆叠的信（参考图 5/6）。单封时就是一条展开卡。
  reader.append(node("h1", { class: "mail-subject", text: subject }));
  const stack = node("div", { class: "thread-stack", role: "list" });
  for (const m of msgs) {
    const isActive = active && m.id === active.summary.id;
    stack.append(isActive ? renderActiveItem(active) : renderCollapsedItem(m));
  }
  reader.append(stack);
}

/** 展开的那封：信头卡片 + 标签 + 远程图横幅 + 正文 + 附件。 */
function renderActiveItem(d) {
  const s = d.summary;
  return node(
    "div",
    { class: "thread-item is-open", role: "listitem" },
    renderMsgHead(d),
    renderMarkTools(s),
    // 远程图片横幅
    d.remote_image_count > 0 ? (() => {
      const allowed = d.remote_policy !== "block";
      return node(
        "div",
        { class: `banner${allowed ? " is-done" : ""}` },
        node("span", {
          text: allowed
            ? `已显示这封邮件里的 ${d.remote_image_count} 张远程图片。`
            : `这封邮件包含 ${d.remote_image_count} 张远程图片，已拦截。`,
        }),
        allowed ? null : node("button", { type: "button", text: "显示图片", onclick: showRemoteImages }),
      );
    })() : null,
    // 正文 —— 唯一的 innerHTML。链接点击不开在 webview 里：拦下来交给
    // 系统浏览器（正文是不可信输入，scheme 另有后端白名单把关）。
    (() => {
      const body = node("div", { class: `mail-body${d.body_kind === "plain" ? " is-plain" : ""}` });
      if (d.body_html && d.body_kind !== "plain") body.innerHTML = d.body_html;
      else if (d.body_text) body.textContent = d.body_text;
      else body.append(node("p", { class: "empty", text: "（这封邮件没有正文）" }));
      body.addEventListener("click", (e) => {
        const a = e.target instanceof Element ? e.target.closest("a[href]") : null;
        if (!a || !body.contains(a)) return;
        e.preventDefault(); // 别让 webview 导航走丢
        openExternal(String(a.getAttribute("href") || ""));
      });
      return body;
    })(),
    // 附件
    (() => {
      const real = d.attachments.filter((a) => !a.inline);
      return real.length > 0
        ? node(
            "section",
            { class: "mail-attachments" },
            node("h2", { text: `附件 ${real.length}` }),
            real.map((a) =>
              node(
                "div",
                { class: "attach" },
                node("span", { class: "name", text: a.filename || "（未命名）" }),
                node("span", { class: "meta", text: `${a.mime_type} · ${fmtSize(a.size)}` }),
                node("button", {
                  class: "btn attach-save", type: "button", text: "保存",
                  title: "保存到本机「下载」目录",
                  onclick: () => saveAttachment(d.summary.id, a.id),
                }),
              ),
            ),
          )
        : null;
    })(),
  );
}

/** 保存附件到本机「下载」目录（文件名由后端消毒）。 */
async function saveAttachment(messageId, attachmentId) {
  try {
    const path = await invoke("save_attachment", { message_id: messageId, attachment_id: attachmentId });
    toast(`已保存到 ${path}`);
  } catch (err) {
    toast(`保存失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 折叠的那封（会话里未展开）：头像 + 发件人 + 日期 + 摘要，点击展开。 */
function renderCollapsedItem(m) {
  return node(
    "button",
    {
      class: "thread-item",
      type: "button",
      role: "listitem",
      onclick: () => openMessage(m.id),
    },
    renderAvatar(m.from?.[0] ?? {}),
    node(
      "div",
      { class: "thread-item-main" },
      node(
        "div",
        { class: "thread-item-top" },
        node("span", { class: "from", text: fmtSender(m.from[0] ?? {}) }),
        node("span", { class: "date", text: fmtFullDate(m.date || m.received_at) }),
      ),
      node("span", { class: "preview", text: m.preview || m.subject || "（无正文）" }),
    ),
    node("span", { class: "thread-badge", text: "›" }),
  );
}

/**
 * 阅读页信头卡片：头像 + 发件人 + 日期 +「发至 …」+「详情」（展开原始头）。
 * 若这封是「代发」（Sender 头跟 From 不是一路），补一行「此邮件由 … 代发」。
 */
function renderMsgHead(d) {
  const s = d.summary;
  const card = node(
    "div",
    { class: "msg-card" },
    renderAvatar(s.from?.[0] ?? {}),
    node(
      "div",
      { class: "msg-meta" },
      node(
        "div",
        { class: "msg-l1" },
        node("span", { class: "msg-sender", text: fmtSender(s.from[0] ?? {}) }),
        node("span", { class: "msg-date", text: fmtFullDate(s.date) }),
      ),
      node(
        "div",
        { class: "msg-l2" },
        node("span", { text: `发至 ${fmtAddr(s.to)}` }),
        d.cc.length ? node("span", { class: "msg-cc", text: `，抄送 ${fmtAddr(d.cc)}` }) : null,
        d.reply_to.length ? node("span", { class: "msg-cc", text: `，回复至 ${fmtAddr(d.reply_to)}` }) : null,
      ),
    ),
    node(
      "div",
      { class: "msg-side" },
      node("button", {
        class: "msg-details-btn",
        type: "button",
        text: "详情",
        onclick: (e) => {
          e.stopPropagation();
          const box = card.parentElement?.querySelector(".msg-details");
          if (!box) return;
          box.hidden = !box.hidden;
          e.currentTarget.textContent = box.hidden ? "详情" : "收起";
        },
      }),
    ),
  );

  // 「详情」展开：格式化字段（对齐网易邮箱大师），不甩原始代码。
  const hdr = (name) => (d.raw_headers.find(([k]) => k.toLowerCase() === name) || [])[1] || "";
  const fmtFull = (m) => (m?.display ? `${m.display} <${m.address}>` : m?.address || "");
  const drow = (label, value, mono) =>
    value
      ? node("div", { class: "msg-drow" },
          node("span", { class: "msg-dlabel", text: label }),
          node("span", { class: mono ? "msg-dvalue is-mono" : "msg-dvalue", text: value }),
        )
      : null;
  const details = node("div", { class: "msg-details", hidden: true },
    drow("发件人", fmtFull(s.from[0])),
    drow("收件人", fmtAddr(s.to)),
    d.cc.length ? drow("抄送", fmtAddr(d.cc)) : null,
    d.reply_to.length ? drow("回复至", fmtAddr(d.reply_to)) : null,
    drow("主题", s.subject),
    drow("时间", fmtFullDate(s.date)),
    drow("Message-ID", hdr("message-id"), true),
  );

  // 原始信头收进小折叠（排错参考，不默认展示）
  const raw = node("pre", {
    class: "msg-raw",
    hidden: true,
    text: d.raw_headers.map(([k, v]) => `${k}: ${v}`).join("\n"),
  });
  const rawBtn = node("button", {
    class: "msg-raw-btn", type: "button", text: "原始信头 ▾",
    onclick: () => {
      raw.hidden = !raw.hidden;
      rawBtn.textContent = raw.hidden ? "原始信头 ▾" : "原始信头 ▴";
    },
  });
  details.append(rawBtn, raw);

  // 代发：Sender 头跟 From 地址不是一路 → 提示一行
  const norm = (a) => (a || "").toLowerCase().replace(/[<>]/g, "").trim();
  const senderHdr = (d.raw_headers.find(([k]) => k.toLowerCase() === "sender") || [])[1] || "";
  const onBehalf =
    senderHdr && norm(senderHdr) !== norm(s.from[0]?.address)
      ? node("div", { class: "msg-onbehalf", text: `（此邮件由 ${senderHdr} 代发）` })
      : null;

  return node("div", { class: "msg-head" }, card, onBehalf, details);
}

async function showRemoteImages() {
  if (!state.messageId) return;
  try {
    await invoke("allow_remote_images", { message_id: state.messageId });
    await openMessage(state.messageId);
  } catch (err) {
    alert(`放行失败：${err instanceof Error ? err.message : err}`);
  }
}

// ------------------------------------------------------------- 读信工具条

/**
 * 阅读页顶部的操作条：回复 / 回复全部 / 转发 / 删除 / 置顶 / 更多▾。
 *
 * 「更多▾」是自定义下拉（不用 `<select>` —— WebKitGTK 弹层上下键失效、
 * Esc 关不掉，见已知限制）。里面的「彻底删除」是**两步确认**（再点一次），
 * 不用 `confirm()` —— WebKitGTK 弹窗抢焦点是 M0 踩过的坑。
 */
function renderReaderActions(s) {
  return node(
    "div",
    { class: "reader-actions", role: "toolbar", "aria-label": "阅读邮件操作" },
    node("button", {
      class: "ra-btn", type: "button", text: "↩ 回复",
      onclick: () => replyMessage("reply"),
    }),
    node("button", {
      class: "ra-btn", type: "button", text: "↩↩ 回复全部",
      onclick: () => replyMessage("replyAll"),
    }),
    node("button", {
      class: "ra-btn", type: "button", text: "→ 转发",
      onclick: () => replyMessage("forward"),
    }),
    node("button", {
      class: "ra-btn", type: "button", text: "🗑 删除", title: "移到废纸篓",
      onclick: () => deleteMessage(s.id, false),
    }),
    node("button", {
      class: `ra-btn${s.pinned ? " is-on" : ""}`, type: "button",
      "aria-pressed": s.pinned ? "true" : "false",
      text: s.pinned ? "📌 已置顶" : "📌 置顶",
      onclick: () => togglePin(s.id),
    }),
    node("button", {
      class: "ra-btn", type: "button", text: "🌐 译", title: "AI 翻译这封邮件",
      onclick: (e) => openTranslatePanel(e.currentTarget, s),
    }),
    organizeMenu(s),
    moreMenu(s),
  );
}

/** 读信「译」面板：快捷语言 + 厂商快切 + 译文 + 复制。 */
function openTranslatePanel(anchor, s) {
  closeAllMenus();
  if (openMore) closeMore();
  const overlay = node("div", { class: "menu-overlay", role: "presentation" });
  overlay.addEventListener("mousedown", (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
  const panel = node("div", { class: "more-menu translate-panel is-fixed", role: "dialog", "aria-label": "翻译" });
  panel.addEventListener("click", (ev) => ev.stopPropagation());

  const status = node("p", { class: "dialog-status", text: "" });
  const result = node("div", { class: "translate-result", text: "" });
  let cfg = null;
  let lastLang = null;

  const providerSel = customSelect(TRANSLATE_PROVIDERS.map(([id, name]) => [id, name]), "openai", async (v) => {
    // 厂商快切：带出默认地址/模型存好，再重翻
    const preset = TRANSLATE_PROVIDERS.find(([id]) => id === v);
    if (cfg && preset) {
      cfg = await invoke("save_translate_settings", {
        input: {
          provider: v,
          base_url: preset[2] || cfg.base_url,
          model: preset[3] || cfg.model,
          prompt: cfg.prompt,
          target: cfg.target,
          api_key: "",
          has_key: cfg.has_key,
        },
      });
    }
    if (lastLang) doTranslate(lastLang);
  });

  const langRow = node("div", { class: "translate-langs" },
    ...TRANSLATE_LANGS.map((l) =>
      node("button", {
        class: "subject-chip", type: "button", text: l,
        onclick: () => doTranslate(l),
      })),
  );

  async function doTranslate(lang) {
    lastLang = lang;
    const text = (state.detail?.body_text || "").trim();
    if (!text) {
      status.textContent = "这封信没有可翻译的文本";
      return;
    }
    status.textContent = `正在翻译为${lang}…`;
    status.classList.remove("is-error");
    try {
      if (!cfg) cfg = await invoke("get_translate_settings");
      if (!cfg.has_key) {
        status.textContent = "还没配置翻译 API —— 设置 → 翻译";
        status.classList.add("is-error");
        return;
      }
      providerSel.value = cfg.provider;
      const out = await invoke("translate_text", { text, target: lang });
      result.textContent = out;
      status.textContent = `已翻译为${lang}（${cfg.model}）`;
    } catch (err) {
      status.textContent = `翻译失败：${err instanceof Error ? err.message : err}`;
      status.classList.add("is-error");
    }
  }

  panel.append(
    node("div", { class: "translate-head" },
      node("strong", { text: "译为" }),
      providerSel.el,
    ),
    langRow,
    result,
    node("div", { class: "translate-foot" },
      status,
      node("button", {
        class: "btn btn-sm", type: "button", text: "复制译文",
        onclick: async () => {
          if (!result.textContent) return;
          try {
            await navigator.clipboard.writeText(result.textContent);
            status.textContent = "已复制";
          } catch {
            status.textContent = "复制失败（浏览器权限）";
          }
        },
      }),
    ),
  );

  // 贴按钮下方、不出屏（复用右键菜单的碰撞检测思路）
  overlay.append(panel);
  document.body.append(overlay);
  const r = anchor.getBoundingClientRect();
  const p = panel.getBoundingClientRect();
  let x = Math.max(8, Math.min(r.left, window.innerWidth - p.width - 8));
  let y = r.bottom + 6;
  if (y + p.height > window.innerHeight - 8) {
    y = Math.max(8, r.top - p.height - 6);
  }
  panel.style.left = `${Math.round(x)}px`;
  panel.style.top = `${Math.round(y)}px`;

  // 默认语种即点即翻
  (async () => {
    try {
      cfg = await invoke("get_translate_settings");
      providerSel.value = cfg.provider;
      doTranslate(cfg.target || "英语");
    } catch {
      status.textContent = "读取翻译设置失败";
    }
  })();
}

/** 「更多▾」下拉。全项目同一时刻只留一个开着的菜单（`openMore`）。 */
let openMore = null;
let permanentArmTimer = 0;

function moreMenu(s) {
  const sep = () => node("div", { class: "more-sep", role: "separator" });
  const off = (text) =>
    node("button", { class: "more-item is-off", type: "button", role: "menuitem", text, title: "后续版本", disabled: true });
  const menu = node(
    "div",
    { class: "more-menu", hidden: true, role: "menu" },
    off("作为附件转发"),
    sep(),
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text: "标为未读",
      onclick: (e) => { e.stopPropagation(); closeMore(); markUnread(s.id); },
    }),
    node("button", {
      class: "more-item", type: "button", role: "menuitem",
      text: s.flags.flagged ? "取消标星" : "标星",
      onclick: (e) => { e.stopPropagation(); closeMore(); toggleFlag(s.id); },
    }),
    sep(),
    off("这是推广邮件"),
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text: "标为垃圾邮件",
      onclick: (e) => { e.stopPropagation(); closeMore(); markJunk(s.id); },
    }),
    node("button", {
      class: "more-item is-danger", type: "button", role: "menuitem", text: "彻底删除",
      onclick: (e) => armPermanentDelete(e, s.id),
    }),
    sep(),
    off("翻译全文"),
    node("button", {
      class: "more-item", type: "button", role: "menuitem", text: "打印",
      onclick: (e) => { e.stopPropagation(); closeMore(); printMessage(); },
    }),
  );
  const btn = node("button", {
    class: "ra-btn", type: "button", "aria-haspopup": "true", "aria-expanded": "false",
    text: "⋯ 更多 ▾",
    onclick: (e) => {
      e.stopPropagation();
      if (openMore && openMore.menu === menu) closeMore();
      else showMore(btn, menu);
    },
  });
  return node("div", { class: "more-wrap" }, btn, menu);
}

/** 「整理」= 挪到另一个文件夹。列的是其它文件夹，点了就 `move_message`。 */
function organizeMenu(s) {
  const menu = node("div", { class: "more-menu", hidden: true, role: "menu" });
  const targets = state.folders.filter((f) => f.id !== 0 && f.id !== s.folder_id);
  if (targets.length === 0) {
    menu.append(node("div", { class: "more-item is-off", text: "没有可挪到的文件夹" }));
  } else {
    for (const f of targets) {
      menu.append(
        node("button", {
          class: "more-item", type: "button", role: "menuitem",
          text: `挪到「${f.display_name}」`,
          onclick: (e) => { e.stopPropagation(); closeMore(); moveMessage(s.id, f.id); },
        }),
      );
    }
  }
  const btn = node("button", {
    class: "ra-btn", type: "button", "aria-haspopup": "true", "aria-expanded": "false",
    text: "🗂 整理",
    onclick: (e) => {
      e.stopPropagation();
      if (openMore && openMore.menu === menu) closeMore();
      else showMore(btn, menu);
    },
  });
  return node("div", { class: "more-wrap" }, btn, menu);
}

/** 「整理」的动作：挪到目标文件夹（本地先删行，目标箱靠后台追平重出现）。 */
async function moveMessage(messageId, toFolderId) {
  try {
    await invoke("move_message", { message_id: messageId, to_folder_id: toFolderId });
    state.messages = state.messages.filter((m) => m.id !== messageId);
    if (state.messageId === messageId) {
      state.messageId = null;
      state.detail = null;
      document.querySelector(".shell")?.classList.remove("is-reading");
    }
    repaintList();
    renderReader();
    updateListCount();
    statusNote("已挪到目标文件夹");
  } catch (err) {
    statusNote(`挪箱失败：${err instanceof Error ? err.message : err}`);
  }
}

function showMore(btn, menu) {
  closeMore();
  menu.hidden = false;
  btn.setAttribute("aria-expanded", "true");
  // 用 `position: fixed` 贴到按钮下方：**逃出** `.reader` 的 overflow 裁剪和层叠上下文
  // —— WebKitGTK 里 absolute 在滚动容器内会被后画的正文压住，抬 z-index 不管用。
  // 坐标走 CSSOM：CSP `style-src 'self'` 管的是 `<style>`/`style=""`，不管
  // `el.style.x`（那是 CSSOM 操作，CSP 不拦）。设完向下不超过视口。
  const r = btn.getBoundingClientRect();
  menu.classList.add("is-fixed");
  menu.style.top = ""; // 先占位再量真实高，钳完再定 top（200px 是猜的，会裁）
  menu.style.right = `${Math.round(Math.max(8, window.innerWidth - r.right))}px`;
  const h = menu.getBoundingClientRect().height;
  menu.style.top = `${Math.round(Math.max(8, Math.min(r.bottom + 4, window.innerHeight - h - 8)))}px`;
  openMore = { btn, menu };
}

function closeMore() {
  if (!openMore) return;
  openMore.menu.hidden = true;
  openMore.menu.classList.remove("is-fixed");
  openMore.menu.style.top = "";
  openMore.menu.style.right = "";
  openMore.btn.setAttribute("aria-expanded", "false");
  // 「彻底删除」的两步状态随菜单关闭一起复位，别留个待命按钮在那里。
  clearTimeout(permanentArmTimer);
  const armed = openMore.menu.querySelector('[data-armed="1"]');
  if (armed) {
    armed.dataset.armed = "";
    armed.textContent = "彻底删除";
  }
  openMore = null;
}

/// 点菜单外任意处 = 关掉它。
document.addEventListener("click", () => closeMore());

/**
 * 彻底删除的**两步确认**：第一下就地换成「再点一次确认」并待命，第二下才真删。
 * 菜单在两步之间故意不关；3 秒没第二下就自动复位。`stopPropagation` 挡掉
 * 外面那个「点一下就关菜单」的监听，否则第一步就被关掉了。
 */
function armPermanentDelete(e, messageId) {
  e.stopPropagation();
  const btn = e.currentTarget;
  if (btn.dataset.armed === "1") {
    closeMore();
    deleteMessage(messageId, true);
    return;
  }
  btn.dataset.armed = "1";
  btn.textContent = "再点一次确认彻底删除";
  clearTimeout(permanentArmTimer);
  permanentArmTimer = setTimeout(() => {
    if (btn.isConnected && btn.dataset.armed === "1") {
      btn.dataset.armed = "";
      btn.textContent = "彻底删除";
    }
  }, 3000);
}

// ------------------------------------------------------------- 读信工具条动作

/** 回复 / 回复全部 / 转发：把当前这封信交给撰写窗预填。 */
function replyMessage(mode) {
  if (!state.account || !state.detail) return;
  openCompose({ account: state.account, replyMode: mode, source: state.detail });
}

/** 标为未读（会推回 IMAP）。 */
async function markUnread(messageId) {
  const row = state.messages.find((x) => x.id === messageId);
  const d = state.detail;
  const base = d && d.summary.id === messageId ? d.summary.flags : row?.flags;
  if (!base) return;
  const flags = { ...base, seen: false };
  await invoke("set_message_flags", { message_id: messageId, flags });
  if (row) row.flags = flags;
  if (d && d.summary.id === messageId) d.summary.flags = flags;
  repaintList();
  updateListCount();
  renderReader();
}

/** 删除：`permanent=false` 挪废纸篓，`=true` 彻底删（本地行都先删）。 */
async function deleteMessage(messageId, permanent) {
  try {
    await invoke("delete_message", { message_id: messageId, permanent });
    state.messages = state.messages.filter((m) => m.id !== messageId);
    if (state.messageId === messageId) {
      state.messageId = null;
      state.detail = null;
      document.querySelector(".shell")?.classList.remove("is-reading");
    }
    repaintList();
    renderReader();
    updateListCount();
    statusNote(permanent ? "已彻底删除" : "已移到废纸篓");
  } catch (err) {
    statusNote(`删除失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 列表头「全标已读」：一条 UPDATE 整箱标已读，推服务器放后台线程。 */
async function markAllRead() {
  if (!state.folderId || state.searchQuery) return;
  try {
    await invoke("mark_folder_read", { folder_id: state.folderId });
    for (const m of state.messages) m.flags = { ...m.flags, seen: true };
    if (state.detail) state.detail.summary.flags = { ...state.detail.summary.flags, seen: true };
    repaintList();
    renderReader();
    updateListCount();
  } catch (err) {
    statusNote(`标已读失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 标为垃圾邮件：挪到垃圾箱（`kind=junk`）。没有垃圾箱就提示。 */
async function markJunk(messageId) {
  const junk = state.allFolders.find((f) => f.kind === "junk" && f.id !== 0);
  if (!junk) {
    statusNote("这个账号没有垃圾邮件箱");
    return;
  }
  await moveMessage(messageId, junk.id);
}

/** 打印当前这封（`@media print` 只留正文，见 app.css）。 */
function printMessage() {
  window.print();
}

// ------------------------------------------------------------- 标签

/**
 * 阅读页信头底下的标签行（标星 / 置顶已挪进读信工具条，见 `renderReaderActions`）。
 */
function renderMarkTools(s) {
  const input = node("input", {
    class: "label-input",
    type: "text",
    placeholder: "加标签…",
    "aria-label": "新标签名",
    maxlength: "24",
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      addLabel(s.id, input);
    }
  });

  return node(
    "div",
    { class: "mark-tools", role: "group", "aria-label": "标签" },
    node(
      "span",
      { class: "label-chips" },
      ...s.labels.map((name) =>
        node(
          "span",
          { class: "chip" },
          node("span", { text: name }),
          node("button", {
            class: "chip-x",
            type: "button",
            text: "×",
            title: `去掉标签「${name}」`,
            "aria-label": `去掉标签「${name}」`,
            onclick: () => removeLabel(s.id, name),
          }),
        ),
      ),
    ),
    input,
    node("button", {
      class: "tool-toggle",
      type: "button",
      text: "加标签",
      onclick: () => addLabel(s.id, input),
    }),
  );
}

/** 改完标志之后：行徽标和工具条都得跟着变，但**不重读**列表（标志不改排序）。 */
function repaintAfterMarks() {
  repaintList();
  renderReader();
}

/** 置顶会改排序，改完重读一遍当前文件夹的列表，阅读区留着不动。 */
async function reloadAfterPin() {
  const folder = state.folders.find((f) => f.id === state.folderId);
  if (folder) await loadList(folder);
  repaintList();
  renderReader();
}

async function toggleFlag(messageId) {
  const row = state.messages.find((x) => x.id === messageId);
  const d = state.detail;
  const base = d && d.summary.id === messageId ? d.summary.flags : row?.flags;
  if (!base) return;
  const flags = { ...base, flagged: !base.flagged };
  await invoke("set_message_flags", { message_id: messageId, flags });
  if (row) row.flags = flags;
  if (d && d.summary.id === messageId) d.summary.flags = flags;
  repaintAfterMarks();
}

async function togglePin(messageId) {
  const row = state.messages.find((x) => x.id === messageId);
  const d = state.detail;
  const pinned = !(d && d.summary.id === messageId ? d.summary.pinned : row?.pinned);
  await invoke("set_message_pinned", { message_id: messageId, pinned });
  if (row) row.pinned = pinned;
  if (d && d.summary.id === messageId) d.summary.pinned = pinned;
  await reloadAfterPin();
}

/**
 * 加标签。名字就是标签（没有单独的标签表）：重复加同一个名字是无操作 ——
 * 标签是集合，不是列表，「重要、重要」没有意义。
 */
async function addLabel(messageId, input) {
  const name = input.value.trim();
  if (!name) return;
  const d = state.detail;
  const cur = d && d.summary.id === messageId ? d.summary.labels : [];
  if (!cur.includes(name)) {
    const labels = [...cur, name];
    await invoke("set_message_labels", { message_id: messageId, labels });
    if (d && d.summary.id === messageId) d.summary.labels = labels;
    const row = state.messages.find((x) => x.id === messageId);
    if (row) row.labels = labels;
  }
  input.value = "";
  repaintAfterMarks();
}

async function removeLabel(messageId, name) {
  const d = state.detail;
  const cur = d && d.summary.id === messageId ? d.summary.labels : [];
  const labels = cur.filter((x) => x !== name);
  await invoke("set_message_labels", { message_id: messageId, labels });
  if (d && d.summary.id === messageId) d.summary.labels = labels;
  const row = state.messages.find((x) => x.id === messageId);
  if (row) row.labels = labels;
  repaintAfterMarks();
}

// ================================================================= 同步

/**
 * 「收信」按钮。
 *
 * 这是个**慢操作**（真的连一次服务器），所以按钮要禁用 + 显示状态，
 * 不能让人以为点没点上。列表刷新走本地库（`reloadAfterSync`），别把
 * 「收信」当成列表刷新用。
 */
let syncing = false;

async function syncNow() {
  if (syncing || !state.account) return;
  syncing = true;
  const btn = document.getElementById("btn-sync");
  btn.disabled = true;
  btn.classList.add("is-spinning"); // 收信图标转起来

  try {
    const report = await invoke("sync_account", { account_id: state.account.id });
    const parts = [];
    if (report.fetched > 0) parts.push(`收到 ${report.fetched} 封`);
    if (report.broken > 0) parts.push(`${report.broken} 封解析失败`);
    if (report.rebuilt > 0) parts.push(`${report.rebuilt} 个文件夹重建`);
    toast(parts.length > 0 ? parts.join("，") : "已经是最新");
    await reloadAfterSync();
  } catch (err) {
    toast(`同步失败：${err instanceof Error ? err.message : err}`);
  } finally {
    syncing = false;
    btn.disabled = false;
    btn.classList.remove("is-spinning");
  }
}

/**
 * 同步之后重读文件夹和列表。
 *
 * **不碰正在读的那封信** —— 同步是后台动作，不该把人的阅读位置踢掉。
 * 只有还没有选中文件夹时才挑一个（一般是收件箱）。
 */
async function reloadAfterSync() {
  if (!state.account) return;
  await refreshSidebarData();
  const folders = withDraftsFolder(
    state.allFolders.filter((f) => f.account_id === state.account.id && f.id !== 0),
  );
  state.folders = folders;
  renderSidebar();

  // 智能箱/快捷箱：按当前视图重拉一遍，**不碰正在读的那封信**。
  if (state.smart) {
    const s = state.smart;
    if (s.isDrafts) {
      state.messages = [];
      state.drafts = s.account_id == null ? await allDrafts() : await invoke("list_drafts", { account_id: s.account_id });
    } else {
      state.drafts = [];
      state.messages = await invoke("list_smart", { filter: s.filter, account_id: s.account_id ?? null });
    }
    repaintList();
    updateListCount();
    return;
  }

  if (state.searchQuery) {
    // 搜索模式下重新搜一遍。直接 loadList 会把结果悄悄换成文件夹列表，
    // 而标题还挂着「搜索：…」—— 上下文就对不上了。新收的信顺带能搜着。
    await runSearch(state.searchQuery);
    return;
  }

  if (state.folderId && state.allFolders.some((f) => f.id === state.folderId)) {
    const folder = state.allFolders.find((f) => f.id === state.folderId);
    await loadList(folder);
    repaintList();
    return;
  }

  const inbox = folders.find((f) => f.kind === "inbox") ?? folders[0];
  if (inbox) await selectFolder(inbox.id);
}

// 后台同步线程（`src-tauri/src/worker.rs`）收完信会发这个事件。
// 监听器只负责「刷新界面」，不负责同步本身。
const listen = globalThis.__TAURI__?.event?.listen;
if (typeof listen === "function") {
  listen("sync://changed", (e) => {
    const p = (e && e.payload) || {};
    const status = document.getElementById("sync-status");
    if (status) {
      status.textContent =
        p.fetched > 0
          ? `后台收到 ${p.fetched} 封`
          : p.flags_changed > 0
            ? `后台更新了 ${p.flags_changed} 封的标志`
            : "后台更新了邮件";
    }
    reloadAfterSync().catch((err) => console.error("刷新失败", err));
  });
}

// ================================================================= 通讯录（M4）

async function loadContacts() {
  state.contacts.list = await invoke("list_contacts", { query: state.contacts.query || null });
  renderContacts();
}

function buildContacts(stage) {
  stage.append(
    node("aside", { class: "pane pane-contacts" },
      node(
        "header",
        { class: "pane-head" },
        node("span", { text: "联系人" }),
        node("button", { class: "btn-sync", type: "button", text: "＋ 新建", title: "新建联系人", onclick: () => editContact(null) }),
      ),
      node("input", {
        class: "search-box contact-search",
        type: "search",
        placeholder: "搜姓名 / 邮箱 / 电话 / 公司",
        "aria-label": "搜索联系人",
        value: state.contacts.query,
        oninput: (e) => { state.contacts.query = e.target.value; loadContacts(); },
      }),
      node("nav", { class: "contact-list", id: "contact-list", role: "list" }),
    ),
    node("section", { class: "pane pane-contact-detail" },
      node("header", { class: "pane-head" }, node("span", { id: "contact-detail-title", text: "联系人" })),
      node("div", { class: "contact-detail", id: "contact-detail" }),
    ),
  );
  renderContacts();
}

function renderContacts() {
  const box = document.getElementById("contact-list");
  if (!box) return;
  clear(box);
  if (state.contacts.list.length === 0) {
    box.append(node("p", { class: "empty", text: state.contacts.query ? "没有匹配的联系人" : "还没有联系人" }));
  }
  for (const c of state.contacts.list) {
    box.append(
      node(
        "button",
        {
          class: `contact-row${state.contacts.selected === c.id ? " is-sel" : ""}`,
          type: "button",
          role: "listitem",
          "aria-current": state.contacts.selected === c.id ? "true" : "false",
          onclick: () => selectContact(c.id),
        },
        renderAvatar({ display: c.name, address: c.email }),
        node(
          "div",
          { class: "contact-row-main" },
          node("span", { class: "name", text: c.name || "（无名）" }),
          node("span", { class: "email", text: c.email || c.phone || "" }),
        ),
      ),
    );
  }
  renderContactDetail();
}

function renderContactDetail() {
  const box = document.getElementById("contact-detail");
  const title = document.getElementById("contact-detail-title");
  if (!box) return;
  clear(box);
  if (state.contacts.editing) {
    renderContactForm(box, title);
    return;
  }
  const c = state.contacts.list.find((x) => x.id === state.contacts.selected);
  if (!c) {
    title.textContent = "联系人";
    box.append(node("p", { class: "empty" }, "选一个联系人查看，或点「新建」。"));
    return;
  }
  title.textContent = c.name || "联系人";
  const row = (label, val) =>
    val ? node("div", { class: "kv" }, node("span", { class: "kv-k", text: label }), node("span", { class: "kv-v", text: val })) : null;
  box.append(
    node("div", { class: "contact-card" },
      renderAvatar({ display: c.name, address: c.email }),
      node("h2", { class: "contact-name", text: c.name || "（无名）" }),
    ),
    node("div", { class: "kv-list" },
      row("邮箱", c.email),
      row("电话", c.phone),
      row("公司", c.org),
      row("备注", c.note),
    ),
    node("div", { class: "contact-actions" },
      node("button", { class: "btn btn-primary", type: "button", text: "发邮件", onclick: () => mailTo(c) }),
      node("button", { class: "btn", type: "button", text: "编辑", onclick: () => editContact(c) }),
      node("button", { class: "btn btn-danger", type: "button", text: "删除", onclick: () => removeContact(c.id) }),
    ),
  );
}

function renderContactForm(box, title) {
  const c = state.contacts.editing;
  title.textContent = c.id ? "编辑联系人" : "新建联系人";
  const fields = {};
  const mkField = (key, label, val, ph) => {
    const input = node("input", { class: "form-input", id: `ct-${key}`, value: val || "", placeholder: ph || label });
    fields[key] = input;
    return node("div", { class: "form-field" }, node("label", { class: "field-label", text: label, for: `ct-${key}` }), input);
  };
  box.append(
    node("div", { class: "contact-form" },
      mkField("name", "姓名", c.name),
      mkField("email", "邮箱", c.email, "name@example.com"),
      mkField("phone", "电话", c.phone),
      mkField("org", "公司 / 组织", c.org),
      mkField("note", "备注", c.note),
      node("div", { class: "contact-actions" },
        node("button", { class: "btn btn-primary", type: "button", text: "保存", onclick: () => saveContactForm(fields, c) }),
        node("button", { class: "btn", type: "button", text: "取消", onclick: () => { state.contacts.editing = null; renderContactDetail(); } }),
      ),
    ),
  );
  fields.name.focus();
}

function selectContact(id) {
  state.contacts.selected = id;
  state.contacts.editing = null;
  renderContacts();
}

function editContact(c) {
  state.contacts.editing = c
    ? { ...c }
    : { id: null, name: "", email: "", phone: "", org: "", note: "" };
  renderContactDetail();
}

async function saveContactForm(fields, c) {
  const input = {
    id: c.id ?? null,
    name: fields.name.value.trim(),
    email: fields.email.value.trim(),
    phone: fields.phone.value.trim(),
    org: fields.org.value.trim(),
    note: fields.note.value.trim(),
  };
  if (!input.name && !input.email) {
    statusNote("至少填姓名或邮箱");
    return;
  }
  await invoke("save_contact", { input });
  state.contacts.editing = null;
  await loadContacts();
  if (input.id == null) {
    const just = state.contacts.list.find((x) => x.name === input.name && x.email === input.email);
    if (just) state.contacts.selected = just.id;
    renderContacts();
  }
}

async function removeContact(id) {
  await invoke("delete_contact", { id });
  if (state.contacts.selected === id) state.contacts.selected = null;
  state.contacts.editing = null;
  await loadContacts();
}

/** 「发邮件」：开撰写窗并预填收件人。 */
function mailTo(c) {
  if (!c.email) {
    statusNote("这个联系人没填邮箱");
    return;
  }
  openCompose({ account: state.account, prefillTo: [{ display: c.name || null, address: c.email }] });
}

// ================================================================= 日历（M4）

function dayStr(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function isoLocal(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${dayStr(d)}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
/** 月网格范围（含首尾补满的周日→周六）。 */
/** ISO 周号（周一为一周之始的通用周数；周日开始的网格也用它，够用）。 */
function isoWeekNumber(d) {
  const t = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  t.setDate(t.getDate() + 4 - (t.getDay() || 7)); // 到本周周四
  const yearStart = new Date(t.getFullYear(), 0, 1);
  return Math.ceil(((t - yearStart) / 86400000 + 1) / 7);
}

/** 一周开始日：设置 `cal_week_start`（默认周一）。返回 0=周日 / 1=周一。 */
function weekStart() {
  return state.settings?.cal_week_start === "sun" ? 0 : 1;
}

function calGridRange(y, m) {
  const ws = weekStart();
  const first = new Date(y, m, 1);
  const start = new Date(first);
  start.setDate(1 - ((first.getDay() - ws + 7) % 7));
  const last = new Date(y, m + 1, 0);
  const end = new Date(last);
  end.setDate(last.getDate() + (((ws + 6) % 7) - last.getDay() + 7) % 7);
  return { start, end };
}

async function loadCalendar() {
  const now = new Date();
  if (!state.calendar.year) {
    state.calendar.year = now.getFullYear();
    state.calendar.month = now.getMonth();
    state.calendar.selectedDay = dayStr(now);
  }
  const { start, end } = calGridRange(state.calendar.year, state.calendar.month);
  const endIncl = new Date(end);
  endIncl.setDate(endIncl.getDate() + 1);
  const raw = await invoke("list_events", { start: isoLocal(start), end: isoLocal(endIncl) });
  // 重复日程展开成区间内的实例（编辑/删除作用于整个系列 —— 实例沿用原 id）
  state.calendar.events = expandRepeats(raw, start, endIncl);
  renderCalendar();
}

function buildCalendar(stage) {
  stage.append(
    node("div", { class: "cal" },
      node(
        "header",
        { class: "cal-head" },
        node("button", { class: "btn btn-icon", type: "button", text: "‹", title: "上个月", onclick: () => shiftMonth(-1) }),
        node("h2", { class: "cal-title", id: "cal-title" }),
        node("button", { class: "btn btn-icon", type: "button", text: "›", title: "下个月", onclick: () => shiftMonth(1) }),
        node("button", { class: "btn", type: "button", text: "今天", onclick: () => {
          const n = new Date();
          state.calendar.year = n.getFullYear();
          state.calendar.month = n.getMonth();
          state.calendar.selectedDay = dayStr(n);
          loadCalendar();
        } }),
        node("span", { class: "cal-spacer" }),
        node("button", { class: "btn btn-primary", type: "button", text: "＋ 新建日程", onclick: () => editEvent(null) }),
      ),
      node("div", { class: "cal-body" },
        node("div", { class: "cal-main" },
          node("div", { class: "cal-weekdays", id: "cal-weekdays" }),
          node("div", { class: "cal-days", id: "cal-days" }),
        ),
        node("aside", { class: "cal-side" },
          node("h3", { class: "cal-events-title", id: "cal-events-title" }),
          node("div", { class: "cal-events", id: "cal-events" }),
        ),
      ),
    ),
  );
  renderCalendar();
}

function shiftMonth(delta) {
  const d = new Date(state.calendar.year, state.calendar.month + delta, 1);
  state.calendar.year = d.getFullYear();
  state.calendar.month = d.getMonth();
  state.calendar.selectedDay = dayStr(d);
  loadCalendar();
}

/** 把 daily/weekly/monthly 展开成 [start,end) 内的实例；单次事件原样。
 *  实例沿用原 id（点开改/删都作用于整个系列，v1 如此）。 */
function expandRepeats(events, start, end) {
  const startMs = start.getTime();
  const endMs = end.getTime();
  const out = [];
  for (const e of events) {
    const s0 = new Date(e.start);
    const dur = Math.max(0, new Date(e.end) - s0);
    const rep = e.repeat || "none";
    if (rep === "none" || isNaN(s0)) {
      out.push(e);
      continue;
    }
    let cur = new Date(s0);
    for (let guard = 0; guard < 500; guard++) {
      const t = cur.getTime();
      if (t >= endMs) break;
      if (t >= startMs) {
        out.push({ ...e, start: isoLocal(cur), end: isoLocal(new Date(t + dur)), is_repeat: true });
      }
      if (rep === "daily") cur.setDate(cur.getDate() + 1);
      else if (rep === "weekly") cur.setDate(cur.getDate() + 7);
      else if (rep === "monthly") cur.setMonth(cur.getMonth() + 1);
      else break;
    }
  }
  out.sort((a, b) => new Date(a.start) - new Date(b.start));
  return out;
}

function renderCalendar() {
  const { year, month, events, selectedDay } = state.calendar;
  const title = document.getElementById("cal-title");
  if (title) title.textContent = `${year} 年 ${month + 1} 月`;
  const grid = document.getElementById("cal-days");
  if (!grid) return;
  const ws = weekStart();
  const showWeekNums = state.settings?.cal_week_numbers === "on";
  grid.classList.toggle("has-weeknums", showWeekNums);

  // 星期头也跟随「一周开始日」
  const head = document.getElementById("cal-weekdays");
  if (head) {
    head.classList.toggle("has-weeknums", showWeekNums);
    const wds = ["日", "一", "二", "三", "四", "五", "六"];
    clear(head);
    if (showWeekNums) head.append(node("span", { class: "cal-wd", text: "周" }));
    head.append(...[...wds.slice(ws), ...wds.slice(0, ws)].map((w) => node("span", { class: "cal-wd", text: w })));
  }

  clear(grid);
  const { start, end } = calGridRange(year, month);
  const todayStr = dayStr(new Date());
  for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
    // 每行开头插周数（ISO 周号）
    if (showWeekNums && d.getDay() === ws) {
      grid.append(node("div", { class: "cal-weeknum", text: String(isoWeekNumber(d)) }));
    }
    const ds = dayStr(d);
    const inMonth = d.getMonth() === month;
    const dayEvents = events.filter((e) => e.start.slice(0, 10) === ds);
    grid.append(
      node(
        "button",
        {
          class: `cal-day${inMonth ? "" : " is-out"}${ds === todayStr ? " is-today" : ""}${ds === selectedDay ? " is-sel" : ""}`,
          type: "button",
          onclick: () => { state.calendar.selectedDay = ds; state.calendar.editing = null; renderCalendar(); },
        },
        node("span", { class: "cal-daynum", text: String(d.getDate()) }),
        node("div", { class: "cal-dots" },
          dayEvents.slice(0, 3).map((e) => node("span", { class: `cal-dot${e.all_day ? " is-allday" : ""}`, text: e.title || "（无标题）" })),
        ),
        dayEvents.length > 3 ? node("span", { class: "cal-more", text: `+${dayEvents.length - 3}` }) : null,
      ),
    );
  }
  renderCalEvents();
}

function renderCalEvents() {
  const box = document.getElementById("cal-events");
  const title = document.getElementById("cal-events-title");
  if (!box) return;
  clear(box);
  if (state.calendar.editing) {
    renderEventForm(box, title);
    return;
  }
  const ds = state.calendar.selectedDay || dayStr(new Date());
  title.textContent = `${ds} 的日程`;
  const dayEvents = state.calendar.events
    .filter((e) => e.start.slice(0, 10) === ds)
    .sort((a, b) => a.start.localeCompare(b.start));
  if (dayEvents.length === 0) box.append(node("p", { class: "empty", text: "这天没有日程" }));
  for (const e of dayEvents) {
    box.append(
      node("div", { class: "cal-event" },
        node("div", { class: "cal-event-main" },
          node("span", { class: "cal-event-title", text: e.title || "（无标题）" }),
          node("span", { class: "cal-event-time", text: e.all_day ? "全天" : `${e.start.slice(11)} – ${e.end.slice(11)}` }),
          e.location ? node("span", { class: "cal-event-loc", text: `📍 ${e.location}` }) : null,
        ),
        node("div", { class: "cal-event-actions" },
          node("button", { class: "btn btn-mini", type: "button", text: "编辑", onclick: () => editEvent(e) }),
          node("button", { class: "btn btn-mini btn-danger", type: "button", text: "删除", onclick: () => removeEvent(e.id) }),
        ),
      ),
    );
  }
}

function renderEventForm(box, title) {
  const e = state.calendar.editing;
  title.textContent = e.id ? "编辑日程" : "新建日程";
  const fields = {};
  const text = (key, label, val, ph) => {
    const input = node("input", { class: "form-input", id: `ev-${key}`, value: val || "", placeholder: ph || label });
    fields[key] = input;
    return node("div", { class: "form-field" }, node("label", { class: "field-label", text: label, for: `ev-${key}` }), input);
  };
  const sel = (key, label, val, opts) => {
    const cs = customSelect(opts, val, () => {});
    fields[key] = cs; // 读 fields[key].value，同原生
    return node("div", { class: "form-field" }, node("label", { class: "field-label", text: label }), cs.el);
  };
  const allDay = node("input", { type: "checkbox", id: "ev-allday" });
  allDay.checked = !!e.all_day;
  fields.all_day = allDay;
  box.append(
    node("div", { class: "event-form" },
      text("title", "标题", e.title),
      text("start", "开始", e.start, "2026-11-03T15:00"),
      text("end", "结束", e.end, "2026-11-03T16:00"),
      node("div", { class: "form-field form-check" }, allDay, node("label", { text: " 全天", for: "ev-allday" })),
      text("location", "地点", e.location),
      text("note", "备注", e.note),
      sel("reminder", "提醒", e.reminder, [["none", "不提醒"], ["10m", "10 分钟前"], ["30m", "30 分钟前"], ["1h", "1 小时前"], ["1d", "1 天前"]]),
      sel("repeat", "重复", e.repeat, [["none", "不重复"], ["daily", "每天"], ["weekly", "每周"], ["monthly", "每月"]]),
      node("div", { class: "contact-actions" },
        node("button", { class: "btn btn-primary", type: "button", text: "保存", onclick: () => saveEventForm(fields, e) }),
        node("button", { class: "btn", type: "button", text: "取消", onclick: () => { state.calendar.editing = null; renderCalEvents(); } }),
      ),
    ),
  );
  fields.title.focus();
}

function editEvent(e) {
  const base = state.calendar.selectedDay || dayStr(new Date());
  // 默认时长 / 提醒 / 全天（设置页可改）
  const dur = state.settings?.cal_duration ?? "1h";
  const durMin = { "15m": 15, "30m": 30, "1h": 60, "2h": 120 }[dur] ?? 60;
  const startStr = `${base}T09:00`;
  const endDate = new Date(new Date(startStr).getTime() + durMin * 60000);
  const endStr = `${base}T${String(endDate.getHours()).padStart(2, "0")}:${String(endDate.getMinutes()).padStart(2, "0")}`;
  state.calendar.editing = e
    ? { ...e }
    : {
        id: null,
        title: "",
        start: startStr,
        end: endStr,
        all_day: dur === "all",
        location: "",
        note: "",
        reminder: state.settings?.cal_remind ?? "10m",
        repeat: "none",
      };
  renderCalEvents();
}

async function saveEventForm(fields, e) {
  const input = {
    id: e.id ?? null,
    title: fields.title.value.trim(),
    start: fields.start.value.trim(),
    end: fields.end.value.trim(),
    all_day: fields.all_day.checked,
    location: fields.location.value.trim(),
    note: fields.note.value.trim(),
    reminder: fields.reminder.value,
    repeat: fields.repeat.value,
  };
  if (!input.title) { statusNote("给日程起个标题"); return; }
  if (!input.start || !input.end) { statusNote("填开始 / 结束时间"); return; }
  if (input.end < input.start) { statusNote("结束不能早于开始"); return; }
  await invoke("save_event", { input });
  state.calendar.editing = null;
  await loadCalendar();
}

async function removeEvent(id) {
  await invoke("delete_event", { id });
  state.calendar.editing = null;
  await loadCalendar();
}

// // ================================================================= 设置（M5/M6）

// ================================================================= AI 翻译
//
// 走 OpenAI 兼容 chat/completions（OpenAI/DeepSeek/SiliconFlow/自定义都认）。
// 提示词模板带 {lang} 占位；API key 存 keyring（设置里只显示有没有配）。

const TRANSLATE_LANGS = ["中文", "英语", "日语", "韩语", "法语", "德语", "俄语", "西班牙语", "葡萄牙语", "意大利语"];

/** [id, 名称, 默认地址, 默认模型]——选厂商自动带出地址/模型，可改。 */
const TRANSLATE_PROVIDERS = [
  ["openai", "OpenAI", "https://api.openai.com/v1", "gpt-4o-mini"],
  ["deepseek", "DeepSeek", "https://api.deepseek.com/v1", "deepseek-chat"],
  ["siliconflow", "SiliconFlow", "https://api.siliconflow.cn/v1", "Qwen/Qwen2.5-7B-Instruct"],
  ["custom", "自定义（OpenAI 兼容）", "", ""],
];

/** 设置 → 翻译。整块异步填充（要拉 get_translate_settings）。 */
function renderTranslateSettings(content) {
  content.append(
    node("h2", { class: "settings-title", text: "翻译" }),
    node("p", { class: "muted", text: "AI 翻译邮件正文。走 OpenAI 兼容接口，密钥只存系统钥匙串。" }),
    node("div", { class: "settings-block", id: "translate-form" }, node("p", { class: "muted", text: "加载中…" })),
  );
  const box = content.querySelector("#translate-form");
  (async () => {
    let cfg;
    try {
      cfg = await invoke("get_translate_settings");
    } catch {
      clear(box).append(node("p", { class: "muted", text: "读取设置失败" }));
      return;
    }
    const status = node("p", { class: "dialog-status", text: cfg.has_key ? "已配置 API 密钥" : "还没配置 API 密钥" });
    const providerSel = customSelect(
      TRANSLATE_PROVIDERS.map(([id, name]) => [id, name]),
      cfg.provider,
      (v) => {
        const preset = TRANSLATE_PROVIDERS.find(([id]) => id === v);
        if (preset && preset[2]) baseUrl.value = preset[2];
        if (preset && preset[3]) model.value = preset[3];
      },
    );
    const baseUrl = node("input", { class: "form-input", type: "text", value: cfg.base_url, placeholder: "https://api.openai.com/v1" });
    const model = node("input", { class: "form-input", type: "text", value: cfg.model, placeholder: "gpt-4o-mini" });
    const apiKey = node("input", {
      class: "form-input", type: "password", value: "",
      placeholder: cfg.has_key ? "已配置（留空保持不变）" : "sk-…",
    });
    const prompt = node("textarea", {
      class: "form-input", rows: "3",
      text: cfg.prompt,
      placeholder: "{lang} 会被替换成目标语言",
    });
    const targetSel = customSelect(
      TRANSLATE_LANGS.map((l) => [l, l]),
      cfg.target,
      () => {},
    );
    const save = async (quiet = false) => {
      try {
        cfg = await invoke("save_translate_settings", {
          input: {
            provider: providerSel.value,
            base_url: baseUrl.value.trim(),
            model: model.value.trim(),
            prompt: prompt.value,
            target: targetSel.value,
            api_key: apiKey.value,
            has_key: cfg.has_key,
          },
        });
        apiKey.value = "";
        status.textContent = cfg.has_key ? "已配置 API 密钥" : "还没配置 API 密钥";
        if (!quiet) statusNote("翻译设置已保存");
      } catch (err) {
        status.textContent = `保存失败：${err instanceof Error ? err.message : err}`;
      }
    };
    const testBtn = node("button", {
      class: "btn btn-primary", type: "button", text: "测试翻译",
      onclick: async () => {
        await save(true);
        status.textContent = "翻译中…";
        try {
          const out = await invoke("translate_text", { text: "你好，世界。这是一条翻译测试。", target: targetSel.value });
          status.textContent = `测试结果：${out}`;
          status.classList.remove("is-error");
        } catch (err) {
          status.textContent = `失败：${err instanceof Error ? err.message : err}`;
          status.classList.add("is-error");
        }
      },
    });
    clear(box).append(
      settingRow("翻译厂商", "OpenAI 兼容接口都可接入", providerSel.el),
      settingRow("API 地址", "…/v1 结尾（chat/completions 会拼在后面）", baseUrl),
      settingRow("模型", "如 gpt-4o-mini / deepseek-chat", model),
      settingRow("API 密钥", "只存系统钥匙串，不进配置文件", apiKey),
      settingRow("提示词", "{lang} 会被替换成目标语言", prompt),
      settingRow("默认目标语言", "读信「译」按钮的默认语种", targetSel.el),
      node("div", { class: "setting-row" },
        node("div", { class: "setting-info" }),
        node("div", { class: "setting-ctl" },
          node("button", { class: "btn", type: "button", text: "保存", onclick: () => save() }),
          testBtn,
        ),
      ),
      status,
    );
  })();
}

// ================================================================= 线条图标库
//
// 2px 圆头描边（D2 · 无边留白风格）。图标一律走这里，不再用 emoji——
// emoji 在不同平台渲染不一致，而且「emoji 堆砌」正是要去掉的 AI 味。
// 构造走 createElementNS：**不碰 innerHTML**（全项目只有两处，见 dom.js）。

const ICONS = {
  mail: [["rect", { x: 3, y: 5, width: 18, height: 14, rx: 3 }], ["path", { d: "M3.5 8l8.5 5.5L20.5 8" }]],
  users: [["circle", { cx: 12, cy: 8.5, r: 3.5 }], ["path", { d: "M5 19.5c1.3-3.4 4-5 7-5s5.7 1.6 7 5" }]],
  calendar: [["rect", { x: 3.5, y: 5.5, width: 17, height: 15, rx: 3 }], ["path", { d: "M3.5 10h17M8 3.5v4M16 3.5v4" }]],
  palette: [["circle", { cx: 12, cy: 12, r: 8.5 }], ["circle", { cx: 12, cy: 12, r: 3.5 }]],
  gear: [["circle", { cx: 12, cy: 12, r: 3 }], ["path", { d: "M12 4v2.5m0 11V20M4 12h2.5m11 0H20M6.2 6.2l1.8 1.8m8 8l1.8 1.8M17.8 6.2L16 8M8 16l-1.8 1.8" }]],
  sun: [["circle", { cx: 12, cy: 12, r: 4 }], ["path", { d: "M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6l1.4 1.4m10 10l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4" }]],
  moon: [["path", { d: "M19.5 13.5A8 8 0 1 1 10.5 4.5 6.5 6.5 0 0 0 19.5 13.5z" }]],
  inbox: [["path", { d: "M4 13.5l3.5-8h9l3.5 8v5.5H4z" }], ["path", { d: "M4 13.5h5l1 2h4l1-2h5" }]],
  envelope: [["rect", { x: 3.5, y: 5.5, width: 17, height: 13, rx: 3 }], ["path", { d: "M4 8l8 5 8-5" }]],
  star: [["path", { d: "M12 4l2.4 5.2 5.6.7-4.2 3.9 1.1 5.7L12 16.8l-4.9 2.7 1.1-5.7L4 9.9l5.6-.7z" }]],
  doc: [["path", { d: "M7 3.5h7l4 4v13H7z" }], ["path", { d: "M14 3.5v4h4M9.5 12h6M9.5 15.5h6" }]],
  send: [["path", { d: "M4 12l3.5-7h9l3.5 7v7H4z" }], ["path", { d: "M4 12h16" }]],
  folder: [["path", { d: "M3.5 6.5h6l2 2h9v10h-17z" }]],
  trash: [["path", { d: "M5.5 7.5h13l-1 11.5H6.5z" }], ["path", { d: "M9 7.5v-3h6v3" }]],
  spam: [["path", { d: "M5.5 7.5h13l-1 11.5H6.5z" }], ["path", { d: "M9 7.5v-3h6v3M9.5 11.5v4M14.5 11.5v4" }]],
  archive: [["rect", { x: 3.5, y: 4.5, width: 17, height: 5, rx: 1.5 }], ["path", { d: "M5 9.5v10h14v-10M9.5 13.5h5" }]],
  search: [["circle", { cx: 11, cy: 11, r: 6.5 }], ["path", { d: "M16 16l4.5 4.5" }]],
};

/** 造一个线条图标（24px 视口、2px 圆头描边、随文字着色）。 */
function svgIcon(name, cls) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", cls ? `ic-svg ${cls}` : "ic-svg");
  svg.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of ICONS[name] || []) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    svg.append(el);
  }
  return svg;
}

const SETTINGS_SECTIONS = [
  ["system", "系统设置"],
  ["notify", "邮件通知"],
  ["mailbox", "邮箱设置"],
  ["readwrite", "邮件读写"],
  ["calendar", "日历"],
  ["translate", "翻译"],
  ["proxy", "代理设置"],
  ["about", "关于"],
];

/** 只拉设置（不渲染）——启动时用。 */
async function fetchSettings() {
  let s = {};
  try {
    for (const [k, v] of (await invoke("get_settings")) || []) s[k] = v;
  } catch {
    /* 读不到就用默认 */
  }
  state.settings = s;
  // 撰写窗（另一个模块）也要读设置（如回复前缀），挂个全局。
  globalThis.__mailwaySettings = s;
}

async function loadSettings() {
  await fetchSettings();
  renderSettings();
}

function buildSettings(stage) {
  stage.append(
    node("div", { class: "settings" },
      node("header", { class: "pane-head" }, node("span", { text: "设置" })),
      node("div", { class: "settings-body" },
        node("nav", { class: "settings-nav", id: "settings-nav", "aria-label": "设置分区" }),
        node("div", { class: "settings-content", id: "settings-content" }),
      ),
    ),
  );
  renderSettings();
}

function renderSettings() {
  const nav = document.getElementById("settings-nav");
  const content = document.getElementById("settings-content");
  if (!nav || !content) return;
  clear(nav);
  for (const [id, label] of SETTINGS_SECTIONS) {
    nav.append(
      node("button", {
        class: `settings-nav-item${state.settingsSection === id ? " is-active" : ""}`,
        type: "button",
        "aria-current": state.settingsSection === id ? "true" : "false",
        text: label,
        onclick: () => { state.settingsSection = id; renderSettings(); },
      }),
    );
  }
  clear(content);
  renderSettingsSection(content, state.settingsSection);
}

function renderSettingsSection(content, id) {
  const s = state.settings || {};
  const val = (k, d) => s[k] ?? d;
  const set = (k, v) => saveSetting(k, v);
  // 开关：on/off 存储
  const check = (k, d) => settingCheck(val(k, d) === "on", (on) => set(k, on ? "on" : "off"));

  if (id === "translate") {
    renderTranslateSettings(content);
  } else if (id === "system") {
    content.append(
      node("h2", { class: "settings-title", text: "系统设置" }),
      settingRow("开机自动运行", "登录系统后自动启动（XDG autostart）", autostartCheck()),
      settingRow("关闭主窗口时", "点窗口关闭按钮的行为", settingRadio(
        [["最小化到系统托盘", "on"], ["退出 Mailway", "off"]],
        val("close_to_tray", "on"),
        (v) => set("close_to_tray", v),
      )),
    );
  } else if (id === "notify") {
    content.append(
      node("h2", { class: "settings-title", text: "邮件通知" }),
      settingRow("弹窗提醒", "收到新邮件时弹系统通知", check("notify_popup", "on")),
      settingRow("声音提醒", "新邮件到达时播放提示音", check("notify_sound", "on")),
      settingRow("弹窗显示发件人和主题", "通知里带发件人与主题", check("notify_show_sender", "on")),
      settingRow("测试通知", "发一条测试弹窗，验证通知链路", node("button", {
        class: "btn", type: "button", text: "发送测试通知",
        onclick: async (ev) => {
          const b = ev.currentTarget;
          b.disabled = true;
          try {
            await invoke("send_test_notification");
            statusNote("测试通知已发出");
          } catch (err) {
            statusNote(`发送失败：${err instanceof Error ? err.message : err}`);
          }
          b.disabled = false;
        },
      })),
    );
  } else if (id === "mailbox") {
    renderMailboxSettings(content, s);
  } else if (id === "readwrite") {
    content.append(
      node("h2", { class: "settings-title", text: "邮件读写" }),
      node("h3", { class: "settings-sub", text: "邮件列表查看" }),
      settingRow("邮件按主题聚合", "同一主题的多封信折成一条", check("thread_aggregate", "on")),
      settingRow("显示发件人头像", "列表行显示发件人头像", check("show_avatars", "on")),
      node("h3", { class: "settings-sub", text: "收信" }),
      settingRow("收信频率", "IMAP 有推送、新信基本实时；此频率主要影响 POP3 轮询（默认 3 分钟）", settingSelect(
        [["1", "每 1 分钟"], ["3", "每 3 分钟"], ["5", "每 5 分钟"], ["10", "每 10 分钟"], ["15", "每 15 分钟"], ["30", "每 30 分钟"]],
        val("sync_interval_min", "3"),
        (v) => set("sync_interval_min", v),
      )),
      node("h3", { class: "settings-sub", text: "邮件正文" }),
      settingRow("总是显示远程图片", "不拦截邮件里的外链图片（发件人可追踪已读，谨慎）", check("show_remote_images", "off")),
      node("h3", { class: "settings-sub", text: "文件夹列表查看" }),
      settingRow("显示快捷文件夹", "侧栏顶部显示快捷文件夹", check("show_quick_folders", "on")),
      node("h3", { class: "settings-sub", text: "回复 / 转发前缀" }),
      settingRow("前缀", "回复/转发时主题前缀", settingRadio(
        [["自动选择语言", "auto"], ["回复: / 转发:", "cn"], ["Re: / Fw:", "en"]],
        val("reply_prefix", "auto"),
        (v) => set("reply_prefix", v),
      )),
    );
  } else if (id === "calendar") {
    content.append(
      node("h2", { class: "settings-title", text: "日历" }),
      settingRow("启用日历", "在左侧图标栏显示日历入口", settingCheck(
        val("enable_calendar", "on") !== "off",
        (on) => { set("enable_calendar", on ? "on" : "off"); refreshRail(); },
      )),
      settingRow("默认提醒时间", "新建日程的默认提醒", settingSelect(
        [["none", "不提醒"], ["10m", "前 10 分钟"], ["30m", "前 30 分钟"], ["1h", "前 1 小时"], ["1d", "前 1 天"]],
        val("cal_remind", "10m"), (v) => set("cal_remind", v))),
      settingRow("默认日程时长", "新建日程的默认时长", settingSelect(
        [["15m", "15 分钟"], ["30m", "30 分钟"], ["1h", "1 小时"], ["2h", "2 小时"], ["all", "全天"]],
        val("cal_duration", "1h"), (v) => set("cal_duration", v))),
      settingRow("显示周数", "月视图里显示周数", check("cal_week_numbers", "off")),
      settingRow("一周开始日", "月视图的第一列", settingRadio(
        [["周一", "mon"], ["周日", "sun"]],
        val("cal_week_start", "mon"),
        (v) => set("cal_week_start", v),
      )),
    );
  } else if (id === "proxy") {
    renderProxySettings(content, s);
  } else if (id === "about") {
    content.append(
      node("h2", { class: "settings-title", text: "关于" }),
      node("div", { class: "settings-about" },
        node("p", { text: "Mailway —— 原生 Wayland 邮件客户端" }),
        node("p", { class: "muted", text: "版本 0.1.0 · Tauri 2 + Rust · 本地优先，授权码进 keyring" }),
        node("p", { class: "muted", text: "IMAP/SMTP 收发 · SQLite 本地库 · 界面自研，不嵌第三方素材" }),
      ),
    );
  }
}

/**
 * 邮箱设置（对照 wyemail `ACCOUNT_MANAGE_TABS`）：左侧账号列表 + 右侧
 * 邮箱信息 / 签名 / 邮件模板 / 来信分类。
 */
function renderMailboxSettings(content) {
  content.append(node("h2", { class: "settings-title", text: "邮箱设置" }));
  if (state.accounts.length === 0) {
    content.append(node("p", { class: "empty", text: "还没有账号，点侧栏「邮箱」分区的 ＋ 添加。" }));
    return;
  }
  if (state.mailboxSel == null || !state.accounts.some((a) => a.id === state.mailboxSel)) {
    state.mailboxSel = state.accounts[0].id;
  }
  content.append(
    node("div", { class: "mailbox-wrap" },
      node("div", { class: "mailbox-list" },
        ...state.accounts.map((a) =>
          node("button", {
            class: `mailbox-item${state.mailboxSel === a.id ? " is-sel" : ""}`,
            type: "button",
            onclick: () => { state.mailboxSel = a.id; state.mailboxTab = "info"; renderSettings(); },
          },
            node("span", { class: "mailbox-name", text: a.name || a.email }),
            node("span", { class: "mailbox-mail", text: a.email }),
          ),
        ),
        node("button", { class: "btn mailbox-add", type: "button", text: "＋ 添加邮箱", onclick: addAccount }),
      ),
      node("div", { class: "mailbox-panel", id: "mailbox-panel" }),
    ),
  );
  renderMailboxPanel();
}

function renderMailboxPanel() {
  const panel = document.getElementById("mailbox-panel");
  const a = state.accounts.find((x) => x.id === state.mailboxSel);
  if (!panel || !a) return;
  clear(panel);
  const tabs = [["info", "邮箱信息"], ["signature", "签名"], ["template", "邮件模板"], ["rules", "来信分类"]];
  panel.append(
    node("div", { class: "mailbox-tabs" },
      tabs.map(([id, label]) =>
        node("button", {
          class: `mailbox-tab${state.mailboxTab === id ? " is-on" : ""}`,
          type: "button",
          text: label,
          onclick: () => { state.mailboxTab = id; renderMailboxPanel(); },
        }),
      ),
    ),
    node("div", { class: "mailbox-body", id: "mailbox-body" }),
  );
  const body = document.getElementById("mailbox-body");
  if (state.mailboxTab === "info") renderMailboxInfo(body, a);
  else if (state.mailboxTab === "signature") renderMailboxSignature(body, a);
  else if (state.mailboxTab === "template") renderMailboxTemplate(body);
  else if (state.mailboxTab === "rules") renderMailboxRules(body, a);
}

/** 邮箱信息：发件人姓名 / 邮箱名称 / 发件人头像 / 存储空间 / 停用此邮箱。 */
function renderMailboxInfo(body, a) {
  const nameInput = node("input", {
    class: "form-input", type: "text", value: a.name || "", placeholder: "发信时显示的名字",
  });
  nameInput.addEventListener("change", async () => {
    const updated = await invoke("set_account_name", { account_id: a.id, name: nameInput.value.trim() });
    Object.assign(a, updated);
    renderSidebar();
    statusNote("发件人姓名已更新");
  });
  body.append(
    settingRow("发件人姓名", "发信时显示的名字", nameInput),
    settingRow("邮箱名称", "这个邮箱的地址", node("input", { class: "form-input", type: "text", value: a.email, disabled: true })),
    settingRow("发件人头像", "头像暂用姓名首字（自定义后续）", node("button", { class: "btn", type: "button", text: "修改", disabled: true, title: "后续版本" })),
    settingRow("存储空间", "元数据在 SQLite、原文落盘", node("span", { class: "muted", text: "本地存储" })),
    settingRow("停用此邮箱", "停用后不参与收信", settingCheck(a.enabled !== false, (on) => setAccountEnabled(a, on))),
  );
  // Google（OAuth）账号：令牌会过期 —— 提供「重新登录」升级成带
  // refresh_token 的令牌包（后台此后自动续期）。
  if (a.auth_type === "xoauth2") {
    const reloginBtn = node("button", {
      class: "btn", type: "button", text: "重新登录 Google",
      onclick: () => googleRelogin(reloginBtn, a),
    });
    body.append(
      settingRow("Google 登录", "令牌过期后重新授权（应用内弹窗）", reloginBtn),
    );
  }
}

/** 重新走一遍 Google 授权，把新令牌包写进钥匙串。格式同 tokens::pack。 */
async function googleRelogin(btn, a) {
  btn.disabled = true;
  statusNote("正在打开 Google 授权…（应用内弹窗，授权完自动回来）");
  try {
    const token = await invoke("google_oauth_login");
    const packed = JSON.stringify({
      access: token.access_token,
      refresh: token.refresh_token || "",
      exp: Math.floor(Date.now() / 1000) + (token.expires_in || 3600) - 120,
    });
    await invoke("set_account_secret", { account_id: a.id, secret: packed });
    statusNote("Google 已重新登录，令牌会自动续期");
  } catch (err) {
    statusNote(`Google 重新登录失败：${err instanceof Error ? err.message : err}`);
  } finally {
    btn.disabled = false;
  }
}

/** 签名：账号级，发信时拼在正文最后。 */
function renderMailboxSignature(body, a) {
  const ta = node("textarea", {
    class: "form-input mailbox-sig", rows: "8", placeholder: "签名（发信时拼在正文最后）",
  });
  ta.value = a.signature || "";
  ta.addEventListener("change", async () => {
    const updated = await invoke("set_account_signature", { account_id: a.id, signature: ta.value });
    Object.assign(a, updated);
    statusNote("签名已保存");
  });
  body.append(
    node("div", { class: "form-field" },
      node("label", { class: "field-label", text: "签名" }),
      ta,
      node("p", { class: "muted", text: "写信时自动接在正文最后。" }),
    ),
  );
}

/** 邮件模板：全局模板（撰写窗「▾ 插入模板」用）。 */
function renderMailboxTemplate(body) {
  body.append(
    node("p", { class: "muted", text: "邮件模板是全局的（所有账号共用），在撰写窗「▾ 插入模板」里插入。" }),
    node("button", { class: "btn btn-primary", type: "button", text: "管理邮件模板", onclick: openTemplateManager }),
  );
}

/** 来信分类：这个账号的规则（新建/启停/删除），规则是每账号配置。 */
function renderMailboxRules(body, a) {
  renderRuleManager(body, a);
}

/** 启/停用邮箱。 */
async function setAccountEnabled(a, on) {
  try {
    const updated = await invoke("set_account_enabled", { account_id: a.id, enabled: on });
    Object.assign(a, updated);
    renderSidebar();
    statusNote(on ? "邮箱已启用" : "邮箱已停用（不参与收信）");
  } catch (err) {
    statusNote(`操作失败：${err instanceof Error ? err.message : err}`);
  }
}

/** 代理设置：SOCKS5 / HTTP CONNECT，接进全部收发连接（IMAP/POP3/SMTP）。
 *  密码存 keyring；保存即生效（不用重启）。 */
function renderProxySettings(content, s) {
  content.append(node("h2", { class: "settings-title", text: "代理设置" }));
  content.append(
    node("p", { class: "muted", text: "对全部收发连接生效（IMAP/POP3/SMTP）。只代理建连这一段，TLS 依旧端到端加密，代理看不到邮件内容。" }),
    node("div", { class: "settings-block", id: "proxy-form" }, node("p", { class: "muted", text: "加载中…" })),
  );
  const box = content.querySelector("#proxy-form");
  (async () => {
    let cfg;
    try {
      cfg = await invoke("get_proxy_settings");
    } catch {
      clear(box).append(node("p", { class: "muted", text: "读取设置失败" }));
      return;
    }
    const status = node("p", { class: "dialog-status", text: "" });
    const enable = settingCheck(cfg.enabled, (on) => {
      cfg.enabled = on;
    });
    const kindSel = customSelect([["socks5", "SOCKS5"], ["http", "HTTP CONNECT"]], cfg.kind, () => {});
    const host = node("input", { class: "form-input", type: "text", value: cfg.host, placeholder: "127.0.0.1" });
    const port = node("input", { class: "form-input", type: "number", value: cfg.port, placeholder: "1080" });
    const user = node("input", { class: "form-input", type: "text", value: cfg.username, placeholder: "可留空" });
    const pass = node("input", {
      class: "form-input", type: "password", value: "",
      placeholder: cfg.has_password ? "已配置（留空保持不变）" : "可留空",
    });
    const save = async (quiet = false) => {
      try {
        cfg = await invoke("save_proxy_settings", {
          input: {
            enabled: cfg.enabled,
            kind: kindSel.value,
            host: host.value.trim(),
            port: port.value.trim(),
            username: user.value.trim(),
            password: pass.value,
            has_password: cfg.has_password,
          },
        });
        pass.value = "";
        status.textContent = cfg.has_password ? "已保存（密码已配置）" : "已保存";
        status.classList.remove("is-error");
        if (!quiet) statusNote("代理设置已保存并生效");
      } catch (err) {
        status.textContent = `保存失败：${err instanceof Error ? err.message : err}`;
        status.classList.add("is-error");
      }
    };
    const testBtn = node("button", {
      class: "btn btn-primary", type: "button", text: "测试连接",
      onclick: async () => {
        await save(true);
        status.textContent = "测试中…";
        status.classList.remove("is-error");
        try {
          const out = await invoke("test_proxy", { host: "imap.163.com", port: 993 });
          status.textContent = out;
        } catch (err) {
          status.textContent = `失败：${err instanceof Error ? err.message : err}`;
          status.classList.add("is-error");
        }
      },
    });
    clear(box).append(
      settingRow("启用代理", "关掉即直连", enable),
      settingRow("代理类型", "SOCKS5（推荐）或 HTTP CONNECT", kindSel.el),
      settingRow("服务器", "代理主机名或 IP", host),
      settingRow("端口", "如 1080 / 7890", port),
      settingRow("用户名", "需要认证才填", user),
      settingRow("密码", "只存系统钥匙串，留空保持不变", pass),
      node("div", { class: "setting-row" },
        node("div", { class: "setting-info" }),
        node("div", { class: "setting-ctl" },
          node("button", { class: "btn", type: "button", text: "保存", onclick: () => save() }),
          testBtn,
        ),
      ),
      status,
    );
  })();
}

// ---- 设置控件 ----------------------------------------------------------

function settingRow(label, desc, control) {
  return node("div", { class: "setting-row" },
    node("div", { class: "setting-text" },
      node("span", { class: "setting-label", text: label }),
      desc ? node("span", { class: "setting-desc", text: desc }) : null,
    ),
    control,
  );
}

function settingCheck(checked, onChange) {
  const cb = node("input", { type: "checkbox", class: "switch-input" });
  cb.checked = !!checked;
  cb.addEventListener("change", () => onChange(cb.checked));
  return node("label", { class: "switch" }, cb, node("span", { class: "switch-ui", "aria-hidden": "true" }));
}

function settingRadio(options, current, onChange) {
  const seg = node("div", { class: "seg", role: "group" });
  for (const [text, value] of options) {
    seg.append(node("button", {
      class: `seg-btn${current === value ? " is-on" : ""}`,
      type: "button", text,
      onclick: () => onChange(value),
    }));
  }
  return seg;
}

/**
 * 自绘选择框（P6）。原生 <select> 的弹层是平台画的，不跟主题——一律不用。
 * 形态 = 输入框 + ▾，菜单同 .more-menu；返回 { el, value } 兼容旧读法。
 */
function customSelect(options, current, onChange) {
  let cur = current ?? (options[0] ? options[0][0] : "");
  const label = node("span", { class: "cs-label" });
  const caret = node("span", { class: "cs-caret", "aria-hidden": "true", text: "▾" });
  const menu = node("div", { class: "more-menu", hidden: true, role: "listbox" });
  const wrap = node("div", { class: "more-wrap custom-select-wrap" });
  const btn = node("button", {
    class: "form-input custom-select", type: "button",
    "aria-haspopup": "listbox", "aria-expanded": "false",
    onclick: (e) => {
      e.stopPropagation();
      const open = menu.hidden;
      closeAllMenus();
      if (!open) return;
      renderMenu();
      menu.hidden = false;
      btn.setAttribute("aria-expanded", "true");
      requestAnimationFrame(flipMenuOverflow);
    },
  }, label, caret);
  function renderMenu() {
    clear(menu);
    for (const [v, t] of options) {
      menu.append(
        node("button", {
          class: v === cur ? "more-item is-selected" : "more-item",
          type: "button", role: "option", "aria-selected": String(v === cur),
          text: t,
          onclick: () => {
            setValue(v);
            menu.hidden = true;
            btn.setAttribute("aria-expanded", "false");
            btn.focus();
          },
        }),
      );
    }
  }
  function setValue(v, notify = true) {
    cur = v;
    const found = options.find(([ov]) => ov === v);
    label.textContent = found ? found[1] : String(v);
    if (!notify) return;
    btn.dispatchEvent(new Event("change"));
    if (onChange) onChange(cur);
  }
  menu.addEventListener("click", (e) => e.stopPropagation());
  wrap.append(btn, menu);
  setValue(cur, false); // 初装不通知 —— 不然 settingSelect 一渲染就写设置
  return {
    el: wrap,
    get value() {
      return cur;
    },
    // 程序赋值**不**通知（同原生 select 语义）——只读回显用。
    // 通知了就会「赋值 → onChange → 再翻译 → 再赋值」死循环（译面板踩过）。
    set value(v) {
      setValue(v, false);
    },
  };
}

function settingSelect(options, current, onChange) {
  return customSelect(options, current, onChange).el;
}

function settingField(value, ph, onChange) {
  const inp = node("input", { class: "form-input setting-field", type: "text", value: value || "", placeholder: ph || "" });
  inp.addEventListener("change", () => onChange(inp.value.trim()));
  return inp;
}

/** 开机自启开关（XDG autostart）—— 状态取自系统自启文件，不是 settings。 */
function autostartCheck() {
  const cb = node("input", { type: "checkbox", class: "switch-input" });
  cb.addEventListener("change", async () => {
    try {
      await invoke("set_autostart", { enabled: cb.checked });
      statusNote(cb.checked ? "已加入开机自启" : "已取消开机自启");
    } catch (err) {
      statusNote(`设置失败：${err instanceof Error ? err.message : err}`);
      cb.checked = !cb.checked;
    }
  });
  invoke("autostart_status")
    .then((on) => { cb.checked = !!on; })
    .catch(() => {});
  return node("label", { class: "switch" }, cb, node("span", { class: "switch-ui", "aria-hidden": "true" }));
}

async function saveSetting(key, value) {
  state.settings[key] = value;
  try {
    await invoke("set_setting", { key, value });
  } catch (err) {
    statusNote(`保存设置失败：${err instanceof Error ? err.message : err}`);
  }
}

// ================================================================= 键盘

document.addEventListener("keydown", (e) => {
  // F5 = 收信。放在最前面，因为焦点在哪都该管用；必须 preventDefault，
  // 不然 webview 会把它当成「刷新页面」，整个前端状态就没了。
  //
  // `e.repeat` 要挡掉：按住 F5 会连发，而收信是**网络操作** —— 实测按一下
  // 就能在假服务器那边看到三轮 `UID FETCH`。长按不该把服务器刷爆。
  if (e.key === "F5") {
    e.preventDefault();
    if (!e.repeat) syncNow();
    return;
  }

  // Ctrl+N = 写邮件。同样放在输入框判断之前 —— 焦点在搜索框里也该能开新邮件。
  if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "n") {
    e.preventDefault();
    if (!e.repeat) composeNew();
    return;
  }

  // Ctrl+1/2/3 = 切模式（邮件 / 联系人 / 日历）。
  if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && ["1", "2", "3"].includes(e.key)) {
    e.preventDefault();
    switchMode({ "1": "mail", "2": "contacts", "3": "calendar" }[e.key]);
    return;
  }

  // Ctrl+Shift+L = 切明/暗主题。
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && !e.altKey && e.key.toLowerCase() === "l") {
    e.preventDefault();
    toggleTheme();
    return;
  }

  if (e.target.closest("input, textarea, button, details")) return;
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  if (state.messages.length === 0) return;

  e.preventDefault();
  const idx = state.messages.findIndex((m) => m.id === state.messageId);
  const next = e.key === "ArrowDown" ? idx + 1 : idx - 1;
  const clamped = Math.max(0, Math.min(state.messages.length - 1, next === -1 ? 0 : next));
  openMessage(state.messages[clamped].id);
});

// ================================================================= go

// 启动即套用上次的主题（只切 `data-theme` 属性，颜色由 CSS 变量覆盖）。
try {
  applyTheme(localStorage.getItem("mailway.theme"));
} catch {
  /* 读不到就用默认亮色 */
}

renderShell();
boot();
