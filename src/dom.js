// DOM 小工具
//
// 从 app.js 里拆出来，因为撰写窗口也要用。**只留一份**是故意的：`node` 的
// 「没有 `html` 这个口子」是条安全约定（见下），两份拷贝就会有人在其中一份上
// 开个后门，而另一份看起来还是干净的。

/**
 * 造一个元素。**没有 `html` 这个口子**——谁要往里塞 HTML 都得显式写
 * `n.innerHTML = …`，这样审查时一眼就能看到。
 *
 * 目前全项目只有两处 `innerHTML`：
 *   * 邮件阅读页的 `.mail-body`（内容是 `core::sanitize` 净化过的）
 *   * 撰写窗口的编辑区（内容是用户自己写的，见 compose.js 的说明）
 */
export function node(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = String(v);
    else if (k.startsWith("on")) n.addEventListener(k.slice(2).toLowerCase(), v);
    else n.setAttribute(k, String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c !== null && c !== undefined && c !== false) n.append(c);
  }
  return n;
}

export function clear(n) {
  n.replaceChildren();
  return n;
}

/** 弹出菜单不出屏：菜单默认向右渲染（left:0），贴屏幕右缘时翻转贴右。
 *  每次点击后 / 窗口尺寸变化时跑一遍（app.js 挂全局钩子）。
 *  is-fixed 的右键菜单自己管坐标，跳过。 */
export function flipMenuOverflow() {
  for (const menu of document.querySelectorAll(".more-menu:not([hidden])")) {
    if (menu.classList.contains("is-fixed")) continue;
    menu.style.left = "";
    menu.style.right = "";
    const r = menu.getBoundingClientRect();
    if (r.right > window.innerWidth - 8) {
      menu.style.left = "auto";
      menu.style.right = "0";
    } else if (r.left < 8) {
      menu.style.left = "0";
      menu.style.right = "auto";
    }
  }
}

/** 右键菜单按光标摆位。**先入 DOM 再调**——量的是真实尺寸（菜单几项就多高，
 *  写死 320px 的旧猜法在九项菜单上必裁底）。四边贴 8px 边距兜住不出屏。 */
export function placeMenuAt(menu, x, y) {
  const r = menu.getBoundingClientRect();
  const left = Math.max(8, Math.min(x, window.innerWidth - r.width - 8));
  const top = Math.max(8, Math.min(y, window.innerHeight - r.height - 8));
  menu.style.left = `${Math.round(left)}px`;
  menu.style.top = `${Math.round(top)}px`;
}
