// keycap — an inline <kbd>. Optionally with a hint after it:
//   keycap({ key: "/" })                       → <kbd>/</kbd>
//   keycap({ key: "Enter", hint: "select" })   → <span><kbd>Enter</kbd> select</span>

import { h } from "./h.js";

export function keycap({ key, hint } = {}) {
  const kbd = h("kbd", { class: "r-keycap" }, key ?? "");
  if (!hint) return kbd;
  return h("span", { class: "r-keyhint" }, kbd, h("span", { class: "r-keyhint__text" }, hint));
}

export default keycap;
