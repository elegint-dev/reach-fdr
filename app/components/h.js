// Tiny DOM builder. Every component uses this instead of innerHTML so data
// from the bundle is always inserted as text, never parsed as markup.
//
//   h("td", { class: "r-id", dataset: { rowId: "e1" } }, "ContextProcessId")
//   h("button", { onClick: () => …, "aria-pressed": "false" }, "Copy SPL")
//
// attrs:
//   class      string | array of strings (falsy entries dropped)
//   dataset    { camelKey: value }         → data-camel-key="value"
//   style      { prop: value } | string
//   on<Event>  function                     → addEventListener(event.toLowerCase())
//   anything else is set with setAttribute; `false`/null/undefined are skipped,
//   `true` sets an empty attribute.
// children: string | number | Node | array | null | false — flattened.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs && typeof attrs === "object" && !(attrs instanceof Node) && !Array.isArray(attrs)) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") {
        const cls = Array.isArray(value) ? value.filter(Boolean).join(" ") : String(value);
        if (cls) el.className = cls;
      } else if (key === "dataset") {
        for (const [k, v] of Object.entries(value)) if (v !== null && v !== undefined) el.dataset[k] = String(v);
      } else if (key === "style") {
        if (typeof value === "string") el.setAttribute("style", value);
        else for (const [k, v] of Object.entries(value)) el.style.setProperty(k, v);
      } else if (key.startsWith("on") && typeof value === "function") {
        el.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (key === "value" && "value" in el) {
        el.value = value;
      } else if (value === true) {
        el.setAttribute(key, "");
      } else {
        el.setAttribute(key, String(value));
      }
    }
  } else if (attrs !== null && attrs !== undefined) {
    children.unshift(attrs);
  }
  append(el, children);
  return el;
}

export function append(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false || child === true) continue;
    if (Array.isArray(child)) append(parent, child);
    else if (child instanceof Node) parent.appendChild(child);
    else parent.appendChild(document.createTextNode(String(child)));
  }
  return parent;
}

export function frag(...children) {
  return append(document.createDocumentFragment(), children);
}

// Replace all children of `el` with `children`.
export function replace(el, ...children) {
  el.replaceChildren();
  return append(el, children);
}

let seq = 0;
export function uid(prefix = "r") {
  seq += 1;
  return `${prefix}-${seq.toString(36)}`;
}
