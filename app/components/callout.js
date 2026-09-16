// callout — a labelled aside: glyph + label + body.
//
//   callout({ kind: "why",     body: "…" })
//   callout({ kind: "expect",  body: "…" })
//   callout({ kind: "caution", body: "…" })          monochrome, heavier rule
//   callout({ kind: "hazard",  body: "…" })          the only one with hue (red)
//   callout({ kind: "note",    label: "No CIM path", body: "…" })
//   callout({ kind: "asserted", body: "…" })         join-basis label (amber)
//
// `body` may be a string, a Node, or an array of either. `label` overrides
// the default label text.

import { h } from "./h.js";

const KINDS = {
  why: { glyph: "?", label: "Why" },
  expect: { glyph: "∴", label: "Expect" },
  caution: { glyph: "!", label: "Caution" },
  hazard: { glyph: "⚠︎", label: "Hazard" },
  note: { glyph: "※", label: "Note" },
  // Same amber as the `asserted` chip.
  asserted: { glyph: "≈", label: "Asserted" },
};

export function callout({ kind = "note", label, body, children } = {}) {
  const spec = KINDS[kind] || KINDS.note;
  const el = h(
    "div",
    { class: ["r-callout", `r-callout--${kind}`], role: kind === "hazard" ? "alert" : null },
    h("span", { class: "r-callout__glyph", "aria-hidden": "true" }, spec.glyph),
    h("span", { class: "r-callout__label" }, label ?? spec.label),
    h("div", { class: "r-callout__body" }, typeof body === "string" ? h("p", null, body) : body, children),
  );
  return el;
}

export default callout;
