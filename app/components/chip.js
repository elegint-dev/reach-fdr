// chip — the one place hue appears on data.
//
//   chip({ kind: "layer", value: "raw_fdr" })                 → L1 raw   (monochrome)
//   chip({ kind: "trust", value: "asserted" })                → asserted (amber)
//   chip({ kind: "trust", value: "suggested", confidence: "medium" })
//                                                             → suggested ▮▮▯ medium (violet)
//   chip({ kind: "hazard" })                                  → hazard   (red)
//   chip({ kind: "route", value: "one-hop" })                 → ⤳ one join (monochrome)
//
// Every chip renders visible text. Colour is never the only carrier.

import { h } from "./h.js";

const LAYERS = {
  raw_fdr: ["L1", "raw"],
  ta_derived: ["L2", "TA"],
  cim: ["L3", "CIM"],
  L1: ["L1", "raw"],
  L2: ["L2", "TA"],
  L3: ["L3", "CIM"],
};

const TRUST = {
  confirmed: "confirmed",
  confirmed_ta: "confirmed",
  asserted: "asserted",
  suggested: "suggested",
  inferred: "inferred",
};

const CONFIDENCE = { high: 3, medium: 2, low: 1 };

// Cost is position plus a glyph — never a hue.
const ROUTES = {
  here: ["≡", "here"],
  "one-hop": ["⤳", "one join"],
  one_hop: ["⤳", "one join"],
  "dead-end": ["⊘", "dead end"],
  dead_end: ["⊘", "dead end"],
};

export function chip(props = {}) {
  const { kind = "trust", value, text, title, confidence } = props;

  if (kind === "layer") {
    const [n, label] = LAYERS[value] || ["L?", String(value ?? "")];
    return h(
      "span",
      { class: "r-chip r-chip--layer", title: title || `layer ${n}: ${label}` },
      h("b", { class: "r-chip__n" }, n),
      h("span", { class: "r-chip__text" }, text ?? label),
    );
  }

  if (kind === "route") {
    const [glyph, label] = ROUTES[value] || ["·", String(value ?? "")];
    return h(
      "span",
      { class: ["r-chip", "r-chip--route", `r-chip--route-${label.replace(/\s+/g, "-")}`], title },
      h("span", { class: "r-chip__glyph", "aria-hidden": "true" }, glyph),
      h("span", { class: "r-chip__text" }, text ?? label),
    );
  }

  if (kind === "hazard") {
    return h(
      "span",
      { class: "r-chip r-chip--hazard", title },
      h("span", { class: "r-chip__glyph", "aria-hidden": "true" }, "!"),
      h("span", { class: "r-chip__text" }, text ?? "hazard"),
    );
  }

  // trust (with optional confidence meter)
  const tier = TRUST[value] || "inferred";
  const label = text ?? tier;
  const el = h("span", { class: ["r-chip", "r-chip--trust", `r-chip--${tier}`], title });
  el.appendChild(h("span", { class: "r-chip__text" }, label));

  if (confidence && CONFIDENCE[confidence]) {
    const filled = CONFIDENCE[confidence];
    const meter = h("span", { class: ["r-meter", `r-meter--${confidence}`], "aria-hidden": "true" });
    for (let i = 1; i <= 3; i++) meter.appendChild(h("i", { class: i <= filled ? "is-on" : null }));
    el.appendChild(meter);
    el.appendChild(h("span", { class: "r-chip__conf" }, confidence));
    el.setAttribute("aria-label", `${label}, ${confidence} confidence`);
  }
  return el;
}

export default chip;
