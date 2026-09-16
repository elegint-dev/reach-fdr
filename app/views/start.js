// Start page: #/

import { h } from "../components/h.js";
import { empty } from "../components/empty.js";
import { keycap } from "../components/keycap.js";
import * as fieldView from "./field.js";

// The field the inline example renders.
const TEASER = { name: "ResponsiblePid", on: "LoginItemAdded" };

function card(ctx, c, line) {
  return h(
    "a",
    { class: "r-card", href: c.href },
    h("span", { class: "r-card__key" }, keycap({ key: c.key })),
    h("span", { class: "r-card__title" }, c.title),
    h("span", { class: "r-card__line" }, c.line),
    line ? h("span", { class: "r-card__count" }, line) : null,
  );
}

// No-op drawer: the example is a rendering, not a second interactive surface.
const nullDrawer = {
  setTitle() {},
  setSpl() {},
  setParams() {},
  setHazards() {},
  setState() {},
  showTab() {},
  copy() {},
};

export function render(ctx) {
  const { data } = ctx;
  const counts = data.counts();
  const el = h("div", { class: "r-view r-view--start" });

  el.appendChild(
    h(
      "section",
      { class: "r-section r-lede" },
      h("h1", { class: "r-lede__name" }, "Reach"),
      h(
        "p",
        { class: "r-lede__line" },
        "What you can get to from the thing you are holding, what that costs, and how much to trust it — for CrowdStrike FDR.",
      ),
      empty({
        title: "What are you holding?",
        line:
          "Type it, paste it, or take one of the four below.",
        moves: [
          { key: "/", text: "type a field, an event, a CIM name, a hash, an IP, a PID" },
          { key: "?", text: "see every key" },
        ],
      }),
    ),
  );

  const lines = {
    host: `${counts.edges_confirmed} confirmed joins, aidmaster among them`,
    pid: `${counts.routes.one_hop} fields are one join from the process`,
    detection: `${counts.events_cim_gap} of ${counts.events} events have no CIM path`,
    ioc: `${counts.fields} fields, ${counts.enriched} with a written meaning`,
  };

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      h("div", { class: "r-cards" }, (ctx.cards || []).map((c) => card(ctx, c, lines[c.id]))),
      h(
        "p",
        { class: "r-muted" },
        `Built from ${counts.fields} fields and ${counts.events} events · ${counts.raw_fdr} raw, ${counts.ta_derived} TA-derived, ${counts.cim} CIM · ${counts.edges_confirmed} confirmed and ${counts.edges_asserted} asserted edges · ${counts.decode_tables} decode tables · ${counts.suggested_joins} enrichment suggestions, kept separate from the joins.`,
      ),
    ),
  );

  // ---- the live example -------------------------------------------------
  const teaserCtx = {
    ...ctx,
    params: { name: TEASER.name, on: TEASER.on },
    drawer: nullDrawer,
    compact: true,
    setUrl: () => {},
    setDrawerParamHandler: () => {},
    setDrawerCopyHandler: () => {},
  };

  let teaser = null;
  try {
    teaser = fieldView.render(teaserCtx);
  } catch (err) {
    console.error("teaser failed to render", err);
  }

  if (teaser) {
    el.appendChild(
      h(
        "section",
        { class: "r-section r-teaser" },
        h(
          "div",
          { class: "r-teaser__head" },
          h("h2", null, "What a page looks like"),
          h(
            "p",
            { class: "r-secondary" },
            "This is the real page for ",
            h("a", { href: `#/f/${TEASER.name}?on=${TEASER.on}` }, h("code", null, TEASER.name)),
            " on ",
            h("code", null, TEASER.on),
            ", rendered here from the same data. Free first, then one join, then what enrichment merely suggests, then what you cannot get at all.",
          ),
        ),
        h("div", { class: "r-teaser__body", inert: "" }, teaser),
      ),
    );
  }

  return el;
}

export default { render };
