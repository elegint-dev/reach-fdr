// ledger — the pivot map. One band per cost tier, top to bottom; each band
// is a real <table> with <caption> and <th scope="col">.
//
//   ledger({
//     selectedId: "e_context_to_target",
//     bands: [{
//       id: "one-join",
//       kind: "here" | "automatic" | "one-join" | "suggested" | "unreachable",
//       title: "One join",            // optional; defaults per kind
//       caption: "…",                 // <caption>, visually hidden by default
//       note: "…" | Node,             // one line under the heading
//       columns: ["target", "via", "scope", "cardinality", "basis"],
//       rows: [{
//         id: "e_context_to_target",
//         cells: ["the process that caused this event", { mono: "ContextProcessId → TargetProcessId" }, "same aid", "n:1", chip(…)],
//         hazard: false,              // hazard rows get the red rule
//         disabled: false,            // unreachable rows are not selectable
//       }],
//       empty: "…" | Node,            // shown as a single full-width row when rows is empty
//     }],
//   })
//
// Cost is carried by band order and a glyph; trust by the chip the caller
// puts in a cell. Rows are focusable (tabindex=0, data-row-id) and dispatch
// a bubbling `select` CustomEvent (detail: { rowId, bandId, row }) on click
// or Enter. Arrow-key movement is the spine's job.
//
// Element API: el.select(rowId) marks the row aria-selected; el.rows() lists
// the <tr>s in order.

import { h, uid } from "./h.js";

const BANDS = {
  here: { glyph: "≡", title: "Here", sub: "already on the record, free" },
  automatic: { glyph: "⚙", title: "Automatic", sub: "the TA does this at search time; already on the record" },
  "one-join": { glyph: "⤳", title: "One join", sub: "key, scope, cardinality, basis" },
  suggested: { glyph: "≈", title: "Suggested", sub: "enrichment, not validated" },
  unreachable: { glyph: "⊘", title: "Not reachable", sub: "and the closest you can get" },
};

function cell(content, tag = "td", extra = {}) {
  if (content === null || content === undefined) return h(tag, extra, "");
  if (content instanceof Node) return h(tag, extra, content);
  if (typeof content === "object" && !Array.isArray(content)) {
    const { mono, text, muted, wrap } = content;
    return h(
      tag,
      { ...extra, class: [muted && "r-muted", wrap && "r-ledger__wrap"] },
      mono !== undefined ? h("code", null, mono) : text ?? "",
    );
  }
  return h(tag, extra, content);
}

export function ledger({ bands = [], selectedId = null, caption } = {}) {
  const el = h("div", { class: "r-ledger", role: "group", "aria-label": caption || "Reach ledger" });
  let selected = selectedId;

  function selectRow(rowId) {
    selected = rowId;
    for (const tr of el.querySelectorAll("tr[data-row-id]")) {
      const on = tr.dataset.rowId === rowId;
      tr.classList.toggle("is-selected", on);
      tr.setAttribute("aria-selected", on ? "true" : "false");
    }
  }

  for (const band of bands) {
    const spec = BANDS[band.kind] || BANDS.here;
    const headId = uid("band");
    const columns = band.columns || [];
    const rows = band.rows || [];

    const table = h(
      "table",
      { class: "r-ledger__table" },
      h("caption", { class: band.captionVisible ? null : "r-sr" }, band.caption || `${spec.title}: ${spec.sub}`),
      columns.length
        ? h("thead", null, h("tr", null, columns.map((c) => cell(c, "th", { scope: "col" }))))
        : null,
    );

    const tbody = h("tbody");
    if (rows.length === 0) {
      tbody.appendChild(
        h(
          "tr",
          { class: "r-ledger__empty" },
          h("td", { colspan: Math.max(columns.length, 1) }, typeof band.empty === "string" ? band.empty : band.empty ?? "Nothing here."),
        ),
      );
    }
    for (const row of rows) {
      const tr = h(
        "tr",
        {
          class: ["r-ledger__row", row.hazard && "r-ledger__row--hazard", row.disabled && "r-ledger__row--disabled"],
          tabindex: row.disabled ? null : "0",
          dataset: { rowId: row.id, bandId: band.id },
          "aria-selected": row.id === selected ? "true" : "false",
          "aria-disabled": row.disabled ? "true" : null,
        },
        (row.cells || []).map((c, i) => cell(c, "td", i === 0 ? { class: "r-ledger__lead" } : {})),
      );
      if (row.id === selected) tr.classList.add("is-selected");
      if (!row.disabled) {
        const fire = (e) => {
          selectRow(row.id);
          el.dispatchEvent(new CustomEvent("select", { bubbles: true, detail: { rowId: row.id, bandId: band.id, row } }));
          if (e.type === "keydown") e.preventDefault();
        };
        tr.addEventListener("click", (e) => {
          if (e.target.closest("a, button, input, details")) return;
          fire(e);
        });
        tr.addEventListener("keydown", (e) => {
          if (e.key === "Enter") fire(e);
        });
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);

    const section = h(
      "section",
      { class: ["r-ledger__band", `r-ledger__band--${band.kind}`], "aria-labelledby": headId, dataset: { bandId: band.id ?? band.kind } },
      h(
        "h3",
        { id: headId, class: "r-ledger__head" },
        h("span", { class: "r-ledger__glyph", "aria-hidden": "true" }, spec.glyph),
        h("span", { class: "r-ledger__title" }, band.title || spec.title),
        h("span", { class: "r-ledger__count" }, `${rows.length}`),
      ),
      band.note ? h("p", { class: "r-ledger__note" }, band.note) : null,
      h("div", { class: "r-ledger__scroll" }, table),
    );
    el.appendChild(section);
  }

  el.select = selectRow;
  el.rows = () => Array.from(el.querySelectorAll("tr[data-row-id]:not([aria-disabled])"));
  return el;
}

export default ledger;
