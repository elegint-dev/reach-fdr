// table — a dense data table: zebra rows, sticky header, mono where the
// column says so.
//
//   table({
//     caption: "Fields on DnsRequest, by role",
//     captionVisible: false,
//     columns: [{ key: "field", label: "field", mono: true }, { key: "role", label: "role" }, { key: "layer", label: "layer" }],
//     rows: [{ field: "DomainName", role: "domain", layer: chip({…}) }],
//     rowId: (row) => row.field,       // optional; sets data-row-id
//     maxHeight: "320px",               // optional; makes the header sticky within a scroll box
//   })
// Cells may be strings, numbers, Nodes, or { mono, text, muted, align }.

import { h } from "./h.js";

function cellContent(value, col) {
  if (value === null || value === undefined) return "";
  if (value instanceof Node) return value;
  if (typeof value === "object" && !Array.isArray(value)) {
    if (value.mono !== undefined) return h("code", null, value.mono);
    return value.text ?? "";
  }
  return col && col.mono ? h("code", null, String(value)) : String(value);
}

export function table({ caption, captionVisible = false, columns = [], rows = [], rowId, maxHeight, class: extra } = {}) {
  const tbl = h(
    "table",
    { class: ["r-table", extra] },
    caption ? h("caption", { class: captionVisible ? null : "r-sr" }, caption) : null,
    h(
      "thead",
      null,
      h(
        "tr",
        null,
        columns.map((c) => h("th", { scope: "col", class: [c.align && `r-table__${c.align}`, c.mono && "r-table__mono"] }, c.label ?? c.key)),
      ),
    ),
    h(
      "tbody",
      null,
      rows.map((row) =>
        h(
          "tr",
          { dataset: rowId ? { rowId: rowId(row) } : null },
          columns.map((c) => {
            const v = row[c.key];
            const align = (v && typeof v === "object" && !(v instanceof Node) && v.align) || c.align;
            const muted = v && typeof v === "object" && !(v instanceof Node) && v.muted;
            return h("td", { class: [align && `r-table__${align}`, muted && "r-muted"] }, cellContent(v, c));
          }),
        ),
      ),
    ),
  );
  return h("div", { class: "r-table-wrap", style: maxHeight ? { "max-height": maxHeight } : null }, tbl);
}

export default table;
