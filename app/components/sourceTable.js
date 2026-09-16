// sourceTable — the CIM ↔ raw walk-back, event-conditional, with the
// TA statement that does it. Reads FieldRecord.sources (CIM/TA → raw) or
// FieldRecord.cim_targets (raw → CIM); pass whichever you have.
//
//   sourceTable({
//     field: "process_id",
//     direction: "sources" | "targets",
//     caption: "Where process_id comes from, by event",
//     rows: [{
//       raw_field: "TargetProcessId",  // or cim_field for direction "targets"
//       cim_field: "process_id",
//       via: "EVAL",
//       sourcetype: "crowdstrike:events:sensor",
//       events: ["ProcessRollup2", "SyntheticProcessRollup2", …],
//       statement: "case(event_simpleName IN (…), TargetProcessId, …)",
//     }],
//   })
//
// Every row is TA-sourced (confirmed). Long event lists collapse behind <details>.

import { h } from "./h.js";
import { chip } from "./chip.js";

const INLINE_EVENTS = 4;

function eventList(events = []) {
  if (!events.length) return h("span", { class: "r-muted" }, "no events");
  const codes = (list) => list.flatMap((e, i) => [i ? ", " : null, h("code", null, e)]);
  if (events.length <= INLINE_EVENTS) return h("span", { class: "r-source-table__events" }, codes(events));
  return h(
    "details",
    { class: "r-source-table__more" },
    h("summary", null, codes(events.slice(0, INLINE_EVENTS)), h("span", { class: "r-muted" }, ` and ${events.length - INLINE_EVENTS} more`)),
    h("div", { class: "r-source-table__all" }, codes(events.slice(INLINE_EVENTS))),
  );
}

export function sourceTable({ field, direction = "sources", caption, rows = [] } = {}) {
  const fromLabel = direction === "targets" ? "raw field" : "CIM / TA field";
  const toLabel = direction === "targets" ? "CIM / TA field" : "raw source";
  const fromKey = direction === "targets" ? "raw_field" : "cim_field";
  const toKey = direction === "targets" ? "cim_field" : "raw_field";

  const tbl = h(
    "table",
    { class: "r-source-table" },
    h("caption", { class: caption ? null : "r-sr" }, caption || `Event-conditional mapping for ${field ?? ""}`),
    h(
      "thead",
      null,
      h(
        "tr",
        null,
        h("th", { scope: "col" }, fromLabel),
        h("th", { scope: "col" }, toLabel),
        h("th", { scope: "col" }, "via"),
        h("th", { scope: "col" }, "on events"),
        h("th", { scope: "col" }, "statement"),
      ),
    ),
    h(
      "tbody",
      null,
      rows.map((r) =>
        h(
          "tr",
          null,
          h("td", null, h("code", null, r[fromKey] ?? field ?? "")),
          h("td", null, h("code", null, r[toKey] ?? "")),
          h(
            "td",
            null,
            h("span", { class: "r-source-table__via" }, h("code", null, r.via ?? ""), " ", chip({ kind: "trust", value: "confirmed", text: "confirmed" })),
            r.sourcetype ? h("div", { class: "r-source-table__st r-muted" }, h("code", null, r.sourcetype)) : null,
          ),
          h("td", null, eventList(r.events)),
          h("td", { class: "r-source-table__stmt" }, r.statement ? h("pre", { tabindex: "0" }, h("code", null, r.statement)) : h("span", { class: "r-muted" }, "—")),
        ),
      ),
    ),
  );
  return h("div", { class: "r-table-wrap r-source-table-wrap" }, tbl);
}

export default sourceTable;
