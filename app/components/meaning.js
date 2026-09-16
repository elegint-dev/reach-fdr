// meaning — what a field means, where that meaning came from, and the
// evidence behind it (toggle).
//
//   meaning({
//     description: "The process ID of the process responsible for the modification.",
//     hunting_notes: "…",           // optional
//     data_format: "…",             // optional
//     source: "enrichment" | "decode_table" | "ta" | "reference" | "curated" | "name_convention",
//     confidence: "high",           // enrichment only
//     evidence: "…",                // enrichment only; rendered under a toggle
//     statement: "case(event_simpleName IN (…), TargetProcessId, …)",  // ta only: the EVAL/LOOKUP body
//     absent: true,                 // nothing on disk explains the field
//   })
//
// Trust line, by source:
//   decode_table    confirmed — the TA's lookup table names the value
//   ta              confirmed — the TA computes it; the statement is shown
//   reference       asserted  — CrowdStrike documentation, not corpus-validated
//   curated         asserted  — hand-authored in data/curated/, validated by the build
//   enrichment      suggested — AI enrichment, with its confidence meter and evidence
//   name_convention inferred  — the name pattern alone

import { h, uid } from "./h.js";
import { chip } from "./chip.js";

const SOURCES = {
  decode_table: { trust: "confirmed", line: "From the TA's decode table: the lookup names this value." },
  ta: { trust: "confirmed", line: "The TA computes this; the statement is below." },
  reference: { trust: "asserted", line: "From CrowdStrike's documentation. Not validated against the corpus." },
  curated: { trust: "asserted", line: "Hand-authored in data/curated/translations.json." },
  enrichment: { trust: "suggested", line: "From AI enrichment." },
  name_convention: { trust: "inferred", line: "Read from the name alone. Nothing on disk explains this field." },
};

export function meaning(props = {}) {
  const { description, hunting_notes, data_format, source, confidence, evidence, statement, absent } = props;

  if (absent || (!description && !source)) {
    return h(
      "div",
      { class: "r-meaning r-meaning--absent" },
      h("p", { class: "r-meaning__desc r-muted" }, "Nothing on disk explains this field. The name is all there is."),
      h("p", { class: "r-meaning__trust" }, chip({ kind: "trust", value: "inferred" }), h("span", null, SOURCES.name_convention.line)),
    );
  }

  const spec = SOURCES[source] || SOURCES.name_convention;
  const evId = uid("evidence");

  return h(
    "div",
    { class: ["r-meaning", `r-meaning--${spec.trust}`] },
    h("p", { class: "r-meaning__desc" }, description ?? ""),
    data_format ? h("p", { class: "r-meaning__format" }, h("span", { class: "r-muted" }, "Format "), h("code", null, data_format)) : null,
    hunting_notes ? h("p", { class: "r-meaning__notes" }, hunting_notes) : null,
    h(
      "p",
      { class: "r-meaning__trust" },
      chip({ kind: "trust", value: spec.trust, confidence: source === "enrichment" ? confidence : undefined }),
      h("span", null, spec.line),
    ),
    statement ? h("pre", { class: "r-meaning__statement", tabindex: "0" }, h("code", null, statement)) : null,
    evidence
      ? h(
          "details",
          { class: "r-meaning__evidence", id: evId },
          h("summary", null, "Evidence"),
          h("p", null, evidence),
        )
      : null,
  );
}

export default meaning;
