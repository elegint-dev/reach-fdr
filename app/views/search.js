// Search results: #/search?q=…

import { h } from "../components/h.js";
import { table } from "../components/table.js";
import { empty } from "../components/empty.js";
import { chip } from "../components/chip.js";
import { classify, matchNames } from "../lib/search.js";

const MATCH_WHY = {
  exact: "exact",
  prefix: "prefix",
  substring: "substring",
  fuzzy: "near miss",
  family: "same name family",
};

export function render(ctx) {
  const { data } = ctx;
  const q = String(ctx.params.q || "");
  const idx = data.searchIndex();
  const el = h("div", { class: "r-view r-view--search" });

  if (!q.trim()) {
    el.appendChild(
      empty({
        title: "Nothing searched yet",
        line: "Type anything you are holding — a field name, an event, a CIM name, a hash, an IP, a PID.",
        moves: [{ key: "/", text: "focus the search box" }, { key: "1", text: "or start from one of the four holdings", href: "#/" }],
      }),
    );
    return el;
  }

  const c = classify(q, idx);
  const hits = c.kind === "name" ? c.candidates : matchNames(q, idx);

  el.appendChild(
    h(
      "section",
      { class: "r-section r-hold" },
      h("div", { class: "r-hold__head" }, h("h1", { class: "r-hold__name" }, q), c.kind !== "name" ? chip({ kind: "trust", value: "inferred", text: c.kind.replace(/_/g, " ") }) : null),
      h("p", { class: "r-secondary" }, `${hits.length} name${hits.length === 1 ? "" : "s"} match.`),
      c.kind !== "name"
        ? h(
            "p",
            null,
            "That also reads as a value — ",
            h("a", { href: `#/v/${encodeURIComponent(q)}` }, "see what carries it"),
            ".",
          )
        : null,
    ),
  );

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      hits.length
        ? table({
            caption: `Matches for ${q}`,
            columns: [
              { key: "name", label: "name" },
              { key: "kind", label: "kind" },
              { key: "about", label: "what it is" },
              { key: "why", label: "match" },
            ],
            rows: hits.map((m) => {
              const rec = m.kind === "field" ? data.field(m.name) : data.event(m.name);
              return {
                name: h("a", { href: `#/${m.kind === "field" ? "f" : "e"}/${encodeURIComponent(m.name)}`, class: "r-idlink r-rowlink", tabindex: "0" }, h("code", null, m.name)),
                kind: m.kind,
                about:
                  m.kind === "field"
                    ? `${rec.layer === "cim" ? "L3 CIM" : rec.layer === "ta_derived" ? "L2 TA" : "L1 raw"} · ${rec.role} · ${rec.event_count} events`
                    : `${rec.field_count} fields · ${rec.cim && rec.cim.normalized ? "CIM normalized" : "no CIM path"}`,
                why: MATCH_WHY[m.match] || m.match,
              };
            }),
          })
        : empty({
            title: "No name matches",
            line: `Nothing in the catalogue is called ${q} or anything close to it.`,
            moves: [{ key: "", text: "see what is near it", href: `#/unknown/${encodeURIComponent(q)}` }],
          }),
    ),
  );

  return el;
}

export default { render };
