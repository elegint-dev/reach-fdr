// Not-in-catalogue page: #/unknown/<name>. Ranking comes from search.matchNames.

import { h } from "../components/h.js";
import { chip } from "../components/chip.js";
import { callout } from "../components/callout.js";
import { table } from "../components/table.js";
import { empty } from "../components/empty.js";
import { matchNames, familyOf } from "../lib/search.js";

const MATCH_WHY = {
  exact: "the same name",
  prefix: "starts with what you typed",
  substring: "contains what you typed",
  fuzzy: "one or two characters away",
  family: "same name family — same kind of thing, different prefix",
};

export function render(ctx) {
  const { data } = ctx;
  const name = String(ctx.params.name || "");
  const idx = data.searchIndex();
  const hits = matchNames(name, idx);
  const counts = data.counts();
  const fam = familyOf(name);
  const top = hits[0] || null;

  const el = h("div", { class: "r-view r-view--unknown" });

  el.appendChild(
    h(
      "section",
      { class: "r-section r-hold" },
      h("div", { class: "r-hold__head" }, h("h1", { class: "r-hold__name" }, name), chip({ kind: "trust", value: "inferred", text: "not in the catalogue" })),
      h(
        "p",
        null,
        "Nothing in the catalogue is called ",
        h("code", null, name),
        `. The catalogue has ${counts.fields} field names and ${counts.events} event names; this is not one of them.`,
      ),
    ),
  );

  if (top) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        callout({
          kind: "why",
          label: "Did you mean",
          body: h(
            "div",
            null,
            h(
              "p",
              null,
              h("a", { href: `#/${top.kind === "field" ? "f" : "e"}/${encodeURIComponent(top.name)}`, class: "r-idlink" }, h("code", null, top.name)),
              ` — ${MATCH_WHY[top.match] || top.match}.`,
            ),
            fam && top.match === "family"
              ? h(
                  "p",
                  null,
                  `Names ending in ${fam.suffix} belong to the ${fam.family} family. The near match with the same stem is `,
                  h("code", null, fam.stem),
                  ".",
                )
              : null,
          ),
        }),
      ),
    );
  }

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      h("h2", null, `Nearest names (${hits.length})`),
      hits.length
        ? table({
            caption: `Names near ${name}`,
            columns: [
              { key: "name", label: "name" },
              { key: "kind", label: "kind" },
              { key: "why", label: "why it is here" },
              { key: "about", label: "what it is" },
            ],
            rows: hits.map((m) => {
              const rec = m.kind === "field" ? data.field(m.name) : data.event(m.name);
              return {
                name: h("a", { href: `#/${m.kind === "field" ? "f" : "e"}/${encodeURIComponent(m.name)}`, class: "r-idlink r-rowlink", tabindex: "0" }, h("code", null, m.name)),
                kind: m.kind,
                why: MATCH_WHY[m.match] || m.match,
                about:
                  m.kind === "field"
                    ? `${rec.layer === "cim" ? "L3 CIM" : rec.layer === "ta_derived" ? "L2 TA" : "L1 raw"} · ${rec.role} · ${rec.event_count} events`
                    : `${rec.field_count} fields · ${rec.cim && rec.cim.normalized ? "CIM normalized" : "no CIM path"}`,
              };
            }),
          })
        : empty({
            title: "Nothing is close to that",
            line: "No catalogue name is within a couple of characters of this, and it matches no known name family.",
            moves: [
              { key: "/", text: "try a shorter fragment — substring matches count" },
              { key: "4", text: "paste a value instead and let the classifier name it", href: "#/w/ioc" },
            ],
          }),
    ),
  );

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      h("h2", null, "What this catalogue covers"),
      h(
        "ul",
        { class: "r-list" },
        h("li", null, `${counts.fields} field names in one namespace: ${counts.raw_fdr} raw FDR, ${counts.ta_derived} TA-derived, ${counts.cim} CIM.`),
        h("li", null, `${counts.events} events, ${counts.events_cim_normalized} of them normalised into a CIM data model and ${counts.events_cim_gap} with no CIM path at all.`),
        h("li", null, `${counts.edges_confirmed} confirmed and ${counts.edges_asserted} asserted join edges. Nothing else is called a join.`),
        h("li", null, `${counts.enriched} fields carry an AI-written meaning from ${counts.enrichment_batches} enrichment batches, always labelled as such.`),
      ),
      h("h3", null, "And what it does not"),
      h(
        "ul",
        { class: "r-list" },
        h("li", null, "Anything your tenant adds or renames locally. This is built from the public FDR field catalogue, the Splunk TA and a public sanitized corpus."),
        h("li", null, `${counts.routes.unobserved} catalogued fields were never seen on an event in that corpus and have no computed route.`),
        h("li", null, "Fill rates, cardinality and anything that would rank fields by how often they are populated. The corpus is fixtures; those numbers do not exist."),
      ),
    ),
  );

  return el;
}

export default { render };
