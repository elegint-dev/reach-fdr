// Field page: #/f/<name>?on=<event>&sel=<rowId>
// Header, then the ledger (HERE · AUTOMATIC · ONE JOIN · SUGGESTED · NOT REACHABLE).
// Reachability is read off the selected event, not the field. All SPL comes
// from spl.generate().

import { decodeWidget, epochWidget } from "../components/convert.js";
import { h } from "../components/h.js";
import { chip } from "../components/chip.js";
import { ledger } from "../components/ledger.js";
import { meaning } from "../components/meaning.js";
import { sourceTable } from "../components/sourceTable.js";
import { callout } from "../components/callout.js";
import * as spl from "../lib/spl.js";
import { familyOf } from "../lib/search.js";
import * as unknownView from "./unknown.js";

export const NO_FILL_RATES =
  "Grouped by role, then alphabetical. No fill-rate data is available for ordering.";

const ROUTE_TEXT = {
  direct_anchor: { chip: "here", label: "on an anchor event" },
  one_hop: { chip: "one-hop", label: "one join to the process" },
  host_only: { chip: "dead-end", label: "host and time only" },
  mixed: { chip: "one-hop", label: "depends on the event" },
  unobserved: { chip: "dead-end", label: "never observed" },
  derived: { chip: "dead-end", label: "computed field" },
};

const BASIS_LABEL = {
  decode_table: "the TA's decode table",
  meaning_sibling: "a sibling *_meaning field",
  dotted_prefix: "the dotted name prefix",
  name_convention: "the name convention",
  enrichment: "AI enrichment",
  none: "nothing — it stayed unclassified",
};

const EDGE_ORDER = [
  "causal_attribution",
  "process_lineage",
  "tree_grouping",
  "detection_handle",
  "host_enrichment",
  "file_enrichment",
  "user_enrichment",
  "os_pid",
];

const PARAM_META = {
  aid: { placeholder: "32-hex agent id", hint: "The host. Both PID spaces are per-host, and ComputerName is not stable — aid is." },
  earliest: { placeholder: "-24h", hint: "Index time (_time), not the sensor's timestamp." },
  latest: { placeholder: "now" },
  value: { placeholder: "the value you hold" },
  pid: { placeholder: "OS PID" },
  tpid: { placeholder: "TargetProcessId" },
  hostname: { placeholder: "COMPUTERNAME" },
  field: {},
  event: {},
  index: { placeholder: "leave empty to use the cs_index macro" },
  sourcetype: {},
};

const PID_HANDLES = new Set(["TargetProcessId", "ContextProcessId", "ParentProcessId", "RawProcessId"]);

// ---------------------------------------------------------------------------
// Pure helpers (exported for tests/views.test.js)

// A search-time lookup is free only where the TA's stanza fires (edge.automatic_on).
export function isAutomaticOn(edge, eventRec) {
  return Boolean(eventRec) && edge.mechanism === "search_time_lookup"
    && (edge.automatic_on || []).includes(eventRec.sourcetype);
}

export function edgeRowsFor(edges, eventRec, fieldName) {
  if (!eventRec) return [];
  const present = new Set(eventRec.fields || []);
  // Offered only if the key rides on this event and, for process-side edges
  // (dst TargetProcessId), is a real handle there — never re-derived from name
  // presence (detection events carry *ProcessId names in an unestablished space).
  const handles = new Set(eventRec.handles || []);
  const usable = (e) => present.has(e.src) && (e.dst !== "TargetProcessId" || handles.has(e.src));
  const rows = edges.filter(usable).map((e) => ({ edge: e, viaSelf: e.src === fieldName }));
  rows.sort((a, b) => {
    if (a.viaSelf !== b.viaSelf) return a.viaSelf ? -1 : 1;
    const ai = EDGE_ORDER.indexOf(a.edge.kind);
    const bi = EDGE_ORDER.indexOf(b.edge.kind);
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || String(a.edge.id).localeCompare(String(b.edge.id));
  });
  return rows;
}

// Pivot for a ONE JOIN row: the edge itself, except a co-field hop to the
// process uses `trace` so the held field stays in the search.
export function pivotForEdgeRow(row, fieldName) {
  const e = row.edge;
  if (row.viaSelf) return { kind: "edge", edge: e };
  if (e.dst === "TargetProcessId") return { kind: "trace" };
  return { kind: "edge", edge: e };
}

export function baseParamsForRow(row, fieldName, eventName) {
  const pivot = pivotForEdgeRow(row, fieldName);
  if (pivot.kind === "trace") return { field: fieldName, event: eventName };
  return {};
}

// ---------------------------------------------------------------------------

function layerChip(rec) {
  return chip({ kind: "layer", value: rec.layer });
}

function routeChip(rec) {
  const r = ROUTE_TEXT[rec.route && rec.route.summary] || ROUTE_TEXT.mixed;
  return chip({ kind: "route", value: r.chip, text: r.label });
}

function basisChip(edge) {
  if (edge.cardinality === "unsafe" || edge.hazard) return chip({ kind: "hazard", text: "unsafe key" });
  return edge.basis === "confirmed_ta"
    ? chip({ kind: "trust", value: "confirmed", title: edge.basis_ref })
    : chip({ kind: "trust", value: "asserted", title: edge.basis_ref });
}

function scopeText(edge) {
  const s = Array.isArray(edge.scope) ? edge.scope : [];
  if (!s.length) return "global";
  if (s.includes("time")) return "same aid and time window";
  return "same " + s.join(" and ");
}

function fieldLink(name) {
  return h("a", { href: `#/f/${encodeURIComponent(name)}`, class: "r-idlink" }, h("code", null, name));
}

function eventLink(name) {
  return h("a", { href: `#/e/${encodeURIComponent(name)}`, class: "r-idlink" }, h("code", null, name));
}

function handlesCell(evRec) {
  const hs = (evRec && evRec.handles) || [];
  if (!hs.length) return h("span", { class: "r-muted" }, "none");
  return h("span", { class: "r-inline" }, hs.flatMap((n, i) => [i ? " " : null, h("code", null, n)]));
}

function cimCell(evRec) {
  if (evRec && evRec.cim && evRec.cim.normalized) {
    return h("span", null, (evRec.cim.data_models || []).join(", ") || "normalized");
  }
  return h("span", { class: "r-muted" }, "no CIM path");
}

// ---------------------------------------------------------------------------

export function render(ctx) {
  const { data } = ctx;
  const name = ctx.params.name;
  const rec = data.field(name);
  if (!rec) return unknownView.render({ ...ctx, params: { ...ctx.params, name } });

  const events = rec.events || [];
  let on = ctx.params.on && events.includes(ctx.params.on) ? ctx.params.on : events[0] || null;
  if (on && on !== ctx.params.on) ctx.setUrl("field", { ...ctx.params, name, on });
  const evRec = on ? data.event(on) : null;

  const compact = ctx.compact === true;
  const el = h("div", { class: "r-view r-view--field" });
  el.appendChild(header(ctx, rec, compact));

  if (!compact && (rec.sources || []).length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        h("h2", null, "Where it comes from"),
        h("p", { class: "r-secondary" }, "This field is computed by the TA. Which raw field feeds it depends on the event — this is the walk-back, not a 1:1 rename."),
        sourceTable({ field: rec.name, direction: "sources", rows: rec.sources }),
      ),
    );
  }
  if (!compact && (rec.cim_targets || []).length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        h("h2", null, "Where it goes"),
        h("p", { class: "r-secondary" }, "The TA maps this raw field onto CIM / TA names, and which name it lands on depends on the event."),
        sourceTable({ field: rec.name, direction: "targets", rows: rec.cim_targets }),
      ),
    );
  }

  // ---- the ledger -------------------------------------------------------
  const oneJoinRows = edgeRowsFor(data.edges(), evRec, rec.name);
  const specs = new Map(); // rowId → { pivot, params, title, subtitle, hazards, errorParams }

  const hereRows = events.map((evName) => {
    const r = data.event(evName);
    specs.set(`ev-${evName}`, {
      pivot: { kind: "event_sample" },
      params: { event: evName },
      title: `See ${evName} on real data`,
      subtitle: `${rec.name} rides on this event · ${(r && r.sourcetype) || ""}`,
      errorParams: ["event", "earliest"],
    });
    return {
      id: `ev-${evName}`,
      cells: [eventLink(evName), handlesCell(r), cimCell(r)],
    };
  });

  const evSt = evRec ? evRec.sourcetype : null;
  const isAutomatic = (e) => isAutomaticOn(e, evRec);
  const autoRows = oneJoinRows.filter((row) => isAutomatic(row.edge)).map((row) => {
    const e = row.edge;
    const viaText = `${e.src} → ${e.dst}`;
    specs.set(e.id, {
      pivot: { kind: "edge", edge: e },
      params: baseParamsForRow(row, rec.name, on),
      title: `${e.target_label} — manual fallback`,
      subtitle: `${viaText}; the TA already applies this on ${on}`,
      valueOwner: e.src,
      errorParams: ["value"],
    });
    const yields = (e.yields || []).filter((y) => data.field(y));
    return {
      id: e.id,
      cells: [
        h("div", null, h("span", null, e.target_label), h("p", { class: "r-ledger__sub r-muted" }, `keyed on ${e.src}, which rides on this event; nothing to run`)),
        { mono: viaText },
        h(
          "div",
          { class: "r-ledger__yields" },
          yields.slice(0, 5).map((y, i) => h("span", null, i ? " " : "", h("a", { href: `#/f/${encodeURIComponent(y)}`, class: "r-idlink" }, h("code", null, y)))),
          yields.length > 5 ? h("span", { class: "r-muted" }, ` +${yields.length - 5} more`) : null,
        ),
        basisChip(e),
      ],
    };
  });

  const joinRows = oneJoinRows.filter((row) => !isAutomatic(row.edge)).map((row) => {
    const e = row.edge;
    const pivot = pivotForEdgeRow(row, rec.name);
    const viaText = e.dst ? `${e.src} → ${e.dst}` : `${e.src} (lookup, not a join)`;
    specs.set(e.id, {
      pivot,
      params: baseParamsForRow(row, rec.name, on),
      title: e.target_label,
      subtitle: row.viaSelf ? `${viaText} from ${rec.name} on ${on}` : `${rec.name} → ${viaText} on ${on}`,
      valueOwner: pivot.kind === "trace" ? rec.name : e.src,
      errorParams: ["value", "aid", "earliest", "latest"],
    });
    return {
      id: e.id,
      hazard: Boolean(e.hazard) || e.cardinality === "unsafe",
      cells: [
        h(
          "div",
          null,
          h("span", null, e.target_label),
          row.viaSelf
            ? null
            : h("p", { class: "r-ledger__sub r-muted" }, `not on ${rec.name} itself — the hop is ${e.src}, which rides on this same event`),
          e.enrichment_concurs
            ? h("p", { class: "r-ledger__sub r-muted" }, `enrichment agrees (${e.enrichment_concurs.confidence}): ${e.enrichment_concurs.why}`)
            : null,
        ),
        { mono: viaText },
        scopeText(e),
        { mono: e.cardinality },
        basisChip(e),
      ],
    };
  });

  const suggestedRows = (rec.suggested_joins || []).map((s) => ({
    id: `s-${s.to}`,
    disabled: true,
    cells: [
      fieldLink(s.to),
      { text: s.why, wrap: true },
      chip({ kind: "trust", value: "suggested", confidence: s.confidence }),
    ],
  }));

  const unreachable = unreachableBand(ctx, rec, on, evRec, oneJoinRows, specs);

  const led = ledger({
    selectedId: ctx.params.sel || null,
    caption: `Reach ledger for ${rec.name}${on ? ` on ${on}` : ""}`,
    bands: [
      {
        id: "here",
        kind: "here",
        title: "Here",
        note: events.length
          ? h(
              "span",
              null,
              `${rec.name} rides on ${events.length} event${events.length === 1 ? "" : "s"}. Pick one — it scopes everything below. `,
              h("kbd", null, "e"),
              " cycles.",
            )
          : "This field is in the catalogue but was never observed on an event in the public corpus.",
        columns: ["event", "process handles", "CIM"],
        rows: hereRows,
        empty: "No events carry this field in the public corpus, so there is nothing free to show.",
      },
      {
        id: "automatic",
        kind: "automatic",
        note: on
          ? `Lookups the Splunk TA runs for you at search time on ${evSt}. Their output fields are already on every ${on} record — no query, no join. Select a row only if you need the manual fallback.`
          : "No event selected.",
        columns: ["target", "via", "already on the record", "basis"],
        rows: autoRows,
        empty: on ? `No TA lookup fires on ${on}'s sourcetype for a key it carries.` : "Nothing to show.",
      },
      {
        id: "one-join",
        kind: "one-join",
        note: on
          ? `Everything that costs a query from ${on}. A row is here only when its key actually rides on this event.`
          : "No event selected, so nothing can be shown as reachable.",
        columns: ["target", "via", "scope", "cardinality", "basis"],
        rows: joinRows,
        empty: on
          ? `Nothing on ${on} is a join key: no field on this event is the source of a typed edge.`
          : "Nothing to join from.",
      },
      {
        id: "suggested",
        kind: "suggested",
        note: "AI enrichment's candidates. Not joins, not validated, never merged into the band above. Follow the name to read that field first.",
        columns: ["candidate", "why enrichment suggested it", "basis"],
        rows: suggestedRows,
        empty: "Enrichment suggested no companion field for this one.",
      },
      unreachable,
    ],
  });

  if (evRec) {
    const hereSection = led.querySelector('[data-band-id="here"]');
    if (hereSection) hereSection.appendChild(coFieldsBlock(ctx, rec, on));
  }

  el.appendChild(h("section", { class: "r-section" }, led));

  // ---- drawer wiring ----------------------------------------------------
  const userParams = {};
  let currentId = null;

  function paramInputs(names, spec) {
    return names.map((n) => {
      const meta = PARAM_META[n] || {};
      let hint = meta.hint;
      if (n === "value" && spec && spec.valueOwner) hint = `the ${spec.valueOwner} value you are holding`;
      return {
        name: n,
        label: n,
        value: userParams[n] ?? "",
        placeholder: meta.placeholder || "",
        hint,
        required: true,
      };
    });
  }

  function fill(rowId, rebuild) {
    const spec = specs.get(rowId);
    if (!spec) return;
    currentId = rowId;
    const params = { ...spec.params, ...userParams };
    let inline;
    try {
      inline = spl.generate(spec.pivot, params);
    } catch (err) {
      if (err && err.name === "SplError") {
        ctx.drawer.setTitle(spec.title, spec.subtitle);
        if (rebuild) ctx.drawer.setParams(paramInputs(spec.errorParams || ["value", "aid", "earliest", "latest"], spec));
        ctx.drawer.setHazards([]);
        ctx.drawer.setSpl({ inline: "", macro: "" });
        ctx.drawer.setState("error", {
          error: {
            code: err.code,
            text:
              err.code === "unscoped_pid"
                ? `A RawProcessId search needs a host and a time window: the OS recycles PIDs, so an unscoped one matches unrelated processes. Bind aid, earliest and latest below. (${err.message})`
                : err.message,
          },
        });
        return;
      }
      throw err;
    }
    let macro = "";
    try {
      macro = spl.generate(spec.pivot, params, { form: "macro" }).spl;
    } catch {
      macro = "";
    }
    ctx.drawer.setTitle(spec.title, spec.subtitle);
    ctx.drawer.setSpl({ inline: inline.spl, macro });
    if (rebuild) ctx.drawer.setParams(paramInputs(inline.missing, spec));
    ctx.drawer.setHazards(inline.hazards);
    ctx.drawer.setState("filled");
  }

  ctx.setDrawerParamHandler((n, v) => {
    userParams[n] = v;
    if (currentId) fill(currentId, false);
  });

  led.addEventListener("select", (e) => {
    const { rowId, bandId } = e.detail;
    if (bandId === "here") {
      const evName = rowId.slice(3);
      ctx.navigate("field", { name: rec.name, on: evName, sel: rowId });
      return;
    }
    ctx.setUrl("field", { ...ctx.params, name: rec.name, on, sel: rowId });
    fill(rowId, true);
  });

  el.selectRow = (rowId) => {
    if (!rowId || !specs.has(rowId)) return;
    led.select(rowId);
    fill(rowId, true);
  };

  el.cycleEvent = () => {
    if (events.length < 2) return;
    const i = events.indexOf(on);
    const next = events[(i + 1) % events.length];
    ctx.navigate("field", { name: rec.name, on: next, sel: `ev-${next}` });
  };

  el.afterMount = () => {
    const sel = ctx.params.sel;
    if (sel && specs.has(sel)) el.selectRow(sel);
  };

  return el;
}

// ---------------------------------------------------------------------------

function header(ctx, rec, compact) {
  const roleLine = h(
    "p",
    { class: "r-hold__role" },
    h("span", { class: "r-muted" }, "role "),
    h("code", null, rec.role || "unclassified"),
    h("span", { class: "r-muted" }, " — read from "),
    BASIS_LABEL[rec.role_basis] || rec.role_basis || "nothing",
    rec.type ? h("span", { class: "r-muted" }, ` · type ${rec.type}`) : null,
    rec.legacy ? h("span", { class: "r-muted" }, " · legacy twin") : null,
    rec.in_catalogue ? null : h("span", { class: "r-muted" }, " · not in the field catalogue"),
  );

  const disagreement = rec.role_disagreement
    ? callout({
        kind: "note",
        label: "Two sources disagree",
        body: `${BASIS_LABEL[rec.role_basis] || rec.role_basis} says ${rec.role}; enrichment says ${
          rec.role_disagreement.enrichment || Object.values(rec.role_disagreement)[0]
        }. The convention wins because it is checkable against FDR's own naming, but both are kept — you can see the disagreement instead of inheriting a verdict.`,
      })
    : null;

  const m = rec.meaning
    ? meaning({
        description: rec.meaning.description,
        hunting_notes: rec.meaning.hunting_notes,
        data_format: rec.meaning.data_format,
        source: rec.meaning.source,
        confidence: rec.meaning.confidence,
        evidence: rec.meaning.evidence,
      })
    : meaning({ absent: true });
  if (rec.meaning && rec.meaning.source === "enrichment") {
    const det = m.querySelector("details");
    if (det) det.setAttribute("open", "");
  }

  const dec = compact ? null : ctx.data.decode(rec.name);

  const unsafe = rec.meaning && rec.meaning.source === "curated" && rec.meaning.safe_to_join === false;

  return h(
    "section",
    { class: "r-section r-hold" },
    h(
      "div",
      { class: "r-hold__head" },
      h("h1", { class: "r-hold__name" }, rec.name),
      layerChip(rec),
      routeChip(rec),
      rec.observed ? null : chip({ kind: "trust", value: "inferred", text: "never observed" }),
    ),
    roleLine,
    m,
    unsafe
      ? callout({
          kind: "hazard",
          label: "Not safe to join on",
          body: "Scope by aid and a time window, and expect multiple matches. The generated search requires both.",
        })
      : null,
    disagreement,
    dec ? decodeWidget({ field: rec.name, decode: dec }) : null,
    !compact && rec.role === "timestamp" ? epochWidget({ field: rec.name }) : null,
    dec
      ? h(
          "details",
          { class: "r-decode" },
          h("summary", null, `Decode table — ${Object.keys(dec.values || {}).length} values via `, h("code", null, dec.lookup)),
          h(
            "ul",
            { class: "r-decode__list" },
            Object.keys(dec.values || {}).map((k) => h("li", null, h("code", null, k), " ", h("span", null, dec.values[k]))),
          ),
        )
      : null,
    !compact && (rec.same_role_fields || []).length
      ? h(
          "details",
          { class: "r-samerole" },
          h("summary", null, `Same-role fields (${rec.same_role_fields.length}) — reference only, never a join`),
          h(
            "p",
            { class: "r-muted" },
            "Fields sharing this role by name convention. Not join edges.",
          ),
          h("p", { class: "r-inline" }, rec.same_role_fields.flatMap((n, i) => [i ? " · " : null, fieldLink(n)])),
        )
      : null,
  );
}

function coFieldsBlock(ctx, rec, on) {
  const groups = ctx.data.coFields(rec.name, on);
  const total = groups.reduce((n, g) => n + g.fields.length, 0);
  return h(
    "div",
    { class: "r-cofields" },
    h("h4", null, `Free on ${on} — ${total} other field${total === 1 ? "" : "s"} on the same record`),
    h("p", { class: "r-cofields__note r-muted" }, NO_FILL_RATES),
    h(
      "div",
      { class: "r-rolelist" },
      groups.map((g) =>
        h(
          "div",
          { class: "r-rolelist__group" },
          h("h5", { class: "r-rolelist__role" }, g.role, h("span", { class: "r-muted" }, ` ${g.fields.length}`)),
          h("p", { class: "r-rolelist__fields" }, g.fields.flatMap((n, i) => [i ? " " : null, fieldLink(n)])),
        ),
      ),
    ),
  );
}

function unreachableBand(ctx, rec, on, evRec, oneJoinRows, specs) {
  const route = rec.route || { summary: "unobserved", explain: "", by_event: {}, derived_from: [] };
  const rows = [];
  const columns = ["what you cannot get from here", "closest you can get", "basis"];

  const addHostOnly = (why, eventName) => {
    const id = `u-host-${eventName || "any"}`;
    specs.set(id, {
      pivot: { kind: "process_table" },
      params: {},
      title: "Every process on the host in the window",
      subtitle: `closest you can get from ${eventName || rec.name} — attribution is to a host and a time, not to a process`,
      errorParams: ["aid", "earliest", "latest"],
      valueOwner: "aid",
    });
    rows.push({
      id,
      cells: [{ text: why, wrap: true }, { text: "Every process on the host for the window (cs_process_table).", wrap: true }, chip({ kind: "trust", value: "confirmed", text: "confirmed" })],
    });
  };

  if (route.summary === "host_only") {
    addHostOnly(`The events carrying ${rec.name} have no process handle — no ContextProcessId, no TargetProcessId, no ParentProcessId. You can attribute this to a host and a time, not to a process.`, on);
  } else if (route.summary === "mixed") {
    if (evRec && (route.by_event[on] || {}).route === "host_only") {
      addHostOnly(`On ${on} this field has no process handle, even though other events carrying it do. The route is event-conditional — that is why there is no single verdict.`, on);
    }
    for (const [evName, info] of Object.entries(route.by_event || {})) {
      if (evName === on && info.route === "host_only") continue; // already the pivot row above
      const r = ROUTE_TEXT[info.route] || { label: info.route };
      rows.push({
        id: `u-ev-${evName}`,
        disabled: true,
        cells: [
          h(
            "span",
            null,
            "on ",
            eventLink(evName),
            evName === on ? h("span", { class: "r-muted" }, " (selected)") : null,
            " — ",
            r.label,
          ),
          info.route === "host_only"
            ? { text: "No process handle on that event: select it above and take the host pivot.", wrap: true }
            : h(
                "span",
                null,
                "handles: ",
                (info.handles || []).length
                  ? h("span", { class: "r-inline" }, (info.handles || []).flatMap((n, i) => [i ? " " : null, h("code", null, n)]))
                  : h("span", { class: "r-muted" }, "none"),
                info.is_anchor ? " · anchor event" : null,
              ),
          chip({ kind: "route", value: (ROUTE_TEXT[info.route] || {}).chip || "dead-end", text: r.label }),
        ],
      });
    }
  } else if (route.summary === "derived") {
    for (const src of route.derived_from || []) {
      const srcRec = ctx.data.field(src);
      rows.push({
        id: `u-derived-${src}`,
        disabled: true,
        cells: [
          h("span", null, "This field is computed, so it has no route of its own. It derives from ", fieldLink(src), "."),
          h(
            "span",
            null,
            srcRec ? `That field's route: ${(ROUTE_TEXT[srcRec.route.summary] || {}).label || srcRec.route.summary}. ` : "",
            fieldLink(src),
            " has the answer.",
          ),
          chip({ kind: "trust", value: "confirmed", text: "the TA computes it" }),
        ],
      });
    }
  } else if (route.summary === "unobserved") {
    rows.push({
      id: "u-unobserved",
      disabled: true,
      cells: [
        { text: "No route can be computed: this field is in the catalogue but was never observed on any event in the public corpus. This is 'we do not know', not 'there is no path'.", wrap: true },
        { text: "Check discovery/01 against your own tenant — your data may carry it where the public fixtures do not.", wrap: true },
        chip({ kind: "trust", value: "inferred", text: "unobserved" }),
      ],
    });
  }

  // *Pid field with no edge: PID space unestablished.
  const fam = familyOf(rec.name);
  if (fam && fam.family === "pid" && !PID_HANDLES.has(rec.name) && !(rec.edges || []).length) {
    const handle = (evRec && (evRec.handles || [])[0]) || null;
    rows.push({
      id: "u-pidspace",
      disabled: true,
      cells: [
        { text: `Which PID space ${rec.name} is in. Nothing in the catalogue, the TA or the reference says whether it is an OS PID (recycled) or a Falcon process id, so no join is offered on it.`, wrap: true },
        handle
          ? h("span", null, "Pivot through ", h("code", null, handle), " on this same event instead — the row in ONE JOIN does exactly that.")
          : { text: "No process handle on this event either; the host pivot above is the closest.", wrap: true },
        chip({ kind: "hazard", text: "no basis" }),
      ],
    });
  }

  return {
    id: "unreachable",
    kind: "unreachable",
    note: h(
      "span",
      null,
      h("b", null, (ROUTE_TEXT[route.summary] || {}).label || route.summary),
      " — ",
      route.explain || "",
    ),
    columns,
    rows,
    empty:
      route.summary === "one_hop" || route.summary === "direct_anchor"
        ? "Nothing is out of reach from this record: the route above gets you to the process."
        : "No breakdown to show for this route.",
  };
}

export default { render, edgeRowsFor, pivotForEdgeRow, baseParamsForRow, NO_FILL_RATES };
