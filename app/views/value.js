// Value page: #/v/<value>. Classifies the value, lists carrier fields, offers a first move.

import { h } from "../components/h.js";
import { chip } from "../components/chip.js";
import { callout } from "../components/callout.js";
import { ledger } from "../components/ledger.js";
import { classify } from "../lib/search.js";
import * as spl from "../lib/spl.js";

// Role per value kind, used to widen the seed carriers.
const KIND_ROLE = {
  sha256: "hash",
  sha1: "hash",
  md5: "hash",
  aid: "agent_id",
  ipv4: "ip",
  ipv6: "ip",
  domain: "domain",
  os_pid: "process_id",
  falcon_pid: "process_id",
  path: "file_path",
};

const KIND_NOTE = {
  os_pid:
    "Small enough to be an OS PID. OS PIDs are recycled, so a PID on its own names a different process every few hours on a busy host; searches on one are scoped to a host and a window.",
  falcon_pid:
    "Too large for an OS PID, so this is almost certainly a Falcon process id (the TargetProcessId space). Those do not repeat on a host.",
  sha256: "SHA-256 is the hash the sensor carries and the one the TA's appinfo lookup is keyed on — the confirmed file join.",
  md5: "The corpus carries MD5 on far fewer events than SHA-256; if you have a choice, hunt the SHA-256.",
  aid: "An aid is per sensor install: reimage a host and you get a new one. It is still the stable key — ComputerName is not.",
};

const MAX_ROWS = 30;

export function render(ctx) {
  const { data } = ctx;
  const value = String(ctx.params.value || "");
  const idx = data.searchIndex();
  const c = classify(value, idx);
  const el = h("div", { class: "r-view r-view--value" });
  if (c.kind === "name") {
    const first = c.candidates[0];
    el.appendChild(
      h(
        "section",
        { class: "r-section r-hold" },
        h("div", { class: "r-hold__head" }, h("h1", { class: "r-hold__name" }, value), chip({ kind: "trust", value: "confirmed", text: "a name, not a value" })),
        h(
          "p",
          null,
          "This is a catalogue name, not a value. ",
          first
            ? h("a", { href: `#/${first.kind === "field" ? "f" : "e"}/${encodeURIComponent(first.name)}` }, `Open ${first.name}`)
            : h("a", { href: `#/unknown/${encodeURIComponent(value)}` }, "See what is near it"),
        ),
      ),
    );
    return el;
  }

  const kindLabel = c.candidates.map((x) => x.label).join("  or  ") || "unrecognised";

  el.appendChild(
    h(
      "section",
      { class: "r-section r-hold" },
      h(
        "div",
        { class: "r-hold__head" },
        h("h1", { class: "r-hold__name" }, value),
        chip({ kind: "trust", value: c.ambiguous ? "inferred" : "confirmed", text: kindLabel }),
      ),
      c.ambiguous
        ? callout({
            kind: "caution",
            label: "Ambiguous",
            body: "32 hexadecimal characters is an MD5 file hash and it is also the shape of a CrowdStrike aid. Nothing in the value itself separates them. Both readings are below — pick the one that matches where you got it: a hash comes off a file, an aid comes off a host.",
          })
        : null,
      c.kind === "empty" || !c.candidates.length
        ? h("p", null, "Unrecognised value shape. Try it as a name in the search box — substring matches count.")
        : null,
      KIND_NOTE[c.candidates[0] && c.candidates[0].kind] ? h("p", { class: "r-secondary" }, KIND_NOTE[c.candidates[0].kind]) : null,
    ),
  );

  const specs = new Map();
  const bands = [];

  for (const cand of c.candidates) {
    const role = KIND_ROLE[cand.kind];
    const seeds = (cand.fields || []).filter((n) => data.field(n));
    // Unobserved fields are not offered. The `hash` role spans every digest
    // algorithm, so hash carriers are restricted to fields named for the kind.
    const algo = { sha256: /sha256|sha-256/i, sha1: /sha1(?!\d)|sha-1(?!\d)/i, md5: /md5/i }[cand.kind] || null;
    const others = role
      ? data.fieldsWithRole(role).filter((n) => !seeds.includes(n) && data.field(n).observed
          && (!algo || algo.test(n) || algo.test((data.field(n).meaning || {}).data_format || "")))
      : [];
    const rows = [];

    if (cand.kind === "aid") {
      const e = data.edge("e_aid_to_aidmaster");
      if (e) {
        specs.set("v-aidmaster", { pivot: { kind: "edge", edge: e }, params: { value }, title: e.target_label, subtitle: "aid → aidmaster", errorParams: ["value"] });
        rows.push({ id: "v-aidmaster", cells: [{ mono: "aidmaster" }, { text: e.target_label, wrap: true }, chip({ kind: "trust", value: "confirmed" })] });
      }
      specs.set("v-proctable", {
        pivot: { kind: "process_table" },
        params: { aid: value },
        title: "Every process on this host in the window",
        subtitle: "aid → ProcessRollup2 / SyntheticProcessRollup2",
        errorParams: ["aid", "earliest", "latest"],
      });
      rows.push({
        id: "v-proctable",
        cells: [{ mono: "process table" }, { text: "Every process the sensor recorded on this host for a window. Needs earliest and latest.", wrap: true }, chip({ kind: "trust", value: "confirmed" })],
      });
    }

    for (const name of [...seeds, ...others].slice(0, MAX_ROWS)) {
      const rec = data.field(name);
      const id = `v-${cand.kind}-${name}`;
      // External-only fields: the sensor-sourcetype trace would return nothing,
      // so offer an event sample on the external sourcetype instead.
      const externalOnly = rec.events.length > 0
        && rec.events.every((ev) => (data.event(ev) || {}).sourcetype === "crowdstrike:events:external");
      if (externalOnly) {
        specs.set(id, {
          pivot: { kind: "event_sample" },
          params: { event: rec.events[0], sourcetype: "crowdstrike:events:external", value, field: name },
          title: `${name} on detection summary events`,
          subtitle: "external sourcetype — not traceable to a sensor process from here",
          hazards: [{ level: "note", text: `${name} rides only on ${rec.events.join(", ")} (crowdstrike:events:external). The process trace searches sensor telemetry and would return nothing. Use the detection workflow to cross to the sensor side by hash or host.` }],
          errorParams: ["event", "earliest"],
        });
        rows.push({
          id,
          cells: [
            h("a", { href: `#/f/${encodeURIComponent(name)}`, class: "r-idlink" }, h("code", null, name)),
            { text: `detection summary events only (external sourcetype) — see the events, then cross by hash or host via the detection workflow`, wrap: true },
            chip({ kind: "trust", value: "inferred", text: "not traceable here" }),
          ],
        });
        continue;
      }
      specs.set(id, {
        pivot: { kind: "trace" },
        params: { field: name, value },
        title: `The process behind ${name}=${value}`,
        subtitle: "cs_trace_process — observable → the process that produced it",
        errorParams: ["field", "value", "earliest", "aid"],
      });
      rows.push({
        id,
        cells: [
          h("a", { href: `#/f/${encodeURIComponent(name)}`, class: "r-idlink" }, h("code", null, name)),
          {
            text: `${rec.layer === "cim" ? "L3 CIM" : rec.layer === "ta_derived" ? "L2 TA" : "L1 raw"} · ${rec.event_count} event${rec.event_count === 1 ? "" : "s"} · ${
              (rec.route && rec.route.summary) || "no route"
            }`,
            wrap: true,
          },
          seeds.includes(name) ? chip({ kind: "trust", value: "confirmed", text: "carries this" }) : chip({ kind: "trust", value: "inferred", text: `role ${role}` }),
        ],
      });
    }

    bands.push({
      id: `cand-${cand.kind}`,
      kind: "one-join",
      title: `Read as ${cand.label}`,
      note: `Fields that carry a ${cand.label}. Select one and the drawer traces that observable back to the process that produced it.`,
      columns: ["field", "what it is", "basis"],
      rows,
      empty: "No field in the catalogue is typed for this kind of value.",
    });
  }

  if (!bands.length) return el;

  const led = ledger({ selectedId: ctx.params.sel || null, caption: `First moves for ${value}`, bands });
  el.appendChild(h("section", { class: "r-section" }, led));

  const userParams = {};
  let currentId = null;

  function fill(rowId, rebuild) {
    const spec = specs.get(rowId);
    if (!spec) return;
    currentId = rowId;
    const params = { ...spec.params, ...userParams };
    let out;
    try {
      out = spl.generate(spec.pivot, params);
    } catch (err) {
      if (err && err.name === "SplError") {
        ctx.drawer.setTitle(spec.title, spec.subtitle);
        if (rebuild) ctx.drawer.setParams((spec.errorParams || []).map((n) => ({ name: n, label: n, value: userParams[n] ?? "", required: true })));
        ctx.drawer.setSpl({ inline: "", macro: "" });
        ctx.drawer.setState("error", { error: { code: err.code, text: err.message } });
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
    ctx.drawer.setSpl({ inline: out.spl, macro });
    if (rebuild) {
      ctx.drawer.setParams(
        out.missing.map((n) => ({
          name: n,
          label: n,
          value: userParams[n] ?? "",
          placeholder: n === "earliest" ? "-24h" : n === "latest" ? "now" : "",
          hint: n === "aid" ? "Optional here, but orders of magnitude faster." : undefined,
          required: n !== "aid",
        })),
      );
    }
    ctx.drawer.setHazards(out.hazards);
    ctx.drawer.setState("filled");
  }

  ctx.setDrawerParamHandler((n, v) => {
    userParams[n] = v;
    if (currentId) fill(currentId, false);
  });

  led.addEventListener("select", (e) => {
    ctx.setUrl("value", { ...ctx.params, value, sel: e.detail.rowId });
    fill(e.detail.rowId, true);
  });

  el.selectRow = (id) => {
    if (!specs.has(id)) return;
    led.select(id);
    fill(id, true);
  };
  el.afterMount = () => {
    if (ctx.params.sel && specs.has(ctx.params.sel)) el.selectRow(ctx.params.sel);
  };

  return el;
}

export default { render };
