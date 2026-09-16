// Event page: #/e/<name>

import { h } from "../components/h.js";
import { chip } from "../components/chip.js";
import { callout } from "../components/callout.js";
import { table } from "../components/table.js";
import * as spl from "../lib/spl.js";

function fieldLink(name) {
  return h("a", { href: `#/f/${encodeURIComponent(name)}`, class: "r-idlink" }, h("code", null, name));
}

// PID-translation state from events.json `pid_spaces`.
export function pidState(evRec) {
  const ps = (evRec && evRec.pid_spaces) || {};
  const tpid = ps.TargetProcessId === true;
  const raw = ps.RawProcessId === true;
  if (tpid && raw) return "both";
  if (tpid) return "falcon_only";
  if (raw) return "os_only";
  return "neither";
}

function pidCallout(evRec) {
  switch (pidState(evRec)) {
    case "both":
      return callout({
        kind: "expect",
        label: "Both PID spaces",
        body: h(
          "div",
          null,
          h(
            "p",
            null,
            "This event carries TargetProcessId and RawProcessId on the same record, so the translation between CrowdStrike's process id and the OS PID is readable here directly — no join, no arithmetic.",
          ),
          h("p", null, "These records are where PID translation is resolved. Scope by aid and a time window: the OS PID is recycled."),
        ),
      });
    case "falcon_only":
      return callout({
        kind: "caution",
        label: "Falcon process id only",
        body: h(
          "div",
          null,
          h("p", null, "This event carries TargetProcessId but not RawProcessId. To get the OS PID you must pivot to an anchor event — ProcessRollup2 or SyntheticProcessRollup2 — for the same aid and TargetProcessId."),
          h("p", null, "That pivot is in the drawer: it is a lookup, not a conversion. There is no arithmetic that turns one into the other."),
        ),
      });
    case "os_only":
      return callout({
        kind: "hazard",
        label: "OS PID only",
        body: h(
          "div",
          null,
          h("p", null, "This event carries RawProcessId but not TargetProcessId, so it cannot resolve to a CrowdStrike process id on its own record."),
          h("p", null, "The OS PID is recycled. Resolve it with a scoped lookup against the anchor events for the same host and window; expect several candidates."),
        ),
      });
    default:
      // No PID: detection event (unestablished space) / has a handle / no handle.
      if ((evRec.pid_fields_unestablished || []).length) {
        return callout({
          kind: "hazard",
          label: "PID fields in an unestablished space",
          body: h(
            "div",
            null,
            h("p", null, `This is a ${evRec.sourcetype} event. It carries ${evRec.pid_fields_unestablished.join(" and ")}, but nothing on disk says whether those are Falcon process ids or OS PIDs, so they are not treated as process handles and no process join is offered from this event.`),
            h("p", null, h("a", { href: "#/w/detection" }, "The detection workflow"), " leads with the hash and host pivots, which are established, and gates the PID crossover behind that question."),
          ),
        });
      }
      if (!(evRec.handles || []).length) {
        return callout({
          kind: "caution",
          label: "No process handle at all",
          body: "This event carries no ContextProcessId, TargetProcessId or ParentProcessId. You can attribute it to a host (aid) and a time, not to a process. Do not fabricate a process link; the closest you can get is the host's process table for the same window.",
        });
      }
      return callout({
        kind: "note",
        label: "No PID on this event",
        body: `Neither TargetProcessId nor RawProcessId rides on this event, so nothing here translates between the two PID spaces. Attribution comes from ${evRec.handles.join(" / ")}, which is one hop from the process record.`,
      });
  }
}

function cimBlock(ctx, evRec) {
  const c = evRec.cim || { normalized: false, data_models: [], fields: [] };
  if (c.normalized) {
    return h(
      "section",
      { class: "r-section" },
      h("h2", null, "CIM"),
      h(
        "p",
        null,
        "The TA normalises this event into ",
        h("b", null, (c.data_models || []).join(", ")),
        ". You can search it by data model as well as by ",
        h("code", null, "event_simpleName"),
        ".",
      ),
      c.fields && c.fields.length
        ? h("p", { class: "r-inline" }, "CIM fields: ", c.fields.flatMap((n, i) => [i ? " " : null, fieldLink(n)]))
        : null,
    );
  }
  const counts = ctx.data.counts();
  return h(
    "section",
    { class: "r-section" },
    h("h2", null, "CIM"),
    callout({
      kind: "note",
      label: "No CIM path",
      body: h(
        "div",
        null,
        h(
          "p",
          null,
          "The TA does not normalise this event into any CIM data model. There is no CIM field to search and no data model that will find it: the only route to this data is the raw ",
          h("code", null, "event_simpleName"),
          ".",
        ),
        h(
          "p",
          null,
          `It is one of ${counts.events_cim_gap} events in the CIM gap, out of ${counts.events} in the catalogue — ${counts.events_cim_normalized} are normalised.`,
        ),
      ),
    }),
  );
}

export function render(ctx) {
  const { data } = ctx;
  const name = ctx.params.name;
  const rec = data.event(name);
  if (!rec) {
    return h(
      "div",
      { class: "r-section" },
      h("h1", { class: "r-hold__name" }, name),
      h("p", null, "No event by that name is in the catalogue."),
      h("p", null, h("a", { href: `#/unknown/${encodeURIComponent(name)}` }, "See what is near it")),
    );
  }

  const el = h("div", { class: "r-view r-view--event" });

  el.appendChild(
    h(
      "section",
      { class: "r-section r-hold" },
      h(
        "div",
        { class: "r-hold__head" },
        h("h1", { class: "r-hold__name" }, rec.name),
        rec.is_anchor ? chip({ kind: "route", value: "here", text: "anchor event" }) : null,
        rec.cim && rec.cim.normalized ? chip({ kind: "trust", value: "confirmed", text: "CIM normalized" }) : chip({ kind: "trust", value: "inferred", text: "no CIM path" }),
      ),
      h(
        "p",
        { class: "r-hold__role" },
        h("span", { class: "r-muted" }, "sourcetype "),
        h("code", null, rec.sourcetype),
        h("span", { class: "r-muted" }, " · "),
        `${rec.field_count} fields`,
        h("span", { class: "r-muted" }, " · handles "),
        (rec.handles || []).length ? h("span", { class: "r-inline" }, rec.handles.flatMap((n, i) => [i ? " " : null, fieldLink(n)])) : h("span", { class: "r-muted" }, "none"),
      ),
      rec.is_anchor
        ? callout({
            kind: "why",
            label: "Anchor event",
            body: "This is a process-creation record. It is where a process gets its identity — image, command line, user, start time, both PID spaces — and it is the destination of nearly every pivot in Reach.",
          })
        : null,
      pidCallout(rec),
    ),
  );

  el.appendChild(cimBlock(ctx, rec));

  const byRole = rec.fields_by_role || {};
  const roles = Object.keys(byRole).sort();
  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      h("h2", null, `Fields on this event (${rec.field_count})`),
      h("p", { class: "r-muted" }, "Grouped by role, then alphabetical."),
      h(
        "div",
        { class: "r-rolelist" },
        roles.map((role) =>
          h(
            "div",
            { class: "r-rolelist__group" },
            h("h5", { class: "r-rolelist__role" }, role, h("span", { class: "r-muted" }, ` ${byRole[role].length}`)),
            h("p", { class: "r-rolelist__fields" }, byRole[role].slice().sort().flatMap((n, i) => [i ? " " : null, fieldLink(n)])),
          ),
        ),
      ),
    ),
  );

  const userParams = {};
  const state = pidState(rec);
  const pivot = { kind: "event_sample" };
  const base = { event: rec.name, sourcetype: rec.sourcetype };

  function fill(rebuild) {
    const params = { ...base, ...userParams };
    const out = spl.generate(pivot, params);
    ctx.drawer.setTitle(`See ${rec.name} on real data`, state === "falcon_only" ? "…then pivot to an anchor event for the OS PID" : rec.sourcetype);
    ctx.drawer.setSpl({ inline: out.spl, macro: "" });
    if (rebuild) {
      ctx.drawer.setParams(
        out.missing.map((n) => ({ name: n, label: n, value: userParams[n] ?? "", placeholder: n === "earliest" ? "-24h" : "", required: true })),
      );
    }
    ctx.drawer.setHazards(out.hazards);
    ctx.drawer.setState("filled");
  }

  ctx.setDrawerParamHandler((n, v) => {
    userParams[n] = v;
    fill(false);
  });

  el.afterMount = () => fill(true);
  return el;
}

export default { render, pidState };
