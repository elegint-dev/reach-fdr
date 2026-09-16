// Guided workflows: #/w/<id>?…
// Order: situation → inputs (with why) → expect → disambiguate → troubleshoot → SPL.
// `pid` and `process` come from data/curated/translations.json; the rest are defined here.

import { h, replace } from "../components/h.js";
import { step } from "../components/step.js";
import { callout } from "../components/callout.js";
import { chip } from "../components/chip.js";
import { empty } from "../components/empty.js";
import * as spl from "../lib/spl.js";

export const IDS = ["pid", "process", "host", "detection", "ioc"];

const META = {
  aid: { label: "aid", placeholder: "32-hex agent id", required: true },
  earliest: { label: "earliest", placeholder: "-24h", required: true },
  latest: { label: "latest", placeholder: "now", required: true },
  pid: { label: "RawProcessId", placeholder: "4820", required: true },
  tpid: { label: "TargetProcessId", placeholder: "1234567890123456789", required: true },
  hostname: { label: "ComputerName", placeholder: "WKSTN-0042", required: true },
  value: { label: "value", placeholder: "the observable you are holding", required: true },
  field: { label: "field", placeholder: "ImageFileName", required: true },
  sha256: { label: "SHA256String", placeholder: "64 hex characters", required: true },
  processid: { label: "ProcessId (from the detection)", placeholder: "the detection's PID", required: true },
};

function inputs(names, params, optional = []) {
  // A step may mark a META-required param optional for that step.
  return names.map((n) => ({
    ...(META[n] || { label: n }),
    name: n,
    value: params[n] ?? "",
    required: optional.includes(n) ? false : (META[n] || {}).required,
    hint: optional.includes(n) ? "optional — narrows the search a lot" : (META[n] || {}).hint,
  }));
}

// ---------------------------------------------------------------------------
// Definitions

function pidWorkflow(ctx) {
  const t = ctx.data.translations().pid_translation;
  const wf = (t.guided_workflows || []).find((w) => w.id === "os_to_cs") || { steps: [], troubleshooting: [] };
  const inputFor = { aid: ["aid"], time_window: ["earliest", "latest"], RawProcessId: ["pid"] };
  return {
    title: "I have an OS PID and need CrowdStrike's process id",
    kicker: "OS PID → TargetProcessId",
    when: wf.when,
    lead: t.summary,
    why_no_formula: t.why_no_formula,
    steps: (wf.steps || []).map((s) => ({ title: s.ask, why: s.why, help: s.help, required: s.required, names: inputFor[s.input] || [] })),
    expect: wf.expect,
    disambiguate: wf.disambiguate || [],
    troubleshooting: wf.troubleshooting || [],
    results: (p) => [
      {
        id: "lookup",
        label: "The lookup",
        note: "A lookup against the anchor events, not a conversion. Expect more than one row: that is the PID being reused, not a mistake.",
        pivot: { kind: "pid_lookup" },
        params: { aid: p.aid, pid: p.pid, earliest: p.earliest, latest: p.latest },
      },
    ],
    chain: (p) => ({
      href: `#/w/process?${new URLSearchParams(Object.entries({ aid: p.aid || "", tpid: p.tpid || "", earliest: p.earliest || "", latest: p.latest || "" }).filter(([, v]) => v)).toString()}`,
      text: "Carry the TargetProcessId you picked into “everything this process did”",
      inputNames: ["tpid"],
      why: "The value you carry forward is TargetProcessId. That is the key every other FDR event is joined on — the OS PID stops being useful the moment you leave this search.",
    }),
  };
}

function processWorkflow(ctx) {
  const t = ctx.data.translations().pid_translation;
  const wf = (t.guided_workflows || []).find((w) => w.id === "cs_to_os") || { steps: [], troubleshooting: [] };
  const aidStep = (wf.steps || []).find((s) => s.input === "aid");
  const tpidStep = (wf.steps || []).find((s) => s.input === "TargetProcessId");
  return {
    title: "I have a CrowdStrike process id and need everything it did",
    kicker: "TargetProcessId → its events, and its OS PID",
    when: "You are inside FDR following a process — from a detection, a parent, or the PID workflow — and you need everything the sensor recorded for it.",
    lead: (t.fields && t.fields.TargetProcessId && t.fields.TargetProcessId.meaning) || "",
    steps: [
      { title: "Which host?", why: (aidStep && aidStep.why) || "", required: true, names: ["aid"] },
      { title: "The TargetProcessId", why: (tpidStep && tpidStep.why) || "TargetProcessId is unique per host and does not repeat.", required: true, names: ["tpid"] },
      {
        title: "Which window?",
        why: "Events are filtered on _time (index time). ContextTimeStamp and timestamp are sensor-side and will not agree with it.",
        required: true,
        names: ["earliest", "latest"],
      },
    ],
    expect:
      "Every event the sensor recorded whose ContextProcessId or TargetProcessId is this process — file writes, network connections, registry, child processes. Attribution through ContextProcessId is asserted from CrowdStrike's data model, not validated against the corpus.",
    disambiguate: [
      "Rows where the process is the TargetProcessId are things that happened *to* it (its creation, its end).",
      "Rows where it is the ContextProcessId are things it *did*. That is the attribution, and it is the asserted edge.",
      "A quiet result usually means the window, not the process: widen it before concluding the process did nothing.",
    ],
    troubleshooting: wf.troubleshooting || [],
    results: (p) => [
      {
        id: "events",
        label: "Everything this process did",
        note: "ContextProcessId is the attribution key on non-process events, and that attribution is asserted.",
        pivot: { kind: "process_events" },
        params: { aid: p.aid, tpid: p.tpid, earliest: p.earliest, latest: p.latest },
      },
      {
        id: "ospid",
        label: "The OS PID, to hand to someone on the box",
        note: "The caution below travels with this one.",
        pivot: { kind: "tpid_to_pid" },
        params: { aid: p.aid, tpid: p.tpid, earliest: p.earliest, latest: p.latest },
        caution: (t.guided_workflows.find((w) => w.id === "cs_to_os") || {}).caution,
      },
    ],
  };
}

function hostWorkflow() {
  return {
    title: "I have a host and want to know what ran on it",
    kicker: "hostname or aid → the process table",
    when: "You have a hostname from a ticket or an alert, or an aid from another search, and you need the processes the sensor saw on that machine.",
    lead: "Hostnames are not stable and aids are. A renamed or reimaged host has more than one aid; the same hostname can belong to two machines over time. Resolve the name first and carry the aid.",
    steps: [
      {
        title: "The hostname",
        why: "ComputerName changes with a rename, a reimage or a DHCP lease; aid is one sensor install and does not. Resolving the name first is what stops the rest of the hunt from being silently wrong.",
        required: true,
        names: ["hostname"],
      },
      {
        title: "The aid it resolves to",
        why: "Paste the aid the lookup returns. If it returns more than one, the machine has been reimaged — pick by last_seen and say which one you took.",
        required: false,
        names: ["aid"],
      },
      {
        title: "Which window?",
        why: "A process table is per window. Start around the activity you are investigating; widen only if it comes back empty.",
        required: true,
        names: ["earliest", "latest"],
      },
    ],
    expect:
      "One row per aid from the lookup — more than one is normal for a reimaged host. Then one row per process on that host in the window, with its image, command line, user and both PID spaces.",
    disambiguate: [
      "Two aids for one hostname: compare FirstSeen and last_seen. The old aid is the old install.",
      "Three timestamps differ: _time is index time, ProcessStartTime is the sensor's, ContextTimeStamp is the event's. Filter on _time; read the others.",
    ],
    troubleshooting: [
      { symptom: "The hostname returns nothing", causes: ["aidmaster carries the name the sensor reported — try the short name and the FQDN.", "The host may never have had a sensor installed.", "Case and domain suffixes matter in a lookup."] },
      { symptom: "The process table is enormous", causes: ["Narrow the window before anything else.", "Servers churn; filter on ImageFileName once you know what you are looking for."] },
    ],
    results: (p) => [
      { id: "lookup", label: "Resolve the hostname to an aid", note: "The TA's own host join — confirmed.", pivot: { kind: "host_lookup" }, params: { hostname: p.hostname } },
      { id: "table", label: "Every process on the host in the window", note: "Needs the aid and both ends of the window.", pivot: { kind: "process_table" }, params: { aid: p.aid, earliest: p.earliest, latest: p.latest } },
    ],
  };
}

function detectionWorkflow(ctx) {
  const hashEdge = ctx.data.edge("e_sha256string_to_sha256hashdata");
  const aidEdge = ctx.data.edge("e_agentidstring_to_aid");
  const counts = ctx.data.counts();
  return {
    title: "I have a detection and need the telemetry behind it",
    kicker: "detection summary event → sensor telemetry",
    when: "You are holding a detection summary event — from the console, an alert, or a ticket — and you need the sensor data around it.",
    lead: `Detection summary events are a different sourcetype (crowdstrike:events:external), they are in the CIM gap along with ${counts.events_cim_gap} of ${counts.events} events, and their handles are renames of the sensor-side names. Lead with what is safe.`,
    steps: [
      {
        title: "The file hash from the detection",
        why: "SHA256String on the detection is the same value space as SHA256HashData on sensor telemetry: the TA keys its appinfo lookup on it across the boundary, and enrichment agrees. This is the safest first pivot you have.",
        required: true,
        names: ["sha256"],
      },
      {
        title: "The host",
        why: "ComputerName on the detection resolves through aidmaster to an aid, and AgentIdString is the same agent id as a string. Either gets you onto sensor telemetry for the right machine.",
        required: true,
        names: ["hostname", "aid"],
      },
      {
        title: "Which window?",
        why: "The detection's own time is a starting point, not a filter: the behaviour that produced it usually starts earlier. Widen backwards first.",
        required: true,
        names: ["earliest", "latest"],
      },
      {
        title: "The detection's ProcessId — which PID space is it in?",
        why: "ProcessId appears only on the two detection summary events, is not enriched, has no CIM row, and neither the catalogue, the TA nor the reference says whether it is an OS PID or a Falcon process id. Joining an OS PID as a Falcon id returns a different process.",
        required: true,
        names: ["processid"],
        gate: true,
      },
    ],
    expect:
      "The hash pivot returns every sensor event that touched the file, plus the appinfo record for it. The host pivot returns one aid (or more, if the machine was reimaged). The PID step returns nothing until you answer the question.",
    disambiguate: [
      "A hash pivot with no host is fleet-wide: it tells you where else the file is, which is often the more valuable answer.",
      "If the hash returns nothing on sensor telemetry, the file may have been blocked before execution — check the detection's own fields rather than assuming the pivot failed.",
    ],
    troubleshooting: [
      { symptom: "The sensor search returns nothing for a detection you can see", causes: ["You are on the wrong sourcetype: the detection is external, the telemetry is sensor.", "The window is anchored on the detection time; the behaviour is usually earlier.", "The handle you pivoted on is a rename — check the field page for the sensor-side name."] },
      { symptom: "The hostname does not resolve", causes: ["Use AgentIdString from the detection instead; it is the aid as a string."] },
    ],
    hashEdge,
    aidEdge,
    results: (p) => {
      const rows = [];
      if (hashEdge) {
        rows.push({
          id: "hash",
          label: "Everything the file touched (the hash pivot)",
          note: `${hashEdge.note} Enrichment concurs at ${hashEdge.enrichment_concurs ? hashEdge.enrichment_concurs.confidence : "medium"} confidence.`,
          pivot: { kind: "edge", edge: hashEdge },
          params: { value: p.sha256, aid: p.aid, earliest: p.earliest, latest: p.latest },
        });
      }
      rows.push({
        id: "host",
        label: "Resolve the host to an aid",
        note: "The TA's own host join — confirmed.",
        pivot: { kind: "host_lookup" },
        params: { hostname: p.hostname },
      });
      rows.push({
        id: "pidspace",
        label: "The PID crossover",
        note: "Gated: answer the PID-space question and this emits the matching search.",
        gate: true,
        pivot:
          p.pidspace === "falcon"
            ? { kind: "process_events" }
            : p.pidspace === "os"
              ? { kind: "pid_lookup" }
              : null,
        params:
          p.pidspace === "falcon"
            ? { aid: p.aid, tpid: p.processid, earliest: p.earliest, latest: p.latest }
            : { aid: p.aid, pid: p.processid, earliest: p.earliest, latest: p.latest },
      });
      return rows;
    },
  };
}

function iocWorkflow() {
  return {
    title: "I have an observable and need the process behind it",
    kicker: "hash, IP, domain, filename → the process that produced it",
    when: "You have an indicator from threat intel, a ticket or another tool, and you need to know whether it appears in your FDR data and what process is responsible.",
    lead: "Paste the value first. The classifier identifies its kind and lists the fields that carry it. A 32-character hex string is ambiguous between an MD5 and an aid; both readings are offered.",
    steps: [
      { title: "The value", why: "Everything else follows from what kind of thing this is. The classifier never guesses past what the shape supports.", required: true, names: ["value"] },
      {
        title: "Which field carries it",
        why: "The same value can ride on several fields, and the field decides which events are in scope. Open the value page to pick one against the catalogue.",
        required: true,
        names: ["field"],
      },
      {
        title: "The window, and the host if you have one",
        why: "The trace scans the observable plus every process-creation event in the window. Without a window it is unbounded; with an aid it is orders of magnitude faster.",
        required: true,
        names: ["earliest", "aid"],
        optional: ["aid"],
      },
    ],
    expect:
      "One row per process that touched the observable in the window, with its image, command line, OS PID and whether the creation event was inside your window. resolved=no means the process started before your window, not that it does not exist.",
    disambiguate: [
      "resolved=no: widen the window backwards until the ProcessRollup2 lands inside it.",
      "Several processes for one observable is normal for a shared binary or a common domain — the ImageFileName column is how you separate them.",
    ],
    troubleshooting: [
      { symptom: "Nothing comes back", causes: ["Check the field actually carries that kind of value — the value page lists the ones that do.", "The window may predate the observable.", "Case: hashes in FDR are lower-case hex."] },
      { symptom: "It takes forever", causes: ["Bind the aid. The trace is a fleet-wide scan without one."] },
    ],
    results: (p) => [
      {
        id: "trace",
        label: "Trace the observable to its process",
        note: "cs_trace_process: the observable plus the anchor events, correlated on the process handle. No join command; Splunk-Cloud safe.",
        pivot: { kind: "trace" },
        params: { field: p.field, value: p.value, aid: p.aid, earliest: p.earliest, latest: p.latest },
      },
    ],
    valueLink: true,
  };
}

const BUILDERS = { pid: pidWorkflow, process: processWorkflow, host: hostWorkflow, detection: detectionWorkflow, ioc: iocWorkflow };

// ---------------------------------------------------------------------------

export function render(ctx) {
  const id = String(ctx.params.id || "");
  const build = BUILDERS[id];
  if (!build) {
    return h(
      "div",
      { class: "r-section" },
      empty({
        title: "No such workflow",
        line: `Five workflows: ${IDS.join(", ")}.`,
        moves: IDS.map((w) => ({ text: w, href: `#/w/${w}` })),
      }),
    );
  }

  const def = build(ctx);
  const params = { ...ctx.params };
  delete params.id;

  const el = h("div", { class: "r-view r-view--workflow" });

  // ---- situation --------------------------------------------------------
  el.appendChild(
    h(
      "section",
      { class: "r-section r-hold" },
      h("div", { class: "r-hold__head" }, h("h1", null, def.title), chip({ kind: "route", value: "one-hop", text: def.kicker })),
      def.when ? callout({ kind: "why", label: "When you are here", body: def.when }) : null,
      def.lead ? h("p", { class: "r-secondary" }, def.lead) : null,
      def.why_no_formula
        ? h(
            "details",
            { class: "r-samerole" },
            h("summary", null, def.why_no_formula.question),
            h("p", null, def.why_no_formula.answer),
            def.why_no_formula.tested ? h("p", { class: "r-muted" }, "Tested: ", def.why_no_formula.tested) : null,
          )
        : null,
      def.valueLink && params.value
        ? h("p", null, h("a", { href: `#/v/${encodeURIComponent(params.value)}` }, "See which fields carry that value"))
        : null,
    ),
  );

  // ---- steps (why each input is needed) ---------------------------------
  const stepsWrap = h("section", { class: "r-section" }, h("h2", null, "Inputs, and why"));
  let n = 0;
  for (const s of def.steps) {
    n += 1;
    const gate = s.gate ? gateBlock() : null;
    stepsWrap.appendChild(
      step({
        n,
        title: s.title,
        required: s.required !== false,
        state: s.names.filter((name) => !(s.optional || []).includes(name)).every((name) => params[name]) ? "done" : "current",
        input: inputs(s.names, params, s.optional || []),
        why: s.why,
        help: s.help,
        children: gate,
        onInput: (name, value) => {
          params[name] = value;
          ctx.setUrl("workflow", { id, ...params });
          refresh(false);
        },
      }),
    );
  }
  el.appendChild(stepsWrap);

  function gateBlock() {
    const wrap = h("div", { class: "r-gate" });
    const say = h(
      "p",
      { class: "r-gate__ask" },
      "Not determinable from the data: ",
      h("b", null, "which PID space is this ProcessId in?"),
    );
    const choose = (which) => {
      params.pidspace = which;
      ctx.setUrl("workflow", { id, ...params });
      for (const b of wrap.querySelectorAll("button")) b.setAttribute("aria-pressed", b.dataset.choice === which ? "true" : "false");
      replace(answer, answerFor(which));
      refresh(true, "pidspace");
    };
    const answer = h("div", { class: "r-gate__answer" });
    const btns = h(
      "div",
      { class: "r-gate__choices" },
      h("button", { type: "button", class: "r-gate__btn", dataset: { choice: "falcon" }, "aria-pressed": params.pidspace === "falcon" ? "true" : "false", onClick: () => choose("falcon") }, "It is a Falcon process id"),
      h("button", { type: "button", class: "r-gate__btn", dataset: { choice: "os" }, "aria-pressed": params.pidspace === "os" ? "true" : "false", onClick: () => choose("os") }, "It is an OS PID"),
      h("button", { type: "button", class: "r-gate__btn", dataset: { choice: "unknown" }, "aria-pressed": params.pidspace === "unknown" ? "true" : "false", onClick: () => choose("unknown") }, "I do not know"),
    );
    wrap.append(say, btns, answer);
    if (params.pidspace) replace(answer, answerFor(params.pidspace));
    return wrap;
  }

  function answerFor(which) {
    if (which === "falcon") {
      return callout({
        kind: "expect",
        label: "Treated as a Falcon process id",
        body: "The search below is the process workflow's: every event whose ContextProcessId or TargetProcessId is this value, on this host, in this window. If it comes back empty, that is evidence the value was an OS PID after all.",
      });
    }
    if (which === "os") {
      return callout({
        kind: "hazard",
        label: "Treated as an OS PID",
        body: h(
          "div",
          null,
          h("p", null, "Then it is recycled, and the only safe move is a scoped lookup against the anchor events: host and window required, several candidates expected."),
          h("p", null, h("a", { href: `#/w/pid?${new URLSearchParams(Object.entries({ aid: params.aid || "", pid: params.processid || "", earliest: params.earliest || "", latest: params.latest || "" }).filter(([, v]) => v)).toString()}` }, "Continue in the OS PID workflow")),
        ),
      });
    }
    return callout({
      kind: "caution",
      label: "Then no search is emitted",
      body: "Ask whoever raised the detection which value they read, or test it: run the Falcon reading and the OS reading separately and see which one returns a process whose image matches the detection.",
    });
  }

  // ---- expect / disambiguate / troubleshoot -----------------------------
  if (def.expect) el.appendChild(h("section", { class: "r-section" }, h("h2", null, "What to expect"), callout({ kind: "expect", body: def.expect })));

  if ((def.disambiguate || []).length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        h("h2", null, "How to tell them apart"),
        h("ul", { class: "r-list" }, def.disambiguate.map((d) => h("li", null, d))),
      ),
    );
  }

  if ((def.troubleshooting || []).length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        h("h2", null, "When it does not work"),
        def.troubleshooting.map((t) =>
          h(
            "div",
            { class: "r-trouble" },
            h("h4", null, t.symptom),
            h("ul", { class: "r-list" }, (t.causes || []).map((c) => h("li", null, c))),
          ),
        ),
      ),
    );
  }

  // ---- the SPL, last ----------------------------------------------------
  const resultSlot = h("div", { class: "r-result" });
  el.appendChild(h("section", { class: "r-section" }, h("h2", null, "The search"), h("p", { class: "r-muted" }, "In the drawer — ", h("kbd", null, "c"), " copies it."), resultSlot));

  let activeId = null;

  function refresh(rebuildParams, forceId) {
    const results = def.results(params) || [];
    if (forceId) activeId = forceId;
    if (!activeId || !results.some((r) => r.id === activeId)) activeId = results[0] ? results[0].id : null;
    const active = results.find((r) => r.id === activeId) || null;

    replace(
      resultSlot,
      h(
        "div",
        { class: "r-result__choices" },
        results.map((r) =>
          h(
            "button",
            {
              type: "button",
              class: ["r-result__btn", r.id === activeId && "is-active"],
              "aria-pressed": r.id === activeId ? "true" : "false",
              onClick: () => {
                activeId = r.id;
                refresh(true);
              },
            },
            r.label,
          ),
        ),
      ),
      active ? h("p", { class: "r-result__note" }, active.note) : null,
      active && active.caution ? callout({ kind: "caution", label: "Before you hand this on", body: active.caution }) : null,
    );

    if (!active) return;

      if (active.gate && (!params.pidspace || params.pidspace === "unknown" || !active.pivot)) {
      ctx.drawer.setTitle(active.label, "gated — answer the PID-space question above");
      ctx.drawer.setSpl({ inline: "", macro: "" });
      if (rebuildParams) ctx.drawer.setParams([]);
      ctx.drawer.setHazards([]);
      ctx.drawer.setState("error", {
        error: {
          code: "pid_space_unknown",
          text:
            "Nothing in the catalogue, the TA or the reference says which PID space a detection event's ProcessId occupies. Answer the question in step 4 and the matching search appears here.",
        },
      });
      return;
    }

    const bound = {};
    for (const [k, v] of Object.entries(active.params || {})) if (v !== undefined && v !== null && v !== "") bound[k] = v;

    let out;
    try {
      out = spl.generate(active.pivot, bound);
    } catch (err) {
      if (err && err.name === "SplError") {
        ctx.drawer.setTitle(active.label, def.kicker);
        ctx.drawer.setSpl({ inline: "", macro: "" });
        if (rebuildParams) ctx.drawer.setParams([]);
        ctx.drawer.setHazards([]);
        ctx.drawer.setState("error", {
          error: {
            code: err.code,
            text:
              err.code === "unscoped_pid"
                ? `An OS PID predicate needs a host and both ends of the window bound — the OS recycles PIDs, so an unscoped one matches unrelated processes. Fill in the steps above and the search appears. (${err.message})`
                : err.message,
          },
        });
        return;
      }
      throw err;
    }
    let macro = "";
    try {
      macro = spl.generate(active.pivot, bound, { form: "macro" }).spl;
    } catch {
      macro = "";
    }
    ctx.drawer.setTitle(active.label, def.kicker);
    ctx.drawer.setSpl({ inline: out.spl, macro });
    if (rebuildParams) ctx.drawer.setParams([]);
    ctx.drawer.setHazards(out.hazards);
    ctx.drawer.setState("filled");
  }

  if (def.chain) {
    const c = def.chain(params);
    const chainWrap = h("section", { class: "r-section r-chain" });
    chainWrap.appendChild(
      step({
        n: n + 1,
        title: "Carry it forward",
        required: false,
        state: params.tpid ? "done" : "todo",
        input: inputs(c.inputNames || [], params),
        why: c.why,
        onInput: (name, value) => {
          params[name] = value;
          ctx.setUrl("workflow", { id, ...params });
          chainLink.href = def.chain(params).href;
        },
      }),
    );
    const chainLink = h("a", { class: "r-chain__link", href: c.href }, c.text, " →");
    chainWrap.appendChild(h("p", null, chainLink));
    el.appendChild(chainWrap);
  }

  el.afterMount = () => refresh(true);
  return el;
}

export default { render, IDS };
