// View logic tests. No DOM: rendering is verified in a browser.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import * as field from "../app/views/field.js";
import * as eventView from "../app/views/event.js";
import * as workflow from "../app/views/workflow.js";
import { matchNames } from "../app/lib/search.js";
import * as spl from "../app/lib/spl.js";

const read = (n) => JSON.parse(readFileSync(new URL(`../app/data/${n}.json`, import.meta.url), "utf8"));
const EDGES = read("edges");
const EVENTS = read("events");
const FIELDS = read("fields");
const MANIFEST = read("manifest");

// ---------------------------------------------------------------------------
// ONE JOIN: reachability comes from the selected event, not from the field

test("edgeRowsFor: ResponsiblePid on LoginItemAdded reaches the process through a co-field", () => {
  const rows = field.edgeRowsFor(EDGES, EVENTS.LoginItemAdded, "ResponsiblePid");
  const ids = rows.map((r) => r.edge.id);

  // The field itself has no edges — the band must still answer the question.
  assert.deepEqual(FIELDS.ResponsiblePid.edges, []);
  assert.ok(ids.includes("e_context_to_target"), "the ContextProcessId hop rides on the same event");
  assert.ok(ids.includes("e_aid_to_aidmaster"), "aid is on the event, so the host join is reachable");
  assert.ok(rows.length > 0);
  assert.equal(rows.every((r) => r.viaSelf === false), true, "none of them is ResponsiblePid itself");
});

test("edgeRowsFor: never offers a join whose key is not on the event", () => {
  const rows = field.edgeRowsFor(EDGES, EVENTS.LoginItemAdded, "ResponsiblePid");
  const ids = rows.map((r) => r.edge.id);
  assert.equal(ids.includes("e_usersid_to_userinfo"), false, "LoginItemAdded carries no UserSid");
  assert.equal(ids.includes("e_raw_pid"), false, "LoginItemAdded carries no RawProcessId");
});

test("edgeRowsFor: every row's src actually rides on the event, for every event", () => {
  for (const [name, ev] of Object.entries(EVENTS)) {
    const present = new Set(ev.fields);
    for (const row of field.edgeRowsFor(EDGES, ev, null)) {
      assert.ok(present.has(row.edge.src), `${row.edge.id} offered on ${name} without ${row.edge.src}`);
    }
  }
});

test("edgeRowsFor: the field's own edges come first when they are on the event", () => {
  const rows = field.edgeRowsFor(EDGES, EVENTS.ProcessRollup2, "RawProcessId");
  assert.equal(rows[0].edge.id, "e_raw_pid");
  assert.equal(rows[0].viaSelf, true);
});

test("edgeRowsFor: no event, no rows", () => {
  assert.deepEqual(field.edgeRowsFor(EDGES, null, "ResponsiblePid"), []);
});

// ---------------------------------------------------------------------------
// Row → pivot

test("pivotForEdgeRow: the field's own edge is followed as an edge", () => {
  const row = { edge: EDGES.find((e) => e.id === "e_raw_pid"), viaSelf: true };
  assert.equal(field.pivotForEdgeRow(row, "RawProcessId").kind, "edge");
});

test("pivotForEdgeRow: a process hop through a co-field keeps the field you hold", () => {
  const row = { edge: EDGES.find((e) => e.id === "e_context_to_target"), viaSelf: false };
  const pivot = field.pivotForEdgeRow(row, "ResponsiblePid");
  assert.equal(pivot.kind, "trace");
  const params = field.baseParamsForRow(row, "ResponsiblePid", "LoginItemAdded");
  assert.equal(params.field, "ResponsiblePid", "the observable the hunter came in holding is not dropped");

  const out = spl.generate(pivot, { ...params, value: "4711", earliest: "-24h" });
  assert.match(out.spl, /ResponsiblePid="4711"/, "the search filters on the field you hold");
  assert.match(out.spl, /ProcessRollup2/, "and resolves the process behind it");
});

test("pivotForEdgeRow: the unsafe OS-PID row throws until it is scoped, and stops throwing when bound", () => {
  const row = { edge: EDGES.find((e) => e.id === "e_raw_pid"), viaSelf: true };
  const pivot = field.pivotForEdgeRow(row, "RawProcessId");
  assert.throws(() => spl.generate(pivot, { value: "4820" }), (err) => err.name === "SplError" && err.code === "unscoped_pid");
  const ok = spl.generate(pivot, { value: "4820", aid: "a".repeat(32), earliest: "-24h", latest: "now" });
  assert.match(ok.spl, /RawProcessId="4820"/);
  assert.ok(ok.hazards.length > 0, "and it still carries the recycling hazard");
});

// ---------------------------------------------------------------------------
// The event page's PID-translation states

test("pidState reads events.json pid_spaces, all three ways", () => {
  assert.equal(eventView.pidState(EVENTS.ProcessRollup2), "both");
  assert.equal(eventView.pidState(EVENTS.CommandHistory), "falcon_only");
  assert.equal(eventView.pidState(EVENTS.AgenticSessionStart), "os_only");
  assert.equal(eventView.pidState(EVENTS.DnsRequest), "neither");
  assert.equal(eventView.pidState(null), "neither");
});

test("the three PID states partition the catalogue", () => {
  const seen = { both: 0, falcon_only: 0, os_only: 0, neither: 0 };
  for (const ev of Object.values(EVENTS)) seen[eventView.pidState(ev)] += 1;
  assert.equal(Object.values(seen).reduce((a, b) => a + b, 0), MANIFEST.counts.events);
  assert.ok(seen.both > 0 && seen.falcon_only > 0 && seen.os_only > 0);
});

// ---------------------------------------------------------------------------
// Promises the copy makes

test("the co-field ordering note states the ordering and that fill-rate data is absent", () => {
  assert.match(field.NO_FILL_RATES, /by role/i);
  assert.match(field.NO_FILL_RATES, /no fill-rate data/i);
});

test("five guided workflows, no more", () => {
  assert.deepEqual(workflow.IDS, ["pid", "process", "host", "detection", "ioc"]);
});

// ---------------------------------------------------------------------------
// The near-miss

test("ResponsibleProcessId is not a name, and ResponsiblePid is its top hit", () => {
  const index = { fields: Object.keys(FIELDS), events: Object.keys(EVENTS) };
  assert.equal(Object.hasOwn(FIELDS, "ResponsibleProcessId"), false);
  const hits = matchNames("ResponsibleProcessId", index);
  assert.equal(hits[0].name, "ResponsiblePid");
  assert.equal(hits[0].kind, "field");
});

test("edgeRowsFor: a process-handle edge is never offered on a detection summary event", () => {
  // ParentProcessId is present by name on the external sourcetype, but the
  // build reports no handles there because its PID space is unestablished.
  const ev = EVENTS.Event_DetectionSummaryEvent;
  assert.ok(ev.fields.includes("ParentProcessId"), "precondition: the name is on the event");
  assert.deepEqual(ev.handles, [], "precondition: the build refuses it as a handle");
  const ids = field.edgeRowsFor(EDGES, ev, "MD5String").map((r) => r.edge.id);
  assert.equal(ids.includes("e_parent_to_target"), false, "lineage across the sourcetype boundary in an unestablished PID space");
  // The established crossings are still offered.
  assert.ok(ids.includes("e_sha256string_to_sha256hashdata"));
  assert.ok(ids.includes("e_agentidstring_to_aid"));
});

test("edgeRowsFor: on every event, a process-side edge is offered only through a real handle", () => {
  for (const [name, ev] of Object.entries(EVENTS)) {
    const handles = new Set(ev.handles);
    for (const row of field.edgeRowsFor(EDGES, ev, null)) {
      if (row.edge.dst === "TargetProcessId") {
        assert.ok(handles.has(row.edge.src), `${row.edge.id} offered on ${name} through ${row.edge.src}, which is not a handle there`);
      }
    }
  }
});

test("isAutomaticOn: a TA search-time lookup is free only where its stanza fires", () => {
  const aid = EDGES.find((e) => e.id === "e_aid_to_aidmaster");
  const sha = EDGES.find((e) => e.id === "e_sha256_to_appinfo");
  const ctx = EDGES.find((e) => e.id === "e_context_to_target");
  assert.equal(aid.mechanism, "search_time_lookup");
  assert.equal(field.isAutomaticOn(aid, EVENTS.LoginItemAdded), true, "sensor sourcetype: host resolution is already on the record");
  assert.equal(field.isAutomaticOn(aid, EVENTS.Event_DetectionSummaryEvent), false, "external: no host_res stanza there");
  assert.equal(field.isAutomaticOn(sha, EVENTS.Event_DetectionSummaryEvent), true, "the appinfo stanza fires on external too");
  assert.equal(field.isAutomaticOn(ctx, EVENTS.DnsRequest), false, "an asserted process edge is never automatic");
  assert.equal(field.isAutomaticOn(aid, null), false);
});
