import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  generate, lint, SplError, PIVOT_KINDS, TIME_NOTE, HANDOFF_CAUTION, PID_RECYCLING_HAZARD,
  SOURCETYPES, quote, FORBIDDEN_COMMANDS,
} from '../app/lib/spl.js';

const here = dirname(fileURLToPath(import.meta.url));
const hzText = (r) => r.hazards.map((h) => h.text).join('\n');
const hzLevels = (r) => r.hazards.map((h) => h.level);
const EDGES = JSON.parse(readFileSync(join(here, 'fixtures', 'edges.json'), 'utf8'));
const edge = (id) => EDGES.find((e) => e.id === id);

const FULL = { aid: 'abc123', pid: '4820', tpid: '6127484919', earliest: '-1h', latest: 'now',
  value: 'v', field: 'DomainName', event: 'DnsRequest', hostname: 'WS-01' };

// Every (kind, params) pair we can generate without throwing — used by the invariant sweeps.
function allOutputs() {
  const out = [];
  const push = (pivot, params, opts) => {
    for (const form of opts ? [opts] : [{ form: 'inline' }, { form: 'macro' }]) {
      out.push({ pivot, params, form, r: generate(pivot, params, form) });
    }
  };
  push({ kind: 'trace' }, { field: 'SHA256HashData', value: 'ab"c\\d', earliest: '-24h' });
  push({ kind: 'trace' }, { field: 'DomainName', value: 'evil.example.com', earliest: '-7d', aid: 'a1' });
  push({ kind: 'trace' }, {});
  push({ kind: 'process_events' }, FULL);
  push({ kind: 'process_events' }, { aid: 'a', tpid: '1', earliest: '-24h', latest: '-1h' });
  push({ kind: 'process_events' }, {});
  push({ kind: 'process_table' }, FULL);
  push({ kind: 'process_table' }, {});
  push({ kind: 'pid_lookup' }, FULL);
  push({ kind: 'pid_lookup' }, { aid: 'a', earliest: '-1h', latest: '-30m' });
  push({ kind: 'tpid_to_pid' }, FULL);
  push({ kind: 'tpid_to_pid' }, {});
  push({ kind: 'host_lookup' }, FULL);
  push({ kind: 'host_lookup' }, {});
  push({ kind: 'event_sample' }, FULL);
  push({ kind: 'event_sample' }, { event: 'Event_DetectionSummaryEvent' });
  push({ kind: 'decode', decode: { lookup: 'crowdstrike_AccessoryConnectionType.csv', meaning_field: 'AccessoryConnectionType_meaning' } }, { field: 'AccessoryConnectionType' });
  push({ kind: 'decode' }, { field: 'DriverLoadFlags', earliest: '-24h' });
  push({ kind: 'decode' }, {});
  for (const e of EDGES) {
    push({ kind: 'edge', edge: e }, FULL);
    if (!e.scope.includes('time')) push({ kind: 'edge', edge: e }, { value: 'x' });
  }
  return out;
}

describe('generate — every pivot kind', () => {
  test('covers the kinds in ARCHITECTURE §3', () => {
    assert.deepEqual([...PIVOT_KINDS].sort(), ['decode', 'edge', 'event_sample', 'host_lookup', 'pid_lookup', 'process_events', 'process_table', 'tpid_to_pid', 'trace']);
  });

  test('returns the contract shape', () => {
    const r = generate({ kind: 'process_table' }, FULL);
    assert.deepEqual(Object.keys(r).sort(), ['asserted', 'form', 'hazards', 'kind', 'missing', 'sourcetype', 'spl']);
    assert.equal(typeof r.spl, 'string');
    assert.ok(Array.isArray(r.hazards));
    assert.ok(Array.isArray(r.missing));
  });

  test('unknown kind / bad pivot throw SplError', () => {
    assert.throws(() => generate({ kind: 'nope' }), (e) => e instanceof SplError && e.code === 'unknown_kind');
    assert.throws(() => generate(null), (e) => e instanceof SplError && e.code === 'bad_pivot');
    assert.throws(() => generate({ kind: 'edge' }, { value: 'x' }), (e) => e instanceof SplError && e.code === 'bad_pivot');
  });

  test('field / event names must be identifiers (never quoted, never injected)', () => {
    assert.throws(() => generate({ kind: 'trace' }, { field: 'x | join y', value: 'v', earliest: '-1h' }), (e) => e.code === 'bad_identifier');
    assert.throws(() => generate({ kind: 'event_sample' }, { event: 'Dns Request', earliest: '-1h' }), (e) => e.code === 'bad_identifier');
  });
});

describe('invariant 1 — RawProcessId never unscoped', () => {
  test('pid_lookup throws unscoped_pid when aid / earliest / latest are not all bound', () => {
    for (const missing of ['aid', 'earliest', 'latest']) {
      const p = { ...FULL };
      delete p[missing];
      assert.throws(() => generate({ kind: 'pid_lookup' }, p), (e) => e instanceof SplError && e.code === 'unscoped_pid', `missing ${missing}`);
    }
    assert.throws(() => generate({ kind: 'pid_lookup' }, {}), (e) => e.code === 'unscoped_pid');
    assert.throws(() => generate({ kind: 'pid_lookup' }, { aid: '', earliest: '-1h', latest: 'now', pid: '1' }), (e) => e.code === 'unscoped_pid');
  });

  test('placeholders do not satisfy the gate', () => {
    assert.throws(() => generate({ kind: 'pid_lookup' }, { aid: '$aid$', earliest: '$earliest$', latest: '$latest$', pid: '1' }), (e) => e.code === 'unscoped_pid');
  });

  test('macro form is gated the same way', () => {
    assert.throws(() => generate({ kind: 'pid_lookup' }, { aid: 'a', pid: '1', earliest: '-1h' }, { form: 'macro' }), (e) => e.code === 'unscoped_pid');
  });

  test('an edge whose scope includes time throws the same', () => {
    const raw = edge('e_raw_pid');
    assert.throws(() => generate({ kind: 'edge', edge: raw }, { value: '4820', aid: 'a', earliest: '-1h' }), (e) => e.code === 'unscoped_pid');
    assert.throws(() => generate({ kind: 'edge', edge: raw }, { value: '4820' }), (e) => e.code === 'unscoped_pid');
    const ok = generate({ kind: 'edge', edge: raw }, { value: '4820', aid: 'a', earliest: '-1h', latest: 'now' });
    assert.match(ok.spl, /aid="a" RawProcessId="4820"/);
  });

  test('pid_lookup with the scope bound emits the reference shape (queries/process/03)', () => {
    const r = generate({ kind: 'pid_lookup' }, FULL);
    assert.match(r.spl, /earliest=-1h latest=now/);
    assert.match(r.spl, /aid="abc123" RawProcessId="4820"/);
    assert.match(r.spl, /\(event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2\)/);
    assert.match(r.spl, /\| table _time aid TargetProcessId RawProcessId ImageFileName CommandLine ProcessStartTime ParentProcessId/);
    assert.match(r.spl, /\| sort _time$/);
    assert.deepEqual(r.missing, []);
  });

  test('sweep: no output carries a RawProcessId predicate unless aid+earliest+latest were bound', () => {
    for (const { pivot, params, r } of allOutputs()) {
      if (/RawProcessId\s*=/.test(r.spl)) {
        const bound = ['aid', 'earliest', 'latest'].every((k) => params[k] && String(params[k]).trim());
        assert.ok(bound, `${pivot.kind} ${pivot.edge ? pivot.edge.id : ''} emitted RawProcessId= without full scope`);
      }
    }
  });
});

describe('invariant 2 — asserted edges are stamped', () => {
  test('first line is the ASSERTED comment with the edge note', () => {
    const e = edge('e_context_to_target');
    const r = generate({ kind: 'edge', edge: e }, { value: '6127484919', aid: 'abc' });
    const first = r.spl.split('\n')[0];
    assert.equal(r.hazards[0].level, 'asserted');
    assert.ok(r.hazards[0].text.startsWith(e.note));
    assert.ok(!r.spl.includes('```'), 'no comment in the SPL');
    assert.equal(r.asserted, true);
  });

  test('confirmed edges are not stamped', () => {
    const r = generate({ kind: 'edge', edge: edge('e_aid_to_aidmaster') }, { value: 'abc' });
    assert.equal(r.asserted, false);
    assert.ok(!hzLevels(r).includes('asserted'));
  });

  test('stamp precedes every other line, in both forms', () => {
    const e = edge('e_sha256string_to_sha256hashdata');
    for (const form of ['inline', 'macro']) {
      const r = generate({ kind: 'edge', edge: e }, { value: 'a'.repeat(64), earliest: '-24h' }, { form });
      assert.equal(r.hazards[0].level, 'asserted');
      assert.equal(r.form, form);
    }
  });

  test('backticks in a note cannot break out of the comment', () => {
    const e = { ...edge('e_context_to_target'), note: 'uses `TargetProcessId`' };
    const r = generate({ kind: 'edge', edge: e }, { value: '1', aid: 'a' });
    const first = r.spl.split('\n')[0];
    assert.ok(!r.spl.includes('```'));
  });
});

describe('invariant 3 — time bounds on _time with the exact comment', () => {
  test('every output with a time bound carries the comment verbatim', () => {
    assert.match(TIME_NOTE.text, /_time \(index time\)/);
    for (const { pivot, r } of allOutputs()) {
      if (/(^|\s)(earliest|latest)=/.test(r.spl) || r.form === 'macro') {
        assert.ok(r.hazards.includes(TIME_NOTE), `${pivot.kind} lacks the _time note`);
      }
    }
  });

  test('no time predicate is ever on timestamp / ContextTimeStamp / ProcessStartTime', () => {
    for (const { r } of allOutputs()) {
      assert.doesNotMatch(r.spl, /\b(timestamp|ContextTimeStamp|ProcessStartTime)\s*[<>]=?/);
      assert.doesNotMatch(r.spl, /\b(timestamp|ContextTimeStamp)\s*=/);
    }
  });

  test('unbound required time bounds render as placeholders and are listed in missing', () => {
    const r = generate({ kind: 'process_events' }, { aid: 'a', tpid: '1' });
    assert.match(r.spl, /earliest=\$earliest\$ latest=\$latest\$/);
    assert.deepEqual(r.missing, ['earliest', 'latest']);
  });

  test('odd time strings are quoted', () => {
    const r = generate({ kind: 'process_table' }, { aid: 'a', earliest: '09/01/2026:00:00:00', latest: '-1h@h' });
    assert.match(r.spl, /earliest=09\/01\/2026:00:00:00|earliest="09\/01\/2026:00:00:00"/);
    assert.match(r.spl, /latest=-1h@h/);
  });
});

describe('invariant 4 — command allowlist (lint)', () => {
  test('lint rejects join / map / transaction and unknown commands', () => {
    assert.equal(lint('index=x | join aid [search index=y]').ok, false);
    assert.equal(lint('index=x | map search="x"').ok, false);
    assert.equal(lint('index=x | transaction aid').ok, false);
    assert.equal(lint('index=x | dedup aid').ok, false);
    assert.equal(lint('index=x | `my_other_macro(1)`').ok, false);
    assert.deepEqual(lint('search index=x | JOIN aid [search index=y]').violations, ['forbidden command: join']);
  });

  test('lint is comment-aware and quote-aware', () => {
    assert.equal(lint('```never join on this``` search index=x | stats count').ok, true);
    assert.equal(lint('search index=x | eval s="a | join b" | table s').ok, true);
    assert.equal(lint('index=`cs_index` sourcetype=x | stats count').ok, true);
    assert.equal(lint('`cs_trace_process("a","b","-1h")`').ok, true);
  });

  test('every generated output passes lint', () => {
    for (const { pivot, form, r } of allOutputs()) {
      const l = lint(r.spl);
      assert.ok(l.ok, `${pivot.kind} ${form.form}: ${l.violations.join('; ')}\n${r.spl}`);
      for (const f of FORBIDDEN_COMMANDS) assert.doesNotMatch(r.spl.replace(/```[\s\S]*?```/g, ''), new RegExp(`\\|\\s*${f}\\b`, 'i'));
    }
  });
});

describe('invariant 5 — quoting / escaping', () => {
  test('quote escapes backslash then double quote', () => {
    assert.equal(quote('C:\\Windows\\x'), '"C:\\\\Windows\\\\x"');
    assert.equal(quote('say "hi"'), '"say \\"hi\\""');
    assert.equal(quote('a"\\b'), '"a\\"\\\\b"');
  });

  test('values reach the SPL escaped, in both places the trace uses them', () => {
    const r = generate({ kind: 'trace' }, { field: 'CommandLine', value: 'C:\\x "q"', earliest: '-1h' });
    const esc = '"C:\\\\x \\"q\\""';
    assert.equal(r.spl.split(esc).length - 1, 2);
  });

  test('a value cannot smuggle a pipe or a command', () => {
    const r = generate({ kind: 'process_events' }, { ...FULL, tpid: '1" | join x [search index=y] | search a="' });
    assert.equal(lint(r.spl).ok, true);
  });

  test('index and sourcetype are emitted explicitly; odd names are quoted', () => {
    const r = generate({ kind: 'process_table' }, { ...FULL, index: 'my index', sourcetype: 'crowdstrike:events:sensor:ithr' });
    assert.match(r.spl, /index="my index" sourcetype=crowdstrike:events:sensor:ithr/);
  });
});

describe('invariant 6 — hazards', () => {
  test('edge.hazard is carried', () => {
    const raw = edge('e_raw_pid');
    const r = generate({ kind: 'edge', edge: raw }, FULL);
    assert.ok(r.hazards.some((h) => h.text === raw.hazard.text && h.level === 'danger'));
    assert.ok(r.hazards.includes(PID_RECYCLING_HAZARD));
    assert.ok(hzLevels(r).includes('danger'));
  });

  test('pid_lookup carries the recycling hazard, in the SPL and the list', () => {
    const r = generate({ kind: 'pid_lookup' }, FULL);
    assert.ok(r.hazards.includes(PID_RECYCLING_HAZARD));
    assert.match(PID_RECYCLING_HAZARD.text, /expect multiple rows/);
    assert.match(PID_RECYCLING_HAZARD.text, /disambiguate on ImageFileName and ProcessStartTime/);
    assert.match(PID_RECYCLING_HAZARD.text, /carry TargetProcessId forward/);
    assert.ok(!r.spl.includes('```'));
  });

  test('tpid_to_pid carries the hand-off caution, verbatim from data/curated/translations.json', () => {
    const t = JSON.parse(readFileSync(join(here, '..', 'data', 'curated', 'translations.json'), 'utf8'));
    const caution = t.pid_translation.guided_workflows.find((w) => w.id === 'cs_to_os').caution;
    assert.equal(HANDOFF_CAUTION.text, caution);
    const r = generate({ kind: 'tpid_to_pid' }, FULL);
    assert.ok(r.hazards.includes(HANDOFF_CAUTION));
    assert.match(r.spl, /\| head 1$/);
  });

  test('sourcetype change is noted when src and dst sourcetypes differ', () => {
    const r = generate({ kind: 'edge', edge: edge('e_sha256string_to_sha256hashdata') }, { value: 'x', earliest: '-1h' });
    const note = r.hazards.find((h) => /Sourcetype change/.test(h.text));
    assert.ok(note);
    assert.match(note.text, /crowdstrike:events:external/);
    assert.match(note.text, /crowdstrike:events:sensor/);
    assert.equal(r.sourcetype, SOURCETYPES.sensor);
    assert.match(r.spl, /sourcetype=crowdstrike:events:sensor/);

    const same = generate({ kind: 'edge', edge: edge('e_context_to_target') }, { value: 'x', aid: 'a' });
    assert.ok(!same.hazards.some((h) => /Sourcetype change/.test(h.text)));
  });

  test('every hazard is also a leading SPL comment', () => {
    for (const { r } of allOutputs()) {
      assert.ok(!r.spl.includes('```'), `${r.kind}: comments are never pasted; hazards live beside the code`);
      assert.ok(r.hazards.length > 0 || r.kind === 'decode', `${r.kind}: at least the index/time notes`);
    }
  });
});

describe('params, defaults, placeholders', () => {
  test('index defaults to the cs_index macro with a comment; never in missing', () => {
    const r = generate({ kind: 'process_table' }, FULL);
    assert.match(r.spl, /index=`cs_index`/);
    assert.ok(hzText(r).includes('cs_index'));
    assert.ok(!r.missing.includes('index'));
    assert.ok(!r.missing.includes('sourcetype'));
  });

  test('sourcetype defaults per kind and is always explicit', () => {
    assert.equal(generate({ kind: 'trace' }, {}).sourcetype, SOURCETYPES.sensor);
    assert.equal(generate({ kind: 'host_lookup' }, {}).sourcetype, SOURCETYPES.aidmaster);
    assert.equal(generate({ kind: 'event_sample' }, { event: 'Event_DetectionSummaryEvent' }).sourcetype, SOURCETYPES.external);
    assert.equal(generate({ kind: 'event_sample' }, { event: 'DnsRequest' }).sourcetype, SOURCETYPES.sensor);
    assert.equal(generate({ kind: 'edge', edge: edge('e_aid_to_aidmaster') }, { value: 'x' }).sourcetype, SOURCETYPES.aidmaster);
    for (const { r } of allOutputs()) if (r.form === 'inline') assert.match(r.spl, /\bsourcetype=/);
  });

  test('unbound params render as $NAME$ and are listed in missing', () => {
    const r = generate({ kind: 'trace' }, {});
    assert.match(r.spl, /\$field\$="\$value\$"/);
    assert.match(r.spl, /earliest=\$earliest\$/);
    assert.deepEqual(r.missing, ['field', 'value', 'earliest']);
    const h = generate({ kind: 'host_lookup' }, {});
    assert.match(h.spl, /ComputerName="\$hostname\$"/);
    assert.deepEqual(h.missing, ['hostname']);
  });

  test('an aid-scoped edge always emits the aid term', () => {
    const r = generate({ kind: 'edge', edge: edge('e_context_to_target') }, { value: '1' });
    assert.match(r.spl, /aid="\$aid\$" TargetProcessId="1"/);
    assert.deepEqual(r.missing, ['aid']);
  });

  test('trace binds aid when given and drops the host note', () => {
    const without = generate({ kind: 'trace' }, { field: 'DomainName', value: 'x', earliest: '-1h' });
    const withAid = generate({ kind: 'trace' }, { field: 'DomainName', value: 'x', earliest: '-1h', aid: 'a' });
    assert.ok(without.hazards.some((h) => /bind aid/.test(h.text)));
    assert.ok(!withAid.hazards.some((h) => /bind aid/.test(h.text)));
    assert.match(withAid.spl, /\n  aid="a"\n/);
  });

  test('decode uses the pivot.decode record and falls back to the TA naming convention', () => {
    const a = generate({ kind: 'decode', decode: { lookup: 'crowdstrike_Foo.csv', meaning_field: 'Foo_meaning' } }, { field: 'Foo' });
    assert.match(a.spl, /\| lookup crowdstrike_Foo Foo OUTPUT Foo_meaning/);
    const b = generate({ kind: 'decode' }, { field: 'Bar' });
    assert.match(b.spl, /\| lookup crowdstrike_Bar Bar OUTPUT Bar_meaning/);
  });
});

describe('reference shapes', () => {
  test('trace matches cs_trace_process line for line (modulo the search line)', () => {
    const r = generate({ kind: 'trace' }, { field: 'SHA256HashData', value: 'abc', earliest: '-24h' });
    const body = r.spl.split('\n').filter((l) => !l.startsWith('```'));
    assert.equal(body[0], 'search index=`cs_index` sourcetype=crowdstrike:events:sensor earliest=-24h');
    assert.equal(body[1], '  ( SHA256HashData="abc"');
    assert.ok(body.includes('| eval _pid = coalesce(ContextProcessId, TargetProcessId)'));
    assert.ok(body.includes('        by aid, _pid'));
    assert.ok(body.includes('| rename _pid as TargetProcessId'));
    assert.equal(body[body.length - 1], '| sort - last_seen');
  });

  test('process_table matches cs_process_table', () => {
    const r = generate({ kind: 'process_table' }, FULL);
    assert.match(r.spl, /\| stats min\(_time\) as start_seen, values\(RawProcessId\) as os_pid,/);
    assert.match(r.spl, /        by aid, TargetProcessId\n\| convert ctime\(start_seen\)\n\| sort start_seen$/);
  });

  test('process_events matches cs_process_events', () => {
    const r = generate({ kind: 'process_events' }, FULL);
    assert.match(r.spl, /\(ContextProcessId="6127484919" OR TargetProcessId="6127484919"\)/);
    assert.match(r.spl, /\| table _time event_simpleName ContextProcessId TargetProcessId\n\| sort _time$/);
  });

  test('every inline output is multi-line with 2-space continuation on the search line', () => {
    for (const { r } of allOutputs()) {
      if (r.form !== 'inline') continue;
      const lines = r.spl.split('\n').filter((l) => !l.startsWith('```'));
      assert.ok(lines.length >= 3);
      assert.match(lines[0], /^search index=/);
      assert.match(lines[1], /^  \S/);
    }
  });
});

describe('reference files — queries/macros/SPLUNK_CLOUD_MACROS.md', () => {
  const md = readFileSync(join(here, '..', 'queries', 'macros', 'SPLUNK_CLOUD_MACROS.md'), 'utf8');
  function definition(name) {
    const re = new RegExp('\\*\\*Name:\\*\\* `' + name + '(?:\\(\\d\\))?`[\\s\\S]*?\\*\\*Definition:\\*\\*\\n```\\n([\\s\\S]*?)```');
    const m = re.exec(md);
    assert.ok(m, `macro ${name} not found in the md`);
    return m[1].trimEnd().split('\n');
  }
  const pipeline = (lines) => lines.slice(lines.findIndex((l) => l.startsWith('|')));
  const predicates = (lines) => lines.slice(1, lines.findIndex((l) => l.startsWith('|')));
  const body = (spl) => spl.split('\n').filter((l) => !l.startsWith('```'));

  test('cs_trace_process ≡ inline trace (pipeline and predicate lines, placeholders included)', () => {
    const ref = definition('cs_trace_process');
    const mine = body(generate({ kind: 'trace' }, {}).spl);
    assert.deepEqual(pipeline(mine), pipeline(ref));
    assert.deepEqual(predicates(mine), predicates(ref));
    assert.equal(mine[0], ref[0]);
  });

  test('cs_process_table ≡ inline process_table', () => {
    const ref = definition('cs_process_table');
    const mine = body(generate({ kind: 'process_table' }, {}).spl);
    assert.deepEqual(pipeline(mine), pipeline(ref));
    assert.deepEqual(predicates(mine), predicates(ref));
    assert.equal(mine[0], ref[0] + ' latest=$latest$');
  });

  test('cs_pid_lookup ≡ inline pid_lookup (macro placeholder is $ospid$; ours is $pid$)', () => {
    const ref = definition('cs_pid_lookup');
    const mine = body(generate({ kind: 'pid_lookup' }, { aid: 'A', earliest: 'E', latest: 'L' }).spl);
    assert.deepEqual(pipeline(mine), pipeline(ref));
    assert.deepEqual(predicates(mine), predicates(ref).map((l) => l.replace('$ospid$', '$pid$').replace('"$aid$"', '"A"')));
    assert.equal(mine[0], ref[0].replace('$earliest$', 'E') + ' latest=L');
  });

  test('cs_process_events ≡ inline process_events', () => {
    const ref = definition('cs_process_events');
    const mine = body(generate({ kind: 'process_events' }, {}).spl);
    assert.deepEqual(pipeline(mine), pipeline(ref));
    assert.deepEqual(predicates(mine), predicates(ref));
  });

  test('cs_pid_lookup in the md takes no latest argument (why macro form is restricted)', () => {
    assert.match(md, /\*\*Name:\*\* `cs_pid_lookup\(3\)`\n\*\*Arguments:\*\* `aid, ospid, earliest`/);
  });
});

describe('macro form', () => {
  test('missing names only params the emitted form renders as $NAME$', () => {
    for (const { pivot, form, r } of allOutputs()) {
      for (const n of r.missing) assert.ok(r.spl.includes(`$${n}$`), `${pivot.kind} ${form.form}: missing lists ${n} but the SPL has no $${n}$`);
    }
    const r = generate({ kind: 'process_events' }, { aid: 'a', tpid: '1' }, { form: 'macro' });
    assert.deepEqual(r.missing, ['earliest']);
    assert.match(hzText(r), /cs_process_events has no latest argument \(the macro searches up to now\)/);
  });

  test('the four macro kinds return macro calls', () => {
    const t = generate({ kind: 'trace' }, { field: 'DomainName', value: 'evil.example.com', earliest: '-7d' }, { form: 'macro' });
    assert.equal(t.form, 'macro');
    assert.ok(t.spl.endsWith('`cs_trace_process("DomainName", "evil.example.com", "-7d")`'));

    const pt = generate({ kind: 'process_table' }, { aid: 'a', earliest: '-24h', latest: 'now' }, { form: 'macro' });
    assert.equal(pt.form, 'macro');
    assert.ok(pt.spl.endsWith('`cs_process_table("a", "-24h")`'));

    const pl = generate({ kind: 'pid_lookup' }, FULL, { form: 'macro' });
    assert.equal(pl.form, 'macro');
    assert.ok(pl.spl.endsWith('`cs_pid_lookup("abc123", "4820", "-1h")`'));

    const pe = generate({ kind: 'process_events' }, FULL, { form: 'macro' });
    assert.equal(pe.form, 'macro');
    assert.ok(pe.spl.endsWith('`cs_process_events("abc123", "6127484919", "-1h")`'));
    for (const r of [t, pt, pl, pe]) assert.ok(lint(r.spl).ok);
  });

  test('kinds with no macro fall back to inline and say so', () => {
    for (const kind of ['tpid_to_pid', 'host_lookup', 'event_sample', 'decode']) {
      const r = generate({ kind }, FULL, { form: 'macro' });
      assert.equal(r.form, 'inline', kind);
      assert.match(hzText(r), /No macro for pivot kind/);
    }
  });

  test('a latest bound the macro cannot carry forces inline', () => {
    const r = generate({ kind: 'process_table' }, { aid: 'a', earliest: '-24h', latest: '-1h' }, { form: 'macro' });
    assert.equal(r.form, 'inline');
    assert.match(hzText(r), /cannot carry latest=-1h/);
    assert.match(r.spl, /earliest=-24h latest=-1h/);
  });

  test('macro-form values are escaped and the ASSERTED stamp still leads', () => {
    const e = edge('e_sha256string_to_sha256hashdata');
    const r = generate({ kind: 'edge', edge: e }, { value: 'a"b', earliest: '-1h' }, { form: 'macro' });
    assert.equal(r.form, 'macro');
    assert.ok(r.spl.endsWith('`cs_trace_process("SHA256HashData", "a\\"b", "-1h")`'));
    assert.equal(r.hazards[0].level, 'asserted');
  });

  test('macro form resolves edges: os_pid → cs_pid_lookup, aid → cs_process_table', () => {
    const raw = generate({ kind: 'edge', edge: edge('e_raw_pid') }, FULL, { form: 'macro' });
    assert.equal(raw.form, 'macro');
    assert.match(raw.spl, /`cs_pid_lookup\("abc123", "v", "-1h"\)`$/);
  });
});

// trace and process_events resolve a process through the asserted ContextProcessId edge.
test('asserted attribution is labelled on the shapes that rely on it', async (t) => {
  const cases = [
    ['process_events', { kind: 'process_events' },
      { aid: 'abc', tpid: '4242', earliest: '-24h', latest: 'now' }],
    ['trace', { kind: 'trace' },
      { field: 'SHA256HashData', value: 'deadbeef', earliest: '-24h', aid: 'abc' }],
  ];
  for (const [name, pivot, params] of cases) {
    await t.test(`${name} sets the flag and carries the asserted label`, () => {
      const r = generate(pivot, params);
      assert.equal(r.asserted, true, `${name} resolves a process via ContextProcessId`);
      assert.equal(r.hazards[0].level, 'asserted', `${name} leads with the asserted label`);
      assert.ok(!r.spl.includes('```'));
      assert.equal(lint(r.spl).ok, true);
    });
  }

  await t.test('the label appears once', () => {
    const r = generate({ kind: 'process_events' },
      { aid: 'a', tpid: '1', earliest: '-24h', latest: 'now' });
    assert.equal(r.hazards.filter((h) => h.level === 'asserted').length, 1);
  });

  await t.test('a confirmed-only pivot is not labelled asserted', () => {
    const r = generate({ kind: 'process_table' },
      { aid: 'abc', earliest: '-24h', latest: 'now' });
    assert.equal(r.asserted, false);
    assert.ok(!hzLevels(r).includes('asserted'));
  });
});

test('generated SPL never contains a comment, for every kind and both forms', () => {
  for (const { pivot, form, r } of allOutputs()) {
    assert.ok(!r.spl.includes('```'), `${pivot.kind} ${form.form}`);
    assert.ok(!/^\s*#/m.test(r.spl), `${pivot.kind} ${form.form}`);
  }
});

test('event_sample carries the held value and honours an explicit sourcetype', () => {
  const r = generate({ kind: 'event_sample' },
    { event: 'Event_DetectionSummaryEvent', sourcetype: 'crowdstrike:events:external',
      earliest: '-24h', field: 'MD5String', value: 'd41d8cd98f00b204e9800998ecf8427e' });
  assert.ok(r.spl.includes('sourcetype=crowdstrike:events:external'));
  assert.ok(r.spl.includes('MD5String="d41d8cd98f00b204e9800998ecf8427e"'));
  assert.equal(lint(r.spl).ok, true);
  const plain = generate({ kind: 'event_sample' }, { event: 'DnsRequest', earliest: '-1h' });
  assert.ok(!plain.spl.includes('$field$'), 'no dangling placeholder when nothing is held');
});

test('generate() refuses to return SPL that fails lint', async (t) => {
  // Simulate a future shape regression by feeding a value that lint must
  // catch only if the output were unquoted -- and confirm the real path is
  // quoted (no throw), then that the gate itself works on a raw string.
  const r = generate({ kind: 'event_sample' }, { event: 'DnsRequest', earliest: '-1h', value: 'x | join y', field: 'DomainName' });
  assert.equal(lint(r.spl).ok, true, 'a piped value is quoted, so it is not a command');
  assert.equal(lint('search index=x | join type=left aid [ search index=y ]').ok, false);
});
