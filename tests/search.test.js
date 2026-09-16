import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { classify, matchNames, editDistance, familyOf, isIPv6, isDomain, KINDS, MAX_RESULTS } from '../app/lib/search.js';

const INDEX = {
  fields: [
    'aid', 'ContextProcessId', 'TargetProcessId', 'ParentProcessId', 'RawProcessId', 'ResponsiblePid',
    'SourceProcessId', 'ContextTimeStamp', 'ProcessStartTime', 'SHA256HashData', 'MD5HashData',
    'RemoteAddressIP4', 'LocalAddressIP4', 'UserSid', 'ImageFileName', 'TargetFileName', 'DomainName',
    'CommandLine', 'threat.tactic.id', 'process_id', 'parent_process_id', 'event_simpleName',
  ],
  events: ['ProcessRollup2', 'SyntheticProcessRollup2', 'DnsRequest', 'LoginItemAdded', 'ConfigurationProfileModified', 'Event_DetectionSummaryEvent'],
};

describe('classify', () => {
  test('kinds are the expected set', () => {
    assert.deepEqual([...KINDS].sort(), ['domain', 'empty', 'falcon_pid', 'ipv4', 'ipv6', 'md5_or_aid', 'name', 'os_pid', 'path', 'sha1', 'sha256'].sort());
  });

  test('empty', () => {
    assert.equal(classify('').kind, 'empty');
    assert.equal(classify('   ').kind, 'empty');
    assert.equal(classify(null).kind, 'empty');
  });

  test('hashes by length', () => {
    assert.equal(classify('a'.repeat(64)).kind, 'sha256');
    assert.equal(classify('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855').kind, 'sha256');
    assert.equal(classify('b'.repeat(40)).kind, 'sha1');
    assert.equal(classify('c'.repeat(32)).kind, 'md5_or_aid');
    assert.equal(classify('g'.repeat(64)).kind, 'name');
  });

  test('32-hex is ambiguous and offers both candidates', () => {
    const r = classify('0123456789abcdef0123456789abcdef');
    assert.equal(r.kind, 'md5_or_aid');
    assert.equal(r.ambiguous, true);
    assert.deepEqual(r.candidates.map((c) => c.kind), ['md5', 'aid']);
    assert.ok(r.candidates[0].fields.includes('MD5HashData'));
    assert.ok(r.candidates[1].fields.includes('aid'));
  });

  test('IPv4', () => {
    assert.equal(classify('10.1.2.3').kind, 'ipv4');
    assert.equal(classify('255.255.255.255').kind, 'ipv4');
    assert.equal(classify('256.1.1.1').kind, 'name');
    assert.equal(classify('1.2.3').kind, 'name');
    assert.ok(classify('10.1.2.3').candidates[0].fields.includes('RemoteAddressIP4'));
  });

  test('IPv6', () => {
    for (const v of ['::1', 'fe80::1', '2001:db8::8a2e:370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', '::ffff:192.0.2.128', 'fe80::1%en0']) {
      assert.equal(classify(v).kind, 'ipv6', v);
    }
    assert.equal(isIPv6('1:2:3:4:5:6:7:8:9'), false);
    assert.equal(isIPv6('1::2::3'), false);
    assert.equal(isIPv6('12:34'), false);
  });

  test('domain-shaped, but file names are not domains', () => {
    assert.equal(classify('evil.example.com').kind, 'domain');
    assert.equal(classify('EXAMPLE.COM').kind, 'domain');
    assert.equal(classify('cmd.exe').kind, 'name');
    assert.equal(classify('powershell.exe').kind, 'name');
    assert.equal(classify('update.js').kind, 'name');
    assert.equal(classify('localhost').kind, 'name');
    assert.equal(isDomain('a..b'), false);
  });

  test('integers: ≤ 2^32 is an OS PID, larger is a Falcon process id', () => {
    assert.equal(classify('4820').kind, 'os_pid');
    assert.equal(classify('0').kind, 'os_pid');
    assert.equal(classify('4294967296').kind, 'os_pid');
    assert.equal(classify('4294967297').kind, 'falcon_pid');
    assert.equal(classify('6127484919').kind, 'falcon_pid');
    assert.equal(classify('999999999999999999999999').kind, 'falcon_pid');
    assert.deepEqual(classify('4820').candidates[0].fields, ['RawProcessId']);
    assert.ok(classify('6127484919').candidates[0].fields.includes('TargetProcessId'));
  });

  test('paths', () => {
    assert.equal(classify('C:\\Windows\\System32\\cmd.exe').kind, 'path');
    assert.equal(classify('/usr/bin/curl').kind, 'path');
    assert.equal(classify('\\Device\\HarddiskVolume2\\x.exe').kind, 'path');
    assert.equal(classify('evil.example.com/payload').kind, 'path');
  });

  test('everything else is a name', () => {
    assert.equal(classify('ResponsiblePid').kind, 'name');
    assert.equal(classify('ResponsiblePid').value, 'ResponsiblePid');
    assert.equal(classify('  ResponsiblePid ').value, 'ResponsiblePid');
  });

  test('with an index, an exact field/event name wins over every value rule', () => {
    const r = classify('threat.tactic.id', INDEX);
    assert.equal(r.kind, 'name');
    assert.equal(r.candidates[0].name, 'threat.tactic.id');
    assert.equal(classify('threat.tactic.id').kind, 'domain');
    assert.equal(classify('aid', INDEX).kind, 'name');
    assert.equal(classify('processrollup2', INDEX).candidates[0].name, 'ProcessRollup2');
    assert.equal(classify('processrollup2', INDEX).candidates[0].kind, 'event');
  });

  test('with an index, an unknown name carries name suggestions', () => {
    const r = classify('ResponsibleProcessId', INDEX);
    assert.equal(r.kind, 'name');
    assert.equal(r.candidates[0].name, 'ResponsiblePid');
  });
});

describe('matchNames', () => {
  test('ResponsibleProcessId → ResponsiblePid at rank 1 (family: ProcessId ≡ Pid)', () => {
    const r = matchNames('ResponsibleProcessId', INDEX);
    assert.ok(r.length > 0);
    assert.equal(r[0].name, 'ResponsiblePid');
    assert.equal(r[0].kind, 'field');
    assert.ok(['fuzzy', 'family'].includes(r[0].match));
    assert.equal(r[0].match, 'family');
  });

  test('family tier returns the other names sharing the suffix', () => {
    const r = matchNames('FooProcessId', INDEX);
    const names = r.map((x) => x.name);
    for (const n of ['ContextProcessId', 'TargetProcessId', 'ParentProcessId', 'RawProcessId', 'SourceProcessId', 'ResponsiblePid']) {
      assert.ok(names.includes(n), n);
    }
    assert.ok(r.every((x) => x.match === 'family'));
    assert.deepEqual(familyOf('ContextTimeStamp'), { family: 'timestamp', stem: 'Context', suffix: 'TimeStamp' });
    assert.equal(familyOf('Pid'), null);
    assert.equal(familyOf('CommandLine'), null);
  });

  test('exact beats prefix beats substring beats fuzzy; case-sensitive exact first', () => {
    const idx = { fields: ['aid', 'AID', 'aidmaster', 'said', 'aif'], events: [] };
    const r = matchNames('aid', idx);
    assert.deepEqual(r.map((x) => [x.name, x.match]), [
      ['aid', 'exact'], ['AID', 'exact'], ['aidmaster', 'prefix'], ['said', 'substring'], ['aif', 'fuzzy'],
    ]);
  });

  test('prefix and substring are case-insensitive', () => {
    const r = matchNames('targetproc', INDEX);
    assert.equal(r[0].name, 'TargetProcessId');
    assert.equal(r[0].match, 'prefix');
    const s = matchNames('hashdata', INDEX);
    assert.ok(s.every((x) => x.match === 'substring'));
    assert.deepEqual(s.map((x) => x.name).sort(), ['MD5HashData', 'SHA256HashData']);
  });

  test('fuzzy: ≤2 edits for len ≥ 6, ≤1 otherwise', () => {
    assert.equal(matchNames('DnsReqest', INDEX)[0].name, 'DnsRequest');
    assert.equal(matchNames('DnsReqest', INDEX)[0].match, 'fuzzy');
    assert.equal(matchNames('DnsReqes', INDEX)[0].name, 'DnsRequest'); // 2 edits, len ≥ 6
    assert.equal(matchNames('DnsReqe', INDEX).length, 0); // 3 edits
    assert.equal(matchNames('aic', INDEX)[0].name, 'aid'); // 1 edit, short
    assert.equal(matchNames('acc', INDEX).length, 0); // 2 edits, short → no
    assert.equal(editDistance('kitten', 'sitting'), 3);
    assert.equal(editDistance('abc', 'abc'), 0);
  });

  test('events are matched and labelled', () => {
    const r = matchNames('Rollup', INDEX);
    assert.ok(r.every((x) => x.kind === 'event' && x.match === 'substring'));
    assert.deepEqual(r.map((x) => x.name), ['ProcessRollup2', 'SyntheticProcessRollup2']);
  });

  test('capped at 25, deduplicated, empty query → []', () => {
    const fields = Array.from({ length: 60 }, (_, i) => `Field${String(i).padStart(2, '0')}`);
    const r = matchNames('field', { fields, events: fields.slice(0, 5).map((f) => f) });
    assert.equal(r.length, MAX_RESULTS);
    assert.equal(new Set(r.map((x) => `${x.kind}:${x.name}`)).size, MAX_RESULTS);
    assert.deepEqual(matchNames('', INDEX), []);
    assert.deepEqual(matchNames('x', {}), []);
  });
});
