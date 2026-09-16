// Omnibox logic: value classifier + name matcher. Pure functions.
//
// classify(input, index?) → { kind, value, candidates, ambiguous? }
//   candidates is discriminated by `kind`:
//     kind !== 'name' → [{ kind, label, fields }]              value carriers (seed list)
//     kind === 'name' → matchNames() rows                       [{ name, kind: 'field'|'event', match }]
//   ambiguous: true only on md5_or_aid (both candidates offered, in that order).
// matchNames(query, index) → [{ name, kind: 'field'|'event', match }]  (≤ 25, ranked)
//   match ∈ exact | prefix | substring | fuzzy | family, in that rank order.

export const KINDS = Object.freeze([
  'sha256', 'sha1', 'md5_or_aid', 'ipv4', 'ipv6', 'domain', 'os_pid', 'falcon_pid', 'path', 'name', 'empty',
]);

// Well-known FDR fields that carry each kind of value. The view intersects these with the
// bundle's fields_by_role; this list is the "first move" seed, not the catalogue.
const CARRIERS = Object.freeze({
  sha256: ['SHA256HashData', 'SHA256String'],
  sha1: ['SHA1HashData'],
  md5: ['MD5HashData'],
  aid: ['aid', 'AgentIdString'],
  ipv4: ['RemoteAddressIP4', 'LocalAddressIP4', 'aip'],
  ipv6: ['RemoteAddressIP6', 'LocalAddressIP6'],
  domain: ['DomainName', 'ComputerName'],
  os_pid: ['RawProcessId'],
  falcon_pid: ['TargetProcessId', 'ContextProcessId', 'ParentProcessId'],
  path: ['ImageFileName', 'TargetFileName', 'CommandLine'],
  name: [],
});

const MAX_OS_PID = 4294967296n; // 2^32, inclusive

// File extensions that must not be read as a TLD ("cmd.exe" is a name, not a domain).
const FILE_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse', 'wsf', 'msi', 'scr', 'cpl',
  'txt', 'log', 'json', 'csv', 'xml', 'yml', 'yaml', 'ini', 'cfg', 'conf', 'md',
  'py', 'sh', 'rb', 'pl', 'php', 'jar', 'class', 'so', 'dylib', 'app', 'bin', 'dat', 'tmp',
  'zip', 'rar', '7z', 'gz', 'tar', 'iso', 'img', 'vhd', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
  'ppt', 'pptx', 'rtf', 'lnk', 'url', 'hta', 'reg', 'plist', 'dmg', 'pkg', 'deb', 'rpm',
]);

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+([a-z][a-z0-9-]{1,62})\.?$/i;

function cand(kind, label, fields) {
  return { kind, label, fields: fields.slice() };
}

export function isIPv4(s) {
  const m = IPV4_RE.exec(s);
  return !!m && m.slice(1).every((o) => Number(o) <= 255 && !(o.length > 1 && o[0] === '0'));
}

export function isIPv6(s) {
  if (!s.includes(':')) return false;
  let str = s;
  const zone = str.indexOf('%');
  if (zone >= 0) str = str.slice(0, zone);
  if (str.length < 2) return false;
  const parts = str.split('::');
  if (parts.length > 2) return false;
  const groupsOf = (side) => {
    if (side === '') return [];
    const gs = side.split(':');
    // trailing embedded IPv4 (::ffff:1.2.3.4)
    if (gs.length && gs[gs.length - 1].includes('.')) {
      if (!isIPv4(gs[gs.length - 1])) return null;
      gs.splice(gs.length - 1, 1, '0', '0');
    }
    return gs.every((g) => /^[0-9a-f]{1,4}$/i.test(g)) ? gs : null;
  };
  const left = groupsOf(parts[0]);
  const right = parts.length === 2 ? groupsOf(parts[1]) : [];
  if (left === null || right === null) return false;
  const n = left.length + right.length;
  return parts.length === 2 ? n <= 7 : n === 8;
}

export function isDomain(s) {
  const m = DOMAIN_RE.exec(s);
  if (!m) return false;
  const tld = m[1].toLowerCase();
  if (FILE_EXTENSIONS.has(tld)) return false;
  if (/^\d+$/.test(tld)) return false;
  return true;
}

function exactName(input, index) {
  if (!index) return null;
  const out = [];
  for (const kind of ['field', 'event']) {
    const list = index[kind === 'field' ? 'fields' : 'events'] || [];
    for (const n of list) {
      if (n === input) out.unshift({ name: n, kind, match: 'exact' });
      else if (n.toLowerCase() === input.toLowerCase()) out.push({ name: n, kind, match: 'exact' });
    }
  }
  return out.length ? out : null;
}

// Classify a pasted value. `index` ({ fields, events }) is optional: when given, an exact
// field/event name wins over every value rule (so `threat.tactic.id` is a name, not a domain).
export function classify(input, index) {
  const value = String(input == null ? '' : input).trim();
  if (!value) return { kind: 'empty', value: '', candidates: [] };

  const named = exactName(value, index);
  if (named) return { kind: 'name', value, candidates: named };

  if (/^[0-9a-f]{64}$/i.test(value)) {
    return { kind: 'sha256', value, candidates: [cand('sha256', 'SHA-256 file hash', CARRIERS.sha256)] };
  }
  if (/^[0-9a-f]{40}$/i.test(value)) {
    return { kind: 'sha1', value, candidates: [cand('sha1', 'SHA-1 file hash', CARRIERS.sha1)] };
  }
  if (/^[0-9a-f]{32}$/i.test(value)) {
    return {
      kind: 'md5_or_aid',
      value,
      ambiguous: true,
      candidates: [
        cand('md5', 'MD5 file hash', CARRIERS.md5),
        cand('aid', 'CrowdStrike agent id (host)', CARRIERS.aid),
      ],
    };
  }
  if (isIPv4(value)) return { kind: 'ipv4', value, candidates: [cand('ipv4', 'IPv4 address', CARRIERS.ipv4)] };
  if (isIPv6(value)) return { kind: 'ipv6', value, candidates: [cand('ipv6', 'IPv6 address', CARRIERS.ipv6)] };
  if (/^\d+$/.test(value)) {
    if (BigInt(value) <= MAX_OS_PID) {
      return { kind: 'os_pid', value, candidates: [cand('os_pid', 'OS PID (RawProcessId space)', CARRIERS.os_pid)] };
    }
    return {
      kind: 'falcon_pid',
      value,
      candidates: [cand('falcon_pid', 'Falcon process id (TargetProcessId space)', CARRIERS.falcon_pid)],
    };
  }
  if (value.includes('/') || value.includes('\\')) {
    return { kind: 'path', value, candidates: [cand('path', 'file path / image name', CARRIERS.path)] };
  }
  if (isDomain(value)) return { kind: 'domain', value, candidates: [cand('domain', 'domain name', CARRIERS.domain)] };
  return { kind: 'name', value, candidates: index ? matchNames(value, index) : [] };
}

// ---------------------------------------------------------------------------
// Name matching

export const MAX_RESULTS = 25;

// Suffix → family key. ProcessId and Pid are one family.
export const FAMILIES = Object.freeze([
  { suffix: 'ProcessId', family: 'pid' },
  { suffix: 'Pid', family: 'pid' },
  { suffix: 'TimeStamp', family: 'timestamp' },
  { suffix: 'HashData', family: 'hash' },
  { suffix: 'AddressIP4', family: 'ip4' },
  { suffix: 'Sid', family: 'sid' },
  { suffix: 'FileName', family: 'filename' },
]);

export function familyOf(name) {
  for (const f of FAMILIES) {
    if (name.length > f.suffix.length && name.endsWith(f.suffix)) {
      return { family: f.family, stem: name.slice(0, -f.suffix.length), suffix: f.suffix };
    }
  }
  return null;
}

// Levenshtein with early exit above `max`.
export function editDistance(a, b, max = Infinity) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const n = a.length, m = b.length;
  let prev = new Array(m + 1);
  let cur = new Array(m + 1);
  for (let j = 0; j <= m; j++) prev[j] = j;
  for (let i = 1; i <= n; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= m; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    [prev, cur] = [cur, prev];
  }
  return prev[m];
}

function fuzzyLimit(len) {
  return len >= 6 ? 2 : 1;
}

function commonPrefixLen(a, b) {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[i] === b[i]) i++;
  return i;
}

export function matchNames(query, index) {
  const q = String(query == null ? '' : query).trim();
  const idx = index || {};
  if (!q) return [];
  const ql = q.toLowerCase();
  const entries = [];
  for (const n of idx.fields || []) entries.push({ name: n, kind: 'field' });
  for (const n of idx.events || []) entries.push({ name: n, kind: 'event' });

  const seen = new Set();
  const out = [];
  const take = (list, match) => {
    for (const e of list) {
      const key = `${e.kind}:${e.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: e.name, kind: e.kind, match });
    }
  };
  const byLen = (a, b) => a.name.length - b.name.length || a.name.localeCompare(b.name);

  take(entries.filter((e) => e.name === q), 'exact');
  take(entries.filter((e) => e.name.toLowerCase() === ql).sort(byLen), 'exact');
  take(entries.filter((e) => e.name.toLowerCase().startsWith(ql)).sort(byLen), 'prefix');
  take(entries.filter((e) => e.name.toLowerCase().includes(ql)).sort(byLen), 'substring');

  const lim = fuzzyLimit(q.length);
  const fuzzy = [];
  for (const e of entries) {
    if (seen.has(`${e.kind}:${e.name}`)) continue;
    const d = editDistance(ql, e.name.toLowerCase(), lim);
    if (d <= lim) fuzzy.push({ e, d });
  }
  fuzzy.sort((a, b) => a.d - b.d || byLen(a.e, b.e));
  take(fuzzy.map((x) => x.e), 'fuzzy');

  const fam = familyOf(q);
  if (fam) {
    const stem = fam.stem.toLowerCase();
    const family = [];
    for (const e of entries) {
      if (seen.has(`${e.kind}:${e.name}`)) continue;
      const f = familyOf(e.name);
      if (!f || f.family !== fam.family) continue;
      const es = f.stem.toLowerCase();
      const score = es === stem ? 0 : editDistance(stem, es);
      family.push({ e, score, prefix: commonPrefixLen(stem, es) });
    }
    family.sort((a, b) => a.score - b.score || b.prefix - a.prefix || byLen(a.e, b.e));
    take(family.map((x) => x.e), 'family');
  }

  return out.slice(0, MAX_RESULTS);
}
