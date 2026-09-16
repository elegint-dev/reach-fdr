// Reach — SPL generator. The ONLY module that produces SPL strings.
// Contract: docs/ARCHITECTURE.md §3.
// Reference shapes: queries/macros/SPLUNK_CLOUD_MACROS.md, queries/process/*.spl, data/curated/translations.json.
//
// generate(pivot, params, opts) → { spl, hazards, asserted, missing, form, kind, sourcetype }
//
// Plain ES module. No dependencies. No DOM.

export class SplError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'SplError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Constants

export const SOURCETYPES = Object.freeze({
  sensor: 'crowdstrike:events:sensor',
  external: 'crowdstrike:events:external',
  aidmaster: 'crowdstrike:inventory:aidmaster',
  appinfo: 'crowdstrike:appinfo',
  userinfo: 'crowdstrike:userinfo',
  managedassets: 'crowdstrike:managedassets',
  notmanaged: 'crowdstrike:notmanaged',
});

export const INDEX_MACRO = '`cs_index`';

// ARCHITECTURE §3 invariant 3 — byte-for-byte.
// Notes shown beside the SPL, never inside it: the generated text is pure SPL.
export const TIME_NOTE = Object.freeze({
  level: 'note',
  text: 'Time bounds are on _time (index time); timestamp and ContextTimeStamp are sensor-side and differ.',
});
export const INDEX_NOTE = Object.freeze({
  level: 'note',
  text: 'index=`cs_index` is a macro: define it once (queries/macros) or replace it with your index.',
});

// Provenance: SPLUNK_CLOUD_MACROS.md §4 and queries/process/03. Module constant because
// generate() takes no bundle argument .
export const PID_RECYCLING_HAZARD = Object.freeze({
  level: 'danger',
  text: 'RawProcessId is the OS PID and the OS recycles it: expect multiple rows; disambiguate on ImageFileName and ProcessStartTime; carry TargetProcessId forward.',
});

// Provenance: data/curated/translations.json → guided_workflows[id=cs_to_os].caution, verbatim.
// tests/spl.test.js pins this string against the file so it cannot drift silently.
export const HANDOFF_CAUTION = Object.freeze({
  level: 'caution',
  text: 'Once you hand an OS PID to someone, it stops being reliable. If the box has rebooted or the process exited, that PID may now belong to something else entirely. Always pass the ImageFileName and start time alongside it.',
});

export const CONTEXT_ATTRIBUTION_NOTE = Object.freeze({
  // Level `asserted` renders as the asserted chip in the drawer.
  level: 'asserted',
  text: 'ContextProcessId is the attribution key on non-process events. That attribution is asserted from the CrowdStrike data model, not corpus-validated.',
});

export const HOSTNAME_CAUTION = Object.freeze({
  level: 'caution',
  text: 'ComputerName is not stable (rename, reimage, DHCP); aid is. Expect more than one aid for a hostname that has been reimaged. Carry aid forward.',
});

export const TRACE_HOST_NOTE = Object.freeze({
  level: 'note',
  text: 'cs_trace_process scans the observable plus every process-creation event in the window. If you know the host, bind aid: orders of magnitude faster.',
});

// Splunk-Cloud-safe command allowlist (ARCHITECTURE §3 invariant 4).
export const ALLOWED_COMMANDS = Object.freeze([
  'search', 'eval', 'stats', 'eventstats', 'where', 'table', 'sort',
  'convert', 'rename', 'fields', 'head', 'lookup',
]);
export const FORBIDDEN_COMMANDS = Object.freeze(['join', 'map', 'transaction']);
export const KNOWN_MACROS = Object.freeze([
  'cs_index', 'cs_trace_process', 'cs_process_table', 'cs_pid_lookup', 'cs_process_events',
]);

const ANCHOR_FILTER = '(event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2)';
const PROCESS_COLUMNS = '_time aid TargetProcessId RawProcessId ImageFileName CommandLine ProcessStartTime ParentProcessId';

// ---------------------------------------------------------------------------
// Value handling

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const SAFE_TIME_RE = /^[A-Za-z0-9@:+\-._]+$/;
const SAFE_INDEX_RE = /^[A-Za-z0-9_\-*]+$/;
const SAFE_SOURCETYPE_RE = /^[A-Za-z0-9_:\-*.]+$/;

const PLACEHOLDER_RE = /^\$[A-Za-z_][A-Za-z0-9_]*\$$/;

// A value is bound when it is non-empty and not itself a $NAME$ placeholder token.
function isBound(v) {
  if (v === undefined || v === null) return false;
  const s = String(v).trim();
  return s !== '' && !PLACEHOLDER_RE.test(s);
}

// Invariant 5: `"` → `\"`, backslash → `\\`. Backslashes first so quotes are not double-escaped.
export function quote(value) {
  const s = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${s}"`;
}

function ident(name, what) {
  const s = String(name);
  if (!IDENT_RE.test(s)) throw new SplError('bad_identifier', `${what} is not a valid identifier: ${s}`);
  return s;
}


// ---------------------------------------------------------------------------
// Param binding

class Binder {
  constructor(params) {
    this.params = params || {};
    this.missing = [];
  }
  has(name) {
    return isBound(this.params[name]);
  }
  // Quoted value or "$NAME$" placeholder (recorded in `missing`).
  val(name) {
    if (this.has(name)) return quote(this.params[name]);
    this.miss(name);
    return `"$${name}$"`;
  }
  // Time modifier: unquoted when it is a plain modifier (-24h, now, @d, epoch), quoted otherwise.
  time(name) {
    if (!this.has(name)) {
      this.miss(name);
      return `$${name}$`;
    }
    const s = String(this.params[name]).trim();
    return SAFE_TIME_RE.test(s) ? s : quote(s);
  }
  // Identifier (field / event name): validated, never quoted.
  id(name) {
    if (this.has(name)) return ident(this.params[name], name);
    this.miss(name);
    return `$${name}$`;
  }
  miss(name) {
    if (!this.missing.includes(name)) this.missing.push(name);
  }
}

function indexTerm(params) {
  if (isBound(params.index)) {
    const s = String(params.index).trim();
    return { term: `index=${SAFE_INDEX_RE.test(s) ? s : quote(s)}`, comment: null };
  }
  return { term: `index=${INDEX_MACRO}`, note: INDEX_NOTE };
}

function sourcetypeTerm(st) {
  return `sourcetype=${SAFE_SOURCETYPE_RE.test(st) ? st : quote(st)}`;
}

// ---------------------------------------------------------------------------
// Pivot table

const REQUIRED = Object.freeze({
  edge: ['value'],
  trace: ['field', 'value', 'earliest'],
  process_events: ['aid', 'tpid', 'earliest', 'latest'],
  process_table: ['aid', 'earliest', 'latest'],
  pid_lookup: ['aid', 'pid', 'earliest', 'latest'],
  tpid_to_pid: ['aid', 'tpid'],
  host_lookup: ['hostname'],
  event_sample: ['event', 'earliest'],
  decode: ['field'],
});

export const PIVOT_KINDS = Object.freeze(Object.keys(REQUIRED));

// Which kinds have a macro form, and which macro. `null` → always inline.
const MACRO_FOR = Object.freeze({
  trace: 'cs_trace_process',
  process_table: 'cs_process_table',
  pid_lookup: 'cs_pid_lookup',
  process_events: 'cs_process_events',
});

function defaultSourcetype(kind, pivot, params) {
  if (isBound(params.sourcetype)) return String(params.sourcetype).trim();
  if (pivot.sourcetype) return String(pivot.sourcetype);
  if (kind === 'edge') return edgeDstSourcetype(pivot.edge);
  if (kind === 'host_lookup') return SOURCETYPES.aidmaster;
  if (kind === 'event_sample' && /^Event_/.test(String(params.event || ''))) return SOURCETYPES.external;
  return SOURCETYPES.sensor;
}

function edgeDstSourcetype(edge) {
  if (edge.dst_sourcetype) return edge.dst_sourcetype;
  const table = String(edge.dst || '').split('.')[0];
  if (edge.dst && edge.dst.includes('.') && SOURCETYPES[table]) return SOURCETYPES[table];
  return edge.src_sourcetype || SOURCETYPES.sensor;
}

// Invariant 1 gate. Placeholders do not satisfy it.
function assertPidScope(b, why) {
  if (!(b.has('aid') && b.has('earliest') && b.has('latest'))) {
    throw new SplError(
      'unscoped_pid',
      `${why}: a RawProcessId predicate needs aid, earliest and latest bound (placeholders are not enough). ` +
        `Unbound: ${['aid', 'earliest', 'latest'].filter((p) => !b.has(p)).join(', ')}.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Search-line builder

// time: 'required' (earliest+latest, placeholders if unbound) | 'earliest' (earliest required,
// latest if bound) | 'optional' (each only if bound). Every bound is on _time (invariant 3).
function searchLine(b, params, sourcetype, { time = 'required', extra = [] } = {}) {
  const idx = indexTerm(params);
  const head = [`search ${idx.term}`, sourcetypeTerm(sourcetype)];
  const wantEarliest = time === 'required' || time === 'earliest' || b.has('earliest');
  const wantLatest = time === 'required' || b.has('latest');
  let timed = false;
  if (wantEarliest) { head.push(`earliest=${b.time('earliest')}`); timed = true; }
  if (wantLatest) { head.push(`latest=${b.time('latest')}`); timed = true; }
  const lines = [head.join(' ')];
  for (const e of extra) if (e) lines.push('  ' + e);
  return { lines, indexNote: idx.note, timed };
}

// ---------------------------------------------------------------------------
// Shapes (inline). Each returns { body: string[], hazards, timed, indexComment }.

function shapeTrace(b, params, sourcetype, fieldOverride, aidTerm) {
  const field = fieldOverride ? ident(fieldOverride, 'field') : b.id('field');
  const value = b.val('value');
  if (aidTerm === undefined) aidTerm = b.has('aid') ? `aid=${b.val('aid')}` : null;
  const s = searchLine(b, params, sourcetype, {
    time: 'earliest',
    extra: [
      aidTerm,
      `( ${field}=${value}`,
      '  OR event_simpleName=ProcessRollup2',
      '  OR event_simpleName=SyntheticProcessRollup2 )',
    ],
  });
  const body = [
    ...s.lines,
    '| eval _pid = coalesce(ContextProcessId, TargetProcessId)',
    '| where isnotnull(_pid)',
    `| eval _hit = if(${field}=${value}, 1, 0),`,
    '       _anchor = if(event_simpleName IN ("ProcessRollup2","SyntheticProcessRollup2"), 1, 0)',
    '| stats max(_hit) as matched, max(_anchor) as has_anchor,',
    '        min(_time) as first_seen, max(_time) as last_seen,',
    '        values(eval(if(_hit=1, event_simpleName, null()))) as observed_on,',
    '        values(eval(if(_anchor=1, ImageFileName, null()))) as image,',
    '        values(eval(if(_anchor=1, CommandLine, null()))) as command_line,',
    '        values(eval(if(_anchor=1, RawProcessId, null()))) as os_pid,',
    '        values(eval(if(_anchor=1, ParentProcessId, null()))) as parent_pid',
    '        by aid, _pid',
    '| where matched=1',
    '| rename _pid as TargetProcessId',
    '| eval resolved = if(has_anchor=1, "yes", "no - creation event outside time range")',
    '| table aid TargetProcessId os_pid image command_line parent_pid observed_on first_seen last_seen resolved',
    '| convert ctime(first_seen) ctime(last_seen)',
    '| sort - last_seen',
  ];
  // This shape attributes the observable to a process via
  // coalesce(ContextProcessId, TargetProcessId) -- the same asserted
  // relationship process_events leans on. Brief SS4: an asserted join is
  // labelled everywhere it appears, including here.
  const hazards = aidTerm ? [CONTEXT_ATTRIBUTION_NOTE] : [CONTEXT_ATTRIBUTION_NOTE, TRACE_HOST_NOTE];
  return { body, hazards, timed: s.timed, indexNote: s.indexNote };
}

function shapeProcessTable(b, params, sourcetype, aidValue) {
  const s = searchLine(b, params, sourcetype, {
    time: 'required',
    extra: [`aid=${aidValue || b.val('aid')}`, ANCHOR_FILTER],
  });
  const body = [
    ...s.lines,
    '| stats min(_time) as start_seen, values(RawProcessId) as os_pid,',
    '        values(ImageFileName) as image, values(CommandLine) as command_line,',
    '        values(ParentProcessId) as parent_tpid,',
    '        values(ProcessStartTime) as process_start_time,',
    '        values(UserSid) as user_sid, values(SHA256HashData) as sha256',
    '        by aid, TargetProcessId',
    '| convert ctime(start_seen)',
    '| sort start_seen',
  ];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapePidLookup(b, params, sourcetype, pidValue) {
  assertPidScope(b, 'pid_lookup');
  const s = searchLine(b, params, sourcetype, {
    time: 'required',
    extra: [`aid=${b.val('aid')} RawProcessId=${pidValue || b.val('pid')}`, ANCHOR_FILTER],
  });
  const body = [...s.lines, `| table ${PROCESS_COLUMNS}`, '| sort _time'];
  return { body, hazards: [PID_RECYCLING_HAZARD], timed: s.timed, indexNote: s.indexNote };
}

function shapeProcessEvents(b, params, sourcetype) {
  const tpid = b.val('tpid');
  const s = searchLine(b, params, sourcetype, {
    time: 'required',
    extra: [`aid=${b.val('aid')}`, `(ContextProcessId=${tpid} OR TargetProcessId=${tpid})`],
  });
  const body = [
    ...s.lines,
    '| table _time event_simpleName ContextProcessId TargetProcessId',
    '| sort _time',
  ];
  return { body, hazards: [CONTEXT_ATTRIBUTION_NOTE], timed: s.timed, indexNote: s.indexNote };
}

function shapeTpidToPid(b, params, sourcetype) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [`aid=${b.val('aid')} TargetProcessId=${b.val('tpid')}`, ANCHOR_FILTER],
  });
  const body = [
    ...s.lines,
    '| fields _time aid ComputerName TargetProcessId RawProcessId ImageFileName CommandLine ProcessStartTime',
    '| head 1',
  ];
  return { body, hazards: [HANDOFF_CAUTION], timed: s.timed, indexNote: s.indexNote };
}

function shapeAnchorByTpid(b, params, sourcetype, tpidValue, aidTerm) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [aidTerm ? `${aidTerm} TargetProcessId=${tpidValue}` : `TargetProcessId=${tpidValue}`, ANCHOR_FILTER],
  });
  const body = [...s.lines, `| table ${PROCESS_COLUMNS}`, '| sort _time'];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapeHostLookup(b, params, sourcetype, keyTerm) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [keyTerm || `ComputerName=${b.val('hostname')}`],
  });
  const body = [
    ...s.lines,
    '| stats latest(_time) as last_seen, latest(ComputerName) as ComputerName,',
    '        latest(MachineDomain) as MachineDomain, latest(OU) as OU, latest(SiteName) as SiteName,',
    '        latest(event_platform) as platform, latest(Version) as os_version,',
    '        latest(AgentVersion) as AgentVersion, latest(FirstSeen) as FirstSeen',
    '        by aid',
    '| convert ctime(last_seen)',
    '| sort - last_seen',
  ];
  return { body, hazards: keyTerm ? [] : [HOSTNAME_CAUTION], timed: s.timed, indexNote: s.indexNote };
}

function shapeAppinfo(b, params, sourcetype, hashValue) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [`SHA256HashData=${hashValue}`],
  });
  const body = [
    ...s.lines,
    '| stats latest(FileName) as FileName, latest(CompanyName) as CompanyName,',
    '        latest(FileDescription) as FileDescription, latest(ProductName) as ProductName,',
    '        latest(ProductVersion) as ProductVersion, latest(FileVersion) as FileVersion,',
    '        latest(detectioncount) as detection_count',
    '        by SHA256HashData',
  ];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapeUserinfo(b, params, sourcetype, sidValue) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [`UserSid_readable=${sidValue}`],
  });
  const body = [
    ...s.lines,
    '| stats latest(UserName) as UserName, latest(DomainUser) as DomainUser,',
    '        latest(AccountType) as AccountType, latest(LastLoggedOnHost) as LastLoggedOnHost,',
    '        latest(LocalAdminAccess) as LocalAdminAccess, latest(LoggedOnHostCount) as LoggedOnHostCount',
    '        by UserSid_readable',
  ];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapeTree(b, params, sourcetype, treeValue, aidTerm) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [aidTerm ? `${aidTerm} TreeId=${treeValue}` : `TreeId=${treeValue}`],
  });
  const body = [
    ...s.lines,
    '| table _time aid event_simpleName TreeId TargetProcessId ContextProcessId ParentProcessId ImageFileName',
    '| sort _time',
  ];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapeGenericEdge(b, params, sourcetype, dstField, value, aidTerm) {
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [aidTerm ? `${aidTerm} ${dstField}=${value}` : `${dstField}=${value}`],
  });
  const body = [...s.lines, `| table _time aid event_simpleName ${dstField}`, '| sort _time'];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapeEventSample(b, params, sourcetype) {
  // Optional field=value predicate.
  const holding = b.has('field') && b.has('value') ? ` ${b.id('field')}=${b.val('value')}` : '';
  const s = searchLine(b, params, sourcetype, {
    time: 'earliest',
    extra: [
      (b.has('aid') ? `aid=${b.val('aid')} event_simpleName=${b.id('event')}` : `event_simpleName=${b.id('event')}`) + holding,
    ],
  });
  const body = [...s.lines, '| head 20', '| fields - _raw _bkt _cd _indextime _serial _si _subsecond punct'];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

function shapeDecode(b, params, sourcetype, pivot) {
  const field = b.id('field');
  const d = pivot.decode || {};
  const lookup = String(d.lookup || (b.has('field') ? `crowdstrike_${field}.csv` : `crowdstrike_$field$.csv`)).replace(/\.csv$/i, '');
  const meaning = d.meaning_field || `${field}_meaning`;
  if (d.lookup) ident(lookup, 'lookup');
  if (d.meaning_field) ident(meaning, 'meaning_field');
  const s = searchLine(b, params, sourcetype, {
    time: 'optional',
    extra: [`${field}=*`],
  });
  const body = [
    ...s.lines,
    `| lookup ${lookup} ${field} OUTPUT ${meaning}`,
    `| stats count, min(_time) as first_seen, max(_time) as last_seen by ${field} ${meaning}`,
    '| convert ctime(first_seen) ctime(last_seen)',
    '| sort - count',
  ];
  return { body, hazards: [], timed: s.timed, indexNote: s.indexNote };
}

// ---------------------------------------------------------------------------
// Edge dispatch → { shape, macro }  (macro = which macro this resolves to, if any)

function resolveEdge(b, params, pivot, sourcetype) {
  const edge = pivot.edge;
  if (!edge || typeof edge !== 'object') throw new SplError('bad_pivot', 'edge pivot needs pivot.edge');
  const scope = Array.isArray(edge.scope) ? edge.scope : [];
  const value = b.val('value');
  const dst = edge.dst == null ? null : String(edge.dst);
  const dstField = dst && dst.includes('.') ? dst.split('.').slice(1).join('.') : dst;
  const dstTable = dst && dst.includes('.') ? dst.split('.')[0] : null;

  if (scope.includes('time')) assertPidScope(b, `edge ${edge.id || edge.src}`);
  // scope names aid → the aid term is always emitted (placeholder if unbound, recorded in missing).
  const aidTerm = scope.includes('aid') || b.has('aid') ? `aid=${b.val('aid')}` : null;

  // Never emit a RawProcessId predicate outside the gate above.
  if (edge.kind === 'os_pid' || dst === null || dstField === 'RawProcessId' || edge.src === 'RawProcessId') {
    assertPidScope(b, `edge ${edge.id || edge.src}`);
    return { shape: shapePidLookup(b, params, sourcetype, value), macro: 'cs_pid_lookup' };
  }
  if (dstTable === 'aidmaster' || (dstTable && dstField === 'aid')) {
    return { shape: shapeHostLookup(b, params, sourcetype, `aid=${value}`), macro: null };
  }
  if (dstTable === 'appinfo') return { shape: shapeAppinfo(b, params, sourcetype, value), macro: null };
  if (dstTable === 'userinfo') return { shape: shapeUserinfo(b, params, sourcetype, value), macro: null };
  if (dstTable) return { shape: shapeGenericEdge(b, params, sourcetype, ident(dstField, 'dst'), value, aidTerm), macro: null };

  ident(dstField, 'dst');
  if (dstField === 'TargetProcessId') return { shape: shapeAnchorByTpid(b, params, sourcetype, value, aidTerm), macro: null };
  if (dstField === 'TreeId') return { shape: shapeTree(b, params, sourcetype, value, aidTerm), macro: null };
  if (dstField === 'aid') {
    // aid on the sensor sourcetype → the host's process table for the window.
    return { shape: shapeProcessTable(b, params, sourcetype, value), macro: 'cs_process_table' };
  }
  // Any other sensor-side observable: trace it to the process that produced it.
  return { shape: shapeTrace(b, params, sourcetype, dstField, aidTerm), macro: 'cs_trace_process' };
}

// ---------------------------------------------------------------------------
// Macro form. Returns lines or null when the macro cannot express the search.

function macroLines(macro, b, params, pivot) {
  const q = (name, override) => (override !== undefined ? override : b.val(name));
  const t = (name) => (b.has(name) ? quote(String(params[name]).trim()) : `"$${name}$"`);
  const edge = pivot.edge;
  switch (macro) {
    case 'cs_trace_process': {
      const field = edge ? edge.dst : b.id('field');
      if (b.has('aid')) return null; // macro has no aid argument; inline carries it
      return [`\`cs_trace_process("${field}", ${q('value')}, ${t('earliest')})\``];
    }
    case 'cs_process_table':
      return [`\`cs_process_table(${edge ? q('value') : q('aid')}, ${t('earliest')})\``];
    case 'cs_pid_lookup':
      return [`\`cs_pid_lookup(${q('aid')}, ${edge ? q('value') : q('pid')}, ${t('earliest')})\``];
    case 'cs_process_events':
      return [`\`cs_process_events(${q('aid')}, ${q('tpid')}, ${t('earliest')})\``];
    default:
      return null;
  }
}

// The macros take `earliest` only. They can express the search only when `latest`
// is unbound or is "now" (the macro's implicit upper bound). Anything else is a
// different window and must go inline.
function macroCanCarryLatest(b, params) {
  if (!b.has('latest')) return true;
  return String(params.latest).trim().toLowerCase() === 'now';
}

// ---------------------------------------------------------------------------
// generate()

export function generate(pivot, params = {}, opts = {}) {
  if (!pivot || typeof pivot !== 'object' || !pivot.kind) {
    throw new SplError('bad_pivot', 'pivot must be an object with a kind');
  }
  const kind = pivot.kind;
  if (!REQUIRED[kind]) throw new SplError('unknown_kind', `unknown pivot kind: ${kind}`);
  if (kind === 'edge' && (!pivot.edge || typeof pivot.edge !== 'object')) {
    throw new SplError('bad_pivot', 'edge pivot needs pivot.edge');
  }
  const p = params || {};
  const b = new Binder(p);
  const sourcetype = defaultSourcetype(kind, pivot, p);
  const wantMacro = opts && opts.form === 'macro';

  let shape;
  let macro = MACRO_FOR[kind] || null;
  const hazards = [];
  let asserted = false;

  switch (kind) {
    case 'edge': {
      const r = resolveEdge(b, p, pivot, sourcetype);
      shape = r.shape;
      macro = r.macro;
      const edge = pivot.edge;
      asserted = edge.basis === 'asserted';
      if (edge.hazard && edge.hazard.text) hazards.push({ level: edge.hazard.level || 'danger', text: edge.hazard.text });
      // Manual fallback for a lookup the TA already applies at search time.
      if (edge.mechanism === 'search_time_lookup' && (edge.automatic_on || []).length) {
        const yields = (edge.yields || []).slice(0, 4).join(', ') + ((edge.yields || []).length > 4 ? ', …' : '');
        hazards.push({
          level: 'note',
          text: `The TA applies this lookup automatically at search time on ${edge.automatic_on.join(' and ')}: ${yields} are already on those records. Run this only if that LOOKUP stanza is disabled or you are on another sourcetype.`,
        });
      }
      const srcSt = edge.src_sourcetype;
      const dstSt = edge.dst_sourcetype || sourcetype;
      if (srcSt && dstSt && srcSt !== dstSt) {
        hazards.push({
          level: 'note',
          text: `Sourcetype change: ${edge.src} lives on ${srcSt}; this search runs on ${dstSt}. Field names and CIM coverage differ across the boundary.`,
        });
      }
      break;
    }
    // These two resolve a process through ContextProcessId, which is an
    // asserted edge in the join graph. The flag must reflect that so a caller
    // rendering an "asserted" chip off it is not silently told the search is
    // confirmed. The comment in the SPL is emitted by the shape's hazard.
    case 'trace': shape = shapeTrace(b, p, sourcetype); asserted = true; break;
    case 'process_events': shape = shapeProcessEvents(b, p, sourcetype); asserted = true; break;
    case 'process_table': shape = shapeProcessTable(b, p, sourcetype); break;
    case 'pid_lookup': shape = shapePidLookup(b, p, sourcetype); break;
    case 'tpid_to_pid': shape = shapeTpidToPid(b, p, sourcetype); break;
    case 'host_lookup': shape = shapeHostLookup(b, p, sourcetype); break;
    case 'event_sample': shape = shapeEventSample(b, p, sourcetype); break;
    case 'decode': shape = shapeDecode(b, p, sourcetype, pivot); break;
    default: throw new SplError('unknown_kind', `unknown pivot kind: ${kind}`);
  }
  for (const h of shape.hazards) if (!hazards.some((x) => x.text === h.text)) hazards.push(h);

  // Required-but-unbound params for this kind are recorded even if a shape did not touch them.
  for (const name of REQUIRED[kind]) if (!b.has(name)) b.miss(name);

  // Form selection. Anything that would have been a comment is a note the
  // drawer renders beside the code; the copied text is pure SPL.
  let form = 'inline';
  let lines = null;
  const notes = [];
  const note = (text) => notes.push({ level: 'note', text });
  if (wantMacro) {
    if (!macro) {
      note(`No macro for pivot kind ${kind}; inline form shown.`);
    } else if (!macroCanCarryLatest(b, p)) {
      note(`${macro} takes earliest only and cannot carry latest=${String(p.latest).trim()}; inline form shown.`);
    } else {
      lines = macroLines(macro, b, p, pivot);
      if (lines) form = 'macro';
      else note(`${macro} cannot carry every bound parameter; inline form shown.`);
    }
  }
  // `missing` only names params the chosen form renders as $NAME$.
  if (form === 'macro') {
    const text = lines.join('\n');
    const dropped = b.missing.filter((n) => !text.includes(`$${n}$`));
    for (const n of dropped) {
      b.missing.splice(b.missing.indexOf(n), 1);
      note(`${macro} has no ${n} argument${n === 'latest' ? ' (the macro searches up to now)' : ''}; bind it in the inline form.`);
    }
  }

  if (asserted && pivot.edge) {
    hazards.unshift({ level: 'asserted', text: `${(pivot.edge.note || '').trim()} Not corpus-validated.` });
  }
  const out = [];
  if (form === 'macro') {
    if (sourcetype !== SOURCETYPES.sensor) {
      note(`The macro is defined on ${SOURCETYPES.sensor}; this pivot is on ${sourcetype}. Use the inline form if that differs.`);
    }
    if (isBound(p.index)) note('The macro uses cs_index internally; the index parameter applies to the inline form only.');
    notes.push(TIME_NOTE);
    out.push(...lines);
  } else {
    if (shape.indexNote) notes.push(shape.indexNote);
    if (shape.timed) notes.push(TIME_NOTE);
    out.push(...shape.body);
  }
  for (const n of notes) if (!hazards.some((h) => h.text === n.text)) hazards.push(n);

  const text = out.join('\n');
  // Lint at the only exit: forbidden commands fail to generate.
  const verdict = lint(text);
  if (!verdict.ok) {
    const err = new SplError('lint', `generated SPL failed lint: ${verdict.violations.join('; ')}`);
    err.violations = verdict.violations;
    throw err;
  }
  return {
    spl: text,
    hazards,
    asserted,
    missing: b.missing.slice(),
    form,
    kind,
    sourcetype,
  };
}

// ---------------------------------------------------------------------------
// lint(): Splunk-Cloud command allowlist (invariant 4). Comment-aware, quote-aware.

export function stripComments(spl) {
  return String(spl).replace(/```[\s\S]*?```/g, ' ');
}

function splitPipeline(text) {
  const segs = [];
  let cur = '';
  let inQ = false;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQ) {
      cur += ch;
      if (ch === '\\') { cur += text[i + 1] || ''; i++; continue; }
      if (ch === '"') inQ = false;
      continue;
    }
    if (ch === '"') { inQ = true; cur += ch; continue; }
    if (ch === '[') { depth++; segs.push(cur); cur = ''; continue; }
    if (ch === ']') { depth = Math.max(0, depth - 1); segs.push(cur); cur = ''; continue; }
    if (ch === '|') { segs.push(cur); cur = ''; continue; }
    cur += ch;
  }
  segs.push(cur);
  return segs.map((s) => s.trim()).filter(Boolean);
}

export function lint(spl) {
  const violations = [];
  const text = stripComments(spl);
  const segs = splitPipeline(text);
  if (segs.length === 0) return { ok: false, violations: ['empty search'] };
  segs.forEach((seg, i) => {
    const m = /^`([A-Za-z_][A-Za-z0-9_]*)(\(|`)/.exec(seg);
    if (m) {
      if (!KNOWN_MACROS.includes(m[1])) violations.push(`unknown macro: ${m[1]}`);
      return;
    }
    const word = (/^([A-Za-z_][A-Za-z0-9_]*)/.exec(seg) || [])[1] || '';
    const lower = word.toLowerCase();
    if (FORBIDDEN_COMMANDS.includes(lower)) { violations.push(`forbidden command: ${lower}`); return; }
    if (ALLOWED_COMMANDS.includes(lower)) {
      // `search` is fine anywhere; other commands are fine at any segment.
      return;
    }
    if (i === 0 && /^(index|sourcetype|earliest|latest)=/.test(seg)) return; // implicit search
    violations.push(`command not in allowlist: ${word || seg.slice(0, 20)}`);
  });
  return { ok: violations.length === 0, violations };
}
