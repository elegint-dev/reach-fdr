// Hash router. Routes: docs/ARCHITECTURE.md §1/§4.4. All view state lives in the URL.
//
// parse(hash)          → { route, params }
// build(route, params) → '#/…'  (round-trips through parse)
// start(onChange)      → stop()  — listens to hashchange and fires immediately
// navigate(route, params)

export const ROUTES = Object.freeze([
  { route: 'start', pattern: '/', param: null },
  { route: 'field', pattern: '/f', param: 'name' },
  { route: 'event', pattern: '/e', param: 'name' },
  { route: 'workflow', pattern: '/w', param: 'id' },
  { route: 'value', pattern: '/v', param: 'value' },
  { route: 'search', pattern: '/search', param: null },
  { route: 'unknown', pattern: '/unknown', param: 'name' },
]);

const BY_ROUTE = new Map(ROUTES.map((r) => [r.route, r]));

function decode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const pair of qs.split('&')) {
    if (!pair) continue;
    const i = pair.indexOf('=');
    const k = decode(i < 0 ? pair : pair.slice(0, i));
    const v = i < 0 ? '' : decode(pair.slice(i + 1));
    if (k) out[k] = v;
  }
  return out;
}

export function buildQuery(params) {
  const parts = [];
  for (const k of Object.keys(params || {})) {
    const v = params[k];
    if (v === undefined || v === null || v === '') continue;
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return parts.length ? `?${parts.join('&')}` : '';
}

// Accepts "#/f/X?on=Y", "/f/X?on=Y", "#", "" (→ start).
export function parse(hash) {
  let h = String(hash == null ? '' : hash);
  if (h.startsWith('#')) h = h.slice(1);
  if (h.startsWith('!')) h = h.slice(1);
  if (!h.startsWith('/')) h = '/' + h;
  const qi = h.indexOf('?');
  const path = qi < 0 ? h : h.slice(0, qi);
  const query = qi < 0 ? {} : parseQuery(h.slice(qi + 1));

  const segs = path.split('/').filter(Boolean); // '' → [], '/f/X' → ['f','X']
  if (segs.length === 0) return { route: 'start', params: { ...query } };

  const head = '/' + segs[0];
  const def = ROUTES.find((r) => r.pattern === head);
  if (!def) return { route: 'notfound', params: { path, ...query } };

  const params = { ...query };
  if (def.param) {
    if (segs.length < 2) return { route: 'notfound', params: { path, ...query } };
    // Any further slashes are part of the value only if encoded; a raw extra segment is a miss.
    if (segs.length > 2) return { route: 'notfound', params: { path, ...query } };
    params[def.param] = decode(segs[1]);
  } else if (segs.length > 1) {
    return { route: 'notfound', params: { path, ...query } };
  }
  return { route: def.route, params };
}

export function build(route, params = {}) {
  const def = BY_ROUTE.get(route);
  if (!def) throw new Error(`unknown route: ${route}`);
  const rest = { ...params };
  let path = def.pattern;
  if (def.param) {
    const v = rest[def.param];
    if (v === undefined || v === null || v === '') throw new Error(`route ${route} needs ${def.param}`);
    path += '/' + encodeURIComponent(String(v));
    delete rest[def.param];
  }
  return `#${path}${buildQuery(rest)}`;
}

function win() {
  return typeof globalThis !== 'undefined' && globalThis.window ? globalThis.window : null;
}

export function current() {
  const w = win();
  return parse(w ? w.location.hash : '');
}

export function navigate(route, params) {
  const w = win();
  const hash = build(route, params);
  if (w) w.location.hash = hash;
  return hash;
}

export function replace(route, params) {
  const w = win();
  const hash = build(route, params);
  if (w && w.history && w.history.replaceState) {
    w.history.replaceState(null, '', hash);
    w.dispatchEvent(new w.Event('hashchange'));
  } else if (w) {
    w.location.hash = hash;
  }
  return hash;
}

// Calls onChange(state) now and on every hashchange. Returns a stop function.
export function start(onChange, target = win()) {
  const fire = () => onChange(parse(target && target.location ? target.location.hash : ''));
  if (target && target.addEventListener) target.addEventListener('hashchange', fire);
  fire();
  return () => {
    if (target && target.removeEventListener) target.removeEventListener('hashchange', fire);
  };
}
