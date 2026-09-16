// Bundle loader and lookups. Contract: docs/ARCHITECTURE.md §2.
//
//   await load()                  → the whole bundle (idempotent)
//   field(name) / event(name)     → FieldRecord / EventRecord | null
//   edge(id) / edgesFor(name)     → Edge | null / Edge[]  (src or dst is `name`)
//   manifest() / translations()   → the manifest / curated translations
//   decode(name)                  → { lookup, meaning_field, values } | null
//   searchIndex()                 → { fields: [...names], events: [...names] }
//   coFields(field, event)        → [{ role, fields: [...names] }]  (field itself excluded)
//
// schema_version is checked first; a mismatch or load failure renders a visible panel.

import { h } from "../components/h.js";

export const SCHEMA_VERSION = 1;

const BUNDLE_FILES = ["fields", "events", "edges", "decodes", "translations"];

let bundle = null;

function fileUrl(name) {
  return new URL(`../data/${name}.json`, import.meta.url).href;
}

async function getJson(name) {
  const res = await fetch(fileUrl(name));
  if (!res.ok) throw new Error(`app/data/${name}.json — HTTP ${res.status} ${res.statusText}`);
  return res.json();
}

export class BundleError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = "BundleError";
    this.code = code;
    this.detail = detail || "";
  }
}

// fetch() is blocked on file://.
export function isFileProtocol() {
  return typeof location !== "undefined" && location.protocol === "file:";
}

function looksLikeFileOrNoServer(cause) {
  const m = String((cause && cause.message) || cause || "");
  return isFileProtocol() || /failed to fetch|networkerror|load failed|not allowed|cors/i.test(m);
}

// The load-failure panel. Rendered into `target` (default: the page).
export function renderLoadError(err, target) {
  const mount =
    target ||
    (typeof document !== "undefined" ? document.getElementById("boot-error") || document.body : null);
  if (!mount) return null;
  const serve = err && err.code === "needs_server";
  const panel = h(
    "div",
    { class: "r-bootfail", role: "alert" },
    h("h1", null, serve ? "Reach has to be served, not opened" : "Reach cannot read its data"),
    h("p", null, (err && err.message) || "The data bundle failed to load."),
    err && err.detail ? h("p", { class: "r-secondary" }, err.detail) : null,
    h("p", { class: "r-secondary" }, serve ? "From the repository root:" : "Rebuild the bundle from the repository root and reload:"),
    h(
      "pre",
      { class: "r-bootfail__cmd", tabindex: "0" },
      h(
        "code",
        null,
        serve
          ? "python3 -m http.server 8000\n\nthen open  http://localhost:8000/"
          : "python3 tools/build_knowledge_base.py",
      ),
    ),
    h(
      "p",
      { class: "r-secondary" },
      serve
        ? "Reach is plain static files with no build step and no network calls — a local file server is the only thing it needs."
        : h(
            "span",
            null,
            "Check that ",
            h("code", null, "python3 -m http.server"),
            " is running from the repository root, not from inside ",
            h("code", null, "app/"),
            ".",
          ),
    ),
  );
  mount.hidden = false;
  mount.replaceChildren(panel);
  return panel;
}

export async function load() {
  if (bundle) return bundle;

  if (isFileProtocol()) {
    const err = new BundleError(
      "needs_server",
      "This page was opened straight from disk (file://), and browsers block a page on file:// from reading its own data files.",
      "Browsers block fetch() on file://, so the data bundle cannot be loaded without a server.",
    );
    renderLoadError(err);
    throw err;
  }

  // All requests start at once; the manifest is awaited first for the schema check.
  const pending = {};
  for (const name of ["manifest", ...BUNDLE_FILES]) {
    const p = getJson(name);
    p.catch(() => {}); // a rejection handled later must not be "unhandled" now
    pending[name] = p;
  }

  let manifest;
  try {
    manifest = await pending.manifest;
  } catch (cause) {
    const err = looksLikeFileOrNoServer(cause)
      ? new BundleError(
          "needs_server",
          "Reach could not fetch app/data/manifest.json. That almost always means the page is not being served by a web server.",
          String((cause && cause.message) || cause),
        )
      : new BundleError("manifest_unreadable", "app/data/manifest.json could not be loaded.", String((cause && cause.message) || cause));
    renderLoadError(err);
    throw err;
  }

  if (manifest.schema_version !== SCHEMA_VERSION) {
    const err = new BundleError(
      "schema_mismatch",
      `This build of Reach reads bundle schema version ${SCHEMA_VERSION}; app/data/manifest.json says version ${String(manifest.schema_version)}.`,
      "Nothing is rendered against a bundle the interface does not understand — the numbers and the joins would be wrong in ways you could not see.",
    );
    renderLoadError(err);
    throw err;
  }

  let parts;
  try {
    parts = await Promise.all(BUNDLE_FILES.map((n) => pending[n]));
  } catch (cause) {
    const err = new BundleError("bundle_unreadable", "Part of the data bundle could not be loaded.", String(cause && cause.message ? cause.message : cause));
    renderLoadError(err);
    throw err;
  }

  const [fields, events, edges, decodes, translationsDoc] = parts;

  const edgeById = new Map();
  const edgesBySrc = new Map();
  const edgesByDst = new Map();
  for (const e of edges) {
    edgeById.set(e.id, e);
    if (!edgesBySrc.has(e.src)) edgesBySrc.set(e.src, []);
    edgesBySrc.get(e.src).push(e);
    if (e.dst) {
      if (!edgesByDst.has(e.dst)) edgesByDst.set(e.dst, []);
      edgesByDst.get(e.dst).push(e);
    }
  }

  bundle = {
    manifest,
    fields,
    events,
    edges,
    decodes,
    translations: translationsDoc,
    edgeById,
    edgesBySrc,
    edgesByDst,
    index: Object.freeze({
      fields: Object.keys(fields).sort(),
      events: Object.keys(events).sort(),
    }),
  };
  return bundle;
}

function must() {
  if (!bundle) throw new BundleError("not_loaded", "data.load() has not finished yet.");
  return bundle;
}

export function loaded() {
  return bundle !== null;
}

export function manifest() {
  return must().manifest;
}

export function counts() {
  return must().manifest.counts;
}

export function translations() {
  return must().translations;
}

export function field(name) {
  if (!name) return null;
  return must().fields[name] || null;
}

export function event(name) {
  if (!name) return null;
  return must().events[name] || null;
}

export function edge(id) {
  if (!id) return null;
  return must().edgeById.get(id) || null;
}

export function edges() {
  return must().edges;
}

// Every edge this name takes part in, as source or as target.
export function edgesFor(name) {
  if (!name) return [];
  const b = must();
  const out = [];
  for (const e of b.edgesBySrc.get(name) || []) out.push(e);
  for (const e of b.edgesByDst.get(name) || []) if (!out.includes(e)) out.push(e);
  return out;
}

export function decode(name) {
  if (!name) return null;
  return must().decodes[name] || null;
}

export function searchIndex() {
  return must().index;
}

// Other fields on `eventName`, grouped by role, alphabetical.
export function coFields(fieldName, eventName) {
  const rec = event(eventName);
  if (!rec) return [];
  const byRole = rec.fields_by_role || {};
  const out = [];
  for (const role of Object.keys(byRole).sort()) {
    const names = (byRole[role] || []).filter((n) => n !== fieldName);
    if (names.length) out.push({ role, fields: names.slice().sort() });
  }
  return out;
}

// Convenience for the value surface: every field the build typed with this role.
export function fieldsWithRole(role) {
  const b = must();
  const out = [];
  for (const name of b.index.fields) {
    const rec = b.fields[name];
    if (rec && rec.role === role) out.push(name);
  }
  return out;
}

export default {
  load,
  loaded,
  manifest,
  counts,
  translations,
  field,
  event,
  edge,
  edges,
  edgesFor,
  decode,
  searchIndex,
  coFields,
  fieldsWithRole,
  renderLoadError,
  SCHEMA_VERSION,
};
