// App shell: loads the bundle, mounts the omnibox and drawer once, installs
// the keyboard map, renders one view per route. Views fill the drawer via ctx.drawer.

import * as data from "./lib/data.js";
import * as router from "./lib/router.js";
import * as keys from "./lib/keys.js";
import * as search from "./lib/search.js";

import { h, replace } from "./components/h.js";
import { omnibox } from "./components/omnibox.js";
import { drawer } from "./components/drawer.js";
import { keycap } from "./components/keycap.js";

import * as startView from "./views/start.js";
import * as fieldView from "./views/field.js";
import * as eventView from "./views/event.js";
import * as workflowView from "./views/workflow.js";
import * as valueView from "./views/value.js";
import * as searchView from "./views/search.js";
import * as unknownView from "./views/unknown.js";

const VIEWS = {
  start: startView,
  field: fieldView,
  event: eventView,
  workflow: workflowView,
  value: valueView,
  search: searchView,
  unknown: unknownView,
};

// Start cards, keys 1–4.
export const CARDS = Object.freeze([
  { key: "1", id: "host", title: "A host", line: "A hostname or an aid, and you want to know what ran on it.", href: "#/w/host" },
  { key: "2", id: "pid", title: "An OS PID", line: "A PID from a ticket, a dump, ps or Task Manager.", href: "#/w/pid" },
  { key: "3", id: "detection", title: "A detection", line: "A detection summary event — a different sourcetype, renamed handles.", href: "#/w/detection" },
  { key: "4", id: "ioc", title: "An IOC", line: "A hash, an IP, a domain, a filename.", href: "#/w/ioc" },
]);

const bar = document.getElementById("bar");
const main = document.getElementById("main");
const side = document.getElementById("side");

let omni = null;
let paste = null;
let currentView = null;
let drawerParamHandler = null;
let drawerCopyHandler = null;
let omniActive = -1;
let omniResults = [];
let keymapEl = null;

// ---------------------------------------------------------------------------
// URL helpers

// Write state into the URL without re-rendering (`?sel=`, workflow params).
function setUrl(route, params) {
  const hash = router.build(route, params);
  if (window.history && window.history.replaceState) window.history.replaceState(null, "", hash);
  else window.location.hash = hash;
  return hash;
}

function navigate(route, params) {
  router.navigate(route, params);
}

function href(route, params) {
  return router.build(route, params);
}

// ---------------------------------------------------------------------------
// Theme

function currentTheme() {
  const set = document.documentElement.getAttribute("data-theme");
  if (set) return set;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("reach.theme", next);
  } catch {
    /* private mode / storage blocked: the theme still applies for this session */
  }
}

// ---------------------------------------------------------------------------
// Key map overlay, built from keys.KEYMAP

function toggleKeymap(force) {
  const show = force === undefined ? !keymapEl : force;
  if (!show) {
    if (keymapEl) keymapEl.remove();
    keymapEl = null;
    return;
  }
  if (keymapEl) return;
  keymapEl = h(
    "div",
    {
      class: "r-keymap",
      role: "dialog",
      "aria-modal": "false",
      "aria-label": "Keyboard map",
      onClick: (e) => {
        if (e.target === keymapEl) toggleKeymap(false);
      },
    },
    h(
      "div",
      { class: "r-keymap__panel" },
      h("h2", null, "Keys"),
      h(
        "ul",
        { class: "r-keymap__list" },
        keys.KEYMAP.map((k) => h("li", null, keycap({ key: k.key }), h("span", { class: "r-keymap__label" }, k.label))),
      ),
      h(
        "p",
        { class: "r-muted" },
        "Keys never fire while you are typing in a field, except ",
        h("kbd", null, "Esc"),
        ". Everything you see is in the URL, so browser back and forward work.",
      ),
      h("button", { type: "button", class: "r-keymap__close", onClick: () => toggleKeymap(false) }, "Close"),
    ),
  );
  document.body.appendChild(keymapEl);
  const btn = keymapEl.querySelector(".r-keymap__close");
  if (btn) btn.focus();
}

// ---------------------------------------------------------------------------
// Omnibox

function optionsFor(query) {
  const q = String(query || "").trim();
  if (!q) return { results: [], classified: null };
  const idx = data.searchIndex();
  const c = search.classify(q, idx);
  const results = [];
  let classified = null;

  if (c.kind !== "name" && c.kind !== "empty") {
    classified = { kind: c.kind, label: c.candidates.map((x) => x.label).join("  or  ") };
    results.push({
      id: `v:${q}`,
      kind: "value",
      name: q,
      hint: c.ambiguous ? `ambiguous: ${c.candidates.map((x) => x.label).join(" or ")}` : c.candidates[0] && c.candidates[0].label,
    });
  }

  const names = c.kind === "name" ? c.candidates : search.matchNames(q, idx);
  for (const m of names.slice(0, 12)) {
    const rec = m.kind === "field" ? data.field(m.name) : data.event(m.name);
    const hint =
      m.kind === "field"
        ? `${layerShort(rec && rec.layer)} · ${(rec && rec.role) || "unclassified"} · ${(rec && rec.event_count) || 0} events`
        : `event · ${(rec && rec.field_count) || 0} fields · ${rec && rec.cim && rec.cim.normalized ? "CIM" : "no CIM path"}`;
    results.push({ id: `${m.kind === "field" ? "f" : "e"}:${m.name}`, kind: m.kind, name: m.name, hint: `${hint}${m.match === "exact" ? "" : ` · ${m.match} match`}` });
  }

  if (names.length > 12) results.push({ id: `s:${q}`, kind: "search", name: `see all ${names.length} matches`, hint: "results list" });
  if (!names.some((m) => m.match === "exact")) results.push({ id: `u:${q}`, kind: "not found", name: q, hint: "not an exact catalogue name — see what is near it" });

  return { results, classified };
}

function layerShort(layer) {
  return layer === "cim" ? "L3 CIM" : layer === "ta_derived" ? "L2 TA" : "L1 raw";
}

function goToResult(result) {
  if (!result) return;
  const id = String(result.id || "");
  const sep = id.indexOf(":");
  const kind = id.slice(0, sep);
  const name = id.slice(sep + 1);
  if (kind === "f") navigate("field", { name });
  else if (kind === "e") navigate("event", { name });
  else if (kind === "v") navigate("value", { value: name });
  else if (kind === "s") navigate("search", { q: name });
  else navigate("unknown", { name });
}

function omniSubmit() {
  const q = omni.input.value.trim();
  if (!q) return;
  const idx = data.searchIndex();
  const c = search.classify(q, idx);
  if (c.kind === "name" && c.candidates.length && c.candidates[0].match === "exact") {
    goToResult({ id: `${c.candidates[0].kind === "field" ? "f" : "e"}:${c.candidates[0].name}` });
    return;
  }
  if (c.kind !== "name" && c.kind !== "empty") {
    navigate("value", { value: q });
    return;
  }
  navigate("unknown", { name: q });
}

function buildChrome() {
  omni = omnibox({
    onInput: (value) => {
      const { results, classified } = optionsFor(value);
      omniResults = results;
      omniActive = results.length ? 0 : -1;
      omni.setResults(results, omniActive);
      omni.setClassified(classified);
    },
    onSelect: (result) => {
      omni.setResults([]);
      omniResults = [];
      goToResult(result);
    },
    onClear: () => {
      omniResults = [];
      omniActive = -1;
    },
  });
  omni.input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.defaultPrevented) {
      e.preventDefault();
      omniSubmit();
    }
  });

  paste = drawer({
    state: "empty",
    emptyText: "Select a row in the ledger and the SPL for it appears here, with its parameters and its hazards, ready to paste.",
    onParam: (name, value) => {
      if (drawerParamHandler) drawerParamHandler(name, value);
    },
    onCopy: (text, form) => {
      if (drawerCopyHandler) drawerCopyHandler(text, form);
    },
  });

  replace(
    bar,
    omni,
    h(
      "div",
      { class: "r-keys" },
      keycap({ key: "/", hint: "search" }),
      keycap({ key: "↑↓", hint: "rows" }),
      keycap({ key: "Enter", hint: "select" }),
      keycap({ key: "c", hint: "copy" }),
      keycap({ key: "?", hint: "keys" }),
    ),
  );
  replace(side, paste);
}

// ---------------------------------------------------------------------------
// Row focus movement (↑ ↓)

function focusableRows() {
  return Array.from(main.querySelectorAll('tr[data-row-id][tabindex="0"], .r-rowlink'));
}

function moveRows(delta) {
  if (document.activeElement === omni.input && omniResults.length) {
    omniActive = Math.max(0, Math.min(omniResults.length - 1, omniActive + delta));
    omni.setActive(omniActive);
    return;
  }
  const rows = focusableRows();
  if (!rows.length) return;
  const at = rows.indexOf(document.activeElement);
  const next = at < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, at + delta));
  rows[next].focus();
}

// ---------------------------------------------------------------------------
// Routing

function resetDrawer() {
  drawerParamHandler = null;
  drawerCopyHandler = null;
  paste.setTitle("", "");
  paste.setParams([]);
  paste.setHazards([]);
  paste.setSpl({ inline: "", macro: "" });
  paste.setState("empty");
}

function ctxFor(state) {
  return {
    data,
    search,
    route: state.route,
    params: state.params,
    drawer: paste,
    cards: CARDS,
    navigate,
    href,
    setUrl,
    focusSearch: () => omni && omni.focus(),
    setDrawerParamHandler: (fn) => {
      drawerParamHandler = fn;
    },
    setDrawerCopyHandler: (fn) => {
      drawerCopyHandler = fn;
    },
  };
}

function renderRoute(state) {
  const ctx = ctxFor(state);
  resetDrawer();
  let node;
  try {
    const view = VIEWS[state.route];
    node = view ? view.render(ctx) : notFound(state, ctx);
  } catch (err) {
    console.error(err);
    node = h(
      "div",
      { class: "r-section" },
      h("h1", null, "That page did not render"),
      h("p", null, String((err && err.message) || err)),
      h("p", null, h("a", { href: "#/" }, "Back to the start")),
    );
  }
  currentView = node;
  replace(main, node);
  document.title = titleFor(state);
  main.scrollTop = 0;
  window.scrollTo(0, 0);
  if (node && typeof node.afterMount === "function") node.afterMount();
}

function titleFor(state) {
  const p = state.params || {};
  switch (state.route) {
    case "field": return `${p.name} — Reach`;
    case "event": return `${p.name} — event — Reach`;
    case "workflow": return `${p.id} — workflow — Reach`;
    case "value": return `${p.value} — value — Reach`;
    case "search": return `${p.q || ""} — search — Reach`;
    case "unknown": return `${p.name} — not in the catalogue — Reach`;
    default: return "Reach";
  }
}

function notFound(state, ctx) {
  return h(
    "div",
    { class: "r-section" },
    h("h1", null, "No such page"),
    h("p", null, "No page at ", h("code", null, String((state.params && state.params.path) || "that address")), "."),
    h("p", null, h("a", { href: "#/" }, "Start over"), " — or press ", h("kbd", null, "/"), " and type what you are holding."),
  );
}

// ---------------------------------------------------------------------------
// Boot

async function main_() {
  try {
    await data.load();
  } catch {
    // data.js has rendered the failure panel.
    document.getElementById("page").hidden = true;
    return;
  }

  buildChrome();

  keys.install({
    handlers: {
      focusSearch: () => omni.focus(),
      escape: () => {
        if (keymapEl) {
          toggleKeymap(false);
          return;
        }
        if (document.activeElement === omni.input) return false; // the omnibox clears itself
        omni.focus();
      },
      up: () => moveRows(-1),
      down: () => moveRows(1),
      select: () => {
        const el = document.activeElement;
        if (el && el.closest && el.closest("tr[data-row-id]")) return false; // the ledger row handles it
        if (el && el.tagName === "A") return false;
        return false;
      },
      copy: () => paste.copy(),
      cycleEvent: () => {
        if (currentView && typeof currentView.cycleEvent === "function") currentView.cycleEvent();
        else return false;
      },
      card1: () => navigate("workflow", { id: CARDS[0].id }),
      card2: () => navigate("workflow", { id: CARDS[1].id }),
      card3: () => navigate("workflow", { id: CARDS[2].id }),
      card4: () => navigate("workflow", { id: CARDS[3].id }),
      back: () => window.history.back(),
      forward: () => window.history.forward(),
      help: () => toggleKeymap(),
      theme: () => toggleTheme(),
    },
  });

  router.start(renderRoute);
}

main_();
