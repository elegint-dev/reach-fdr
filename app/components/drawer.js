// drawer — the paste. SPL block + param inputs + hazards + copy + inline/macro tabs.
//
//   drawer({
//     state: "empty" | "filled" | "copied" | "error",
//     title: "the process that caused this event",
//     subtitle: "ContextProcessId → TargetProcessId on DnsRequest",
//     spl: { inline: "…", macro: "…" },     // or a string (inline only)
//     form: "inline" | "macro",
//     params: [{ name: "aid", label: "aid", value: "", placeholder: "…", required: true, hint: "…" }],
//     missing: ["aid", "earliest"],         // names that render as $NAME$ in the SPL
//     hazards: [{ level: "danger" | "caution" | "note", text: "…" }],
//     error: { code: "unscoped_pid", text: "…" },   // state "error": no SPL is offered
//     emptyText: "…",
//     onParam(name, value, event), onCopy(text, form), onTab(form)
//   })
//
// Element API: el.setSpl({inline, macro}), el.setState(state), el.setParams(params),
// el.setHazards(list), el.showTab(form), el.copy().
// Events (bubbling): `param` {name, value}, `copy` {text, form}, `tab` {form}.
//
// `$NAME$` placeholders are marked.

import { h, uid, replace } from "./h.js";
import { callout } from "./callout.js";

const LEVEL_TO_KIND = { danger: "hazard", hazard: "hazard", caution: "caution", warning: "caution", note: "note", info: "note", asserted: "asserted" };

function renderSplLines(text) {
  const out = [];
  const lines = String(text ?? "").split("\n");
  lines.forEach((line, i) => {
    const span = h("span", { class: "r-spl__line" });
    const re = /\$([A-Za-z_][A-Za-z0-9_]*)\$/g;
    let last = 0;
    let m;
    while ((m = re.exec(line))) {
      if (m.index > last) span.appendChild(document.createTextNode(line.slice(last, m.index)));
      span.appendChild(h("mark", { class: "r-spl__param", dataset: { param: m[1] } }, m[0]));
      last = m.index + m[0].length;
    }
    if (last < line.length) span.appendChild(document.createTextNode(line.slice(last)));
    out.push(span);
    if (i < lines.length - 1) out.push(document.createTextNode("\n"));
  });
  return out;
}

export function drawer(props = {}) {
  const {
    state: initialState = "empty",
    title = "",
    subtitle = "",
    form: initialForm = "inline",
    params = [],
    hazards = [],
    error = null,
    emptyText = "Select a row in the ledger and the SPL for it appears here, ready to paste.",
    onParam,
    onCopy,
    onTab,
  } = props;

  let spl = typeof props.spl === "string" ? { inline: props.spl, macro: "" } : { inline: "", macro: "", ...(props.spl || {}) };
  let form = initialForm;
  let state = initialState;
  let copiedTimer = null;

  const ids = { inline: uid("tab-inline"), macro: uid("tab-macro"), panelInline: uid("panel-inline"), panelMacro: uid("panel-macro") };

  const titleEl = h("h2", { class: "r-drawer__title" }, title);
  const subEl = h("p", { class: "r-drawer__sub" }, subtitle);
  const status = h("p", { class: "r-drawer__status", role: "status", "aria-live": "polite" });

  const tabs = h(
    "div",
    { class: "r-tabs", role: "tablist", "aria-label": "SPL form" },
    tab("inline", "Inline", "expanded, runs anywhere"),
    tab("macro", "Macro", "calls queries/macros"),
  );

  function tab(key, label, hint) {
    return h(
      "button",
      {
        type: "button",
        id: ids[key],
        class: "r-tabs__tab",
        role: "tab",
        "aria-selected": form === key ? "true" : "false",
        "aria-controls": key === "inline" ? ids.panelInline : ids.panelMacro,
        tabindex: form === key ? "0" : "-1",
        title: hint,
        onClick: () => showTab(key),
        onKeydown: (e) => {
          if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
            e.preventDefault();
            showTab(key === "inline" ? "macro" : "inline", true);
          }
        },
      },
      label,
    );
  }

  const code = h("code", { class: "r-spl__code" });
  const pre = h("pre", { class: "r-spl", tabindex: "0", "aria-label": "SPL", title: "Copy to clipboard: press c or use the button" }, code);
  const hoverCopy = h(
    "button",
    { type: "button", class: "r-spl__copy", title: "Copy to clipboard", "aria-label": "Copy SPL to clipboard", onClick: () => copy() },
    "Copy",
  );
  const codeWrap = h("div", { class: "r-spl-wrap" }, pre, hoverCopy);
  const panel = h("div", { class: "r-drawer__panel", role: "tabpanel", id: ids.panelInline, "aria-labelledby": ids.inline }, codeWrap);

  const paramsForm = h("form", { class: "r-drawer__params", onSubmit: (e) => e.preventDefault() });
  const hazardList = h("ul", { class: "r-drawer__hazards", "aria-label": "Hazards" });

  const copyBtn = h(
    "button",
    { type: "button", class: "r-drawer__copy", onClick: () => copy() },
    h("span", { class: "r-drawer__copylabel" }, "Copy SPL"),
    h("kbd", { "aria-hidden": "true" }, "c"),
  );

  // "Run in Splunk": deep link from a base URL kept in localStorage (guarded; storage may be absent).
  const RUN_KEY = "reach.splunkBase";
  const readBase = () => { try { return localStorage.getItem(RUN_KEY) || ""; } catch { return ""; } };
  const writeBase = (v) => { try { if (v) localStorage.setItem(RUN_KEY, v); else localStorage.removeItem(RUN_KEY); } catch { /* storage unavailable */ } };
  const runLink = h("a", { class: "r-drawer__run", target: "_blank", rel: "noopener noreferrer", hidden: true }, "Run in Splunk ", h("span", { "aria-hidden": "true" }, "↗"));
  const baseInput = h("input", { class: "r-field__input r-drawer__base", type: "url", placeholder: "https://splunk.example:8000", autocomplete: "off", spellcheck: "false", "aria-label": "Splunk base URL" });
  const baseDetails = h(
    "details",
    { class: "r-drawer__runcfg" },
    h("summary", null, "Splunk URL"),
    h("p", { class: "r-muted" }, "Base URL of your Splunk web UI. Kept in this browser only; nothing is sent anywhere."),
    baseInput,
  );
  function renderRun() {
    const base = readBase().replace(/\/+$/, "");
    const text = spl[form] || spl.inline || "";
    const usable = base && text && state === "filled";
    runLink.hidden = !usable;
    if (usable) {
      // Splunk's search app takes the query in `q`; a raw search needs a leading "search ".
      const q = /^\s*(search|\|)/.test(text.replace(/```[^`]*```\s*/g, "")) ? text : `search ${text}`;
      runLink.href = `${base}/app/search/search?q=${encodeURIComponent(q)}`;
    }
    if (baseInput.value !== readBase()) baseInput.value = readBase();
  }
  baseInput.addEventListener("change", () => { writeBase(baseInput.value.trim()); renderRun(); });

  const errorSlot = h("div", { class: "r-drawer__error" });
  const emptySlot = h("div", { class: "r-drawer__empty" }, h("p", null, emptyText));

  const el = h(
    "aside",
    { class: "r-drawer", "aria-label": "Paste" },
    h("header", { class: "r-drawer__head" }, h("p", { class: "r-drawer__kicker" }, "Paste"), titleEl, subEl),
    emptySlot,
    errorSlot,
    h("div", { class: "r-drawer__body" }, tabs, panel, paramsForm, hazardList, h("div", { class: "r-drawer__actions" }, copyBtn, runLink, status), baseDetails),
  );

  function currentText() {
    return form === "macro" ? spl.macro || "" : spl.inline || "";
  }

  function renderSpl() {
    replace(code, renderSplLines(currentText()));
    panel.id = form === "macro" ? ids.panelMacro : ids.panelInline;
    panel.setAttribute("aria-labelledby", ids[form]);
  }

  function showTab(key, focus = false) {
    form = key === "macro" ? "macro" : "inline";
    renderRun();
    for (const t of tabs.children) {
      const on = t.id === ids[form];
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      if (on && focus) t.focus();
    }
    renderSpl();
    if (onTab) onTab(form);
    el.dispatchEvent(new CustomEvent("tab", { bubbles: true, detail: { form } }));
  }

  function setParams(list) {
    replace(
      paramsForm,
      (list || []).map((p) => {
        const id = uid(`param-${p.name}`);
        return h(
          "div",
          { class: ["r-field", p.required && "r-field--required"] },
          h(
            "label",
            { class: "r-field__label", for: id },
            h("code", null, p.label ?? p.name),
            p.required ? h("span", { class: "r-field__req" }, "required") : null,
          ),
          h("input", {
            id,
            class: "r-field__input",
            type: p.type || "text",
            name: p.name,
            value: p.value ?? "",
            placeholder: p.placeholder ?? "",
            autocomplete: "off",
            spellcheck: "false",
            "aria-required": p.required ? "true" : null,
            onInput: (e) => {
              if (onParam) onParam(p.name, e.target.value, e);
              el.dispatchEvent(new CustomEvent("param", { bubbles: true, detail: { name: p.name, value: e.target.value } }));
            },
          }),
          p.hint ? h("p", { class: "r-field__hint" }, p.hint) : null,
        );
      }),
    );
    paramsForm.hidden = !(list && list.length);
  }

  function setHazards(list) {
    replace(hazardList, (list || []).map((hz) => h("li", null, callout({ kind: LEVEL_TO_KIND[hz.level] || "note", label: hz.label, body: hz.text }))));
    hazardList.hidden = !(list && list.length);
  }

  function setState(next, detail = {}) {
    state = next;
    el.classList.remove("r-drawer--empty", "r-drawer--filled", "r-drawer--copied", "r-drawer--error");
    el.classList.add(`r-drawer--${state}`);
    renderRun();
    const body = el.querySelector(".r-drawer__body");
    emptySlot.hidden = state !== "empty";
    errorSlot.hidden = state !== "error";
    body.hidden = state === "empty" || state === "error";
    if (state === "error") {
      const err = detail.error || error || { text: "This pivot cannot be emitted safely." };
      replace(
        errorSlot,
        callout({
          kind: "hazard",
          label: err.code === "unscoped_pid" ? "Not emitted: unscoped PID" : "Not emitted",
          body: err.text,
        }),
      );
    }
    if (state === "copied") {
      copyBtn.querySelector(".r-drawer__copylabel").textContent = "Copied";
      status.textContent = `Copied ${form} SPL to the clipboard.`;
    } else {
      copyBtn.querySelector(".r-drawer__copylabel").textContent = "Copy SPL";
      status.textContent = "";
    }
  }

  async function copy() {
    if (state === "empty" || state === "error") return;
    const text = currentText();
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard unavailable (insecure context); the SPL is still selectable */
    }
    if (onCopy) onCopy(text, form);
    el.dispatchEvent(new CustomEvent("copy", { bubbles: true, detail: { text, form } }));
    setState("copied");
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      if (state === "copied") setState("filled");
    }, 1800);
  }

  function setSpl(next) {
    spl = typeof next === "string" ? { inline: next, macro: "" } : { inline: "", macro: "", ...(next || {}) };
    renderSpl();
    renderRun();
  }

  setParams(params);
  setHazards(hazards);
  renderSpl();
  setState(state, { error });

  el.setSpl = setSpl;
  el.setState = setState;
  el.setParams = setParams;
  el.setHazards = setHazards;
  el.showTab = showTab;
  el.copy = copy;
  el.setTitle = (t, s) => {
    titleEl.textContent = t ?? "";
    subEl.textContent = s ?? "";
  };
  el.pre = pre;
  return el;
}

export default drawer;
