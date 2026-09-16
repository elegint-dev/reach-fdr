// omnibox — the front door. An <input role="combobox"> with a
// <ul role="listbox"> of results.
//
//   omnibox({
//     value: "Context",
//     placeholder: "hold anything: field, event, CIM name, hash, IP, PID",
//     state: "idle" | "focused" | "open" | "classified",
//     results: [{ id, kind: "field"|"event"|"cim"|"workflow"|"value", name, hint }],
//     activeIndex: 0,                       // roving highlight (the spine moves it)
//     classified: { kind: "sha256", label: "SHA256 hash" },
//     onInput(value, event), onSelect(result, event), onClear()
//   })
//
// The element exposes:
//   el.input        the <input>
//   el.list         the <ul role="listbox">
//   el.setResults(results, activeIndex)
//   el.setActive(index)
//   el.setClassified(classified | null)
//   el.open(bool)
// and dispatches bubbling `select` (detail: result) and `clear` events.
// Arrow keys are handled in app.js; the omnibox handles Enter and Esc.

import { h, uid, replace } from "./h.js";

export function omnibox(props = {}) {
  const {
    value = "",
    placeholder = "hold anything: field, event, CIM name, hash, IP, PID",
    state = "idle",
    results = [],
    activeIndex = -1,
    classified = null,
    onInput,
    onSelect,
    onClear,
    label = "Search",
  } = props;

  const listId = uid("omni-list");
  const inputId = uid("omni-input");
  let current = [];
  let active = -1;

  const input = h("input", {
    id: inputId,
    class: "r-omnibox__input",
    type: "text",
    role: "combobox",
    "aria-label": label,
    "aria-autocomplete": "list",
    "aria-expanded": "false",
    "aria-controls": listId,
    "aria-haspopup": "listbox",
    autocomplete: "off",
    autocapitalize: "off",
    spellcheck: "false",
    placeholder,
    value,
  });

  const list = h("ul", { id: listId, class: "r-omnibox__list", role: "listbox", "aria-label": "Results" });
  const kindSlot = h("span", { class: "r-omnibox__kind" });
  const hint = h("span", { class: "r-omnibox__hint", "aria-hidden": "true" }, h("kbd", null, "/"));

  const el = h(
    "div",
    { class: ["r-omnibox", state !== "idle" && `r-omnibox--${state}`] },
    h("div", { class: "r-omnibox__field" }, hint, input, kindSlot),
    list,
  );

  function optionId(i) {
    return `${listId}-opt-${i}`;
  }

  function open(isOpen) {
    el.classList.toggle("r-omnibox--open", isOpen);
    input.setAttribute("aria-expanded", isOpen ? "true" : "false");
    if (!isOpen) {
      input.removeAttribute("aria-activedescendant");
    }
  }

  function setActive(i) {
    active = i;
    for (const li of list.children) li.setAttribute("aria-selected", "false");
    const li = list.children[i];
    if (li) {
      li.setAttribute("aria-selected", "true");
      input.setAttribute("aria-activedescendant", li.id);
      if (typeof li.scrollIntoView === "function") li.scrollIntoView({ block: "nearest" });
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }

  function select(result, event) {
    if (!result) return;
    if (onSelect) onSelect(result, event);
    el.dispatchEvent(new CustomEvent("select", { bubbles: true, detail: result }));
  }

  function setResults(next, activeIdx = -1) {
    current = Array.isArray(next) ? next : [];
    replace(
      list,
      current.map((r, i) =>
        h(
          "li",
          {
            id: optionId(i),
            class: "r-omnibox__option",
            role: "option",
            "aria-selected": "false",
            dataset: { index: i, resultId: r.id ?? "" },
            onMousedown: (e) => e.preventDefault(), // keep focus in the input
            onClick: (e) => select(r, e),
          },
          h("span", { class: "r-omnibox__optkind" }, r.kind ?? ""),
          h("span", { class: "r-omnibox__optname" }, r.name ?? ""),
          r.hint ? h("span", { class: "r-omnibox__opthint" }, r.hint) : null,
        ),
      ),
    );
    open(current.length > 0);
    setActive(current.length ? activeIdx : -1);
  }

  function setClassified(c) {
    replace(kindSlot, c ? h("span", { class: "r-omnibox__classified" }, c.label ?? c.kind) : null);
    el.classList.toggle("r-omnibox--classified", Boolean(c));
    if (c) input.setAttribute("aria-description", `looks like: ${c.label ?? c.kind}`);
    else input.removeAttribute("aria-description");
  }

  input.addEventListener("input", (e) => {
    if (onInput) onInput(input.value, e);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && active >= 0 && current[active]) {
      e.preventDefault();
      select(current[active], e);
    } else if (e.key === "Escape") {
      e.preventDefault();
      input.value = "";
      setResults([]);
      setClassified(null);
      if (onClear) onClear(e);
      el.dispatchEvent(new CustomEvent("clear", { bubbles: true }));
    }
  });

  setResults(results, activeIndex);
  setClassified(classified);
  if (state === "open" && results.length) open(true);

  el.input = input;
  el.list = list;
  el.setResults = setResults;
  el.setActive = setActive;
  el.setClassified = setClassified;
  el.open = open;
  el.focus = () => input.focus();
  return el;
}

export default omnibox;
