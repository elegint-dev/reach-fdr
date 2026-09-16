// step — one numbered workflow step: input, why, help.
//
//   step({
//     n: 2,
//     title: "Bind the host and the window",
//     required: true,
//     state: "todo" | "current" | "done",
//     input: { name: "aid", label: "aid", value, placeholder, hint, type },   // or an array of inputs
//     why: "…",            // rendered as a `why` callout
//     expect: "…",         // rendered as an `expect` callout
//     help: "…",           // rendered as a `note` callout
//     children: Node | [Node],
//     onInput(name, value, event)
//   })
// Dispatches bubbling `param` {name, value} on input.

import { h, uid } from "./h.js";
import { callout } from "./callout.js";

export function step(props = {}) {
  const { n = 1, title = "", required = false, state = "todo", why, expect, help, children, onInput } = props;
  const inputs = Array.isArray(props.input) ? props.input : props.input ? [props.input] : [];
  const headId = uid("step");

  const el = h(
    "section",
    { class: ["r-step", `r-step--${state}`, required && "r-step--required"], "aria-labelledby": headId, "aria-current": state === "current" ? "step" : null },
    h(
      "header",
      { class: "r-step__head" },
      h("span", { class: "r-step__n", "aria-hidden": "true" }, String(n)),
      h(
        "h3",
        { id: headId, class: "r-step__title" },
        h("span", { class: "r-sr" }, `Step ${n}: `),
        title,
        required ? h("span", { class: "r-step__req" }, "required") : null,
      ),
    ),
    h(
      "div",
      { class: "r-step__body" },
      inputs.length
        ? h(
            "div",
            { class: "r-step__inputs" },
            inputs.map((inp) => {
              const id = uid(`step-${inp.name}`);
              return h(
                "div",
                { class: ["r-field", inp.required && "r-field--required"] },
                h(
                  "label",
                  { class: "r-field__label", for: id },
                  h("code", null, inp.label ?? inp.name),
                  inp.required ? h("span", { class: "r-field__req" }, "required") : null,
                ),
                h("input", {
                  id,
                  class: "r-field__input",
                  type: inp.type || "text",
                  name: inp.name,
                  value: inp.value ?? "",
                  placeholder: inp.placeholder ?? "",
                  autocomplete: "off",
                  spellcheck: "false",
                  "aria-required": inp.required ? "true" : null,
                  onInput: (e) => {
                    if (onInput) onInput(inp.name, e.target.value, e);
                    el.dispatchEvent(new CustomEvent("param", { bubbles: true, detail: { name: inp.name, value: e.target.value } }));
                  },
                }),
                inp.hint ? h("p", { class: "r-field__hint" }, inp.hint) : null,
              );
            }),
          )
        : null,
      why ? callout({ kind: "why", body: why }) : null,
      expect ? callout({ kind: "expect", body: expect }) : null,
      help ? callout({ kind: "note", label: "Help", body: help }) : null,
      children,
    ),
  );
  return el;
}

export default step;
