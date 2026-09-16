// empty — the teach state. A title, one line, and the first moves.
//
//   empty({
//     title: "What are you holding?",
//     line: "A field name, an event, a hash, a host, an OS PID.",
//     moves: [{ key: "/", text: "search anything" }, { key: "2", text: "start from an OS PID", href: "#/w/pid" }],
//   })

import { h } from "./h.js";
import { keycap } from "./keycap.js";

export function empty({ title = "", line = "", moves = [] } = {}) {
  return h(
    "div",
    { class: "r-empty" },
    h("h2", { class: "r-empty__title" }, title),
    line ? h("p", { class: "r-empty__line" }, line) : null,
    moves.length
      ? h(
          "ul",
          { class: "r-empty__moves", "aria-label": "First moves" },
          moves.map((m) =>
            h(
              "li",
              null,
              m.key ? keycap({ key: m.key }) : null,
              m.href ? h("a", { href: m.href }, m.text) : h("span", null, m.text),
            ),
          ),
        )
      : null,
  );
}

export default empty;
