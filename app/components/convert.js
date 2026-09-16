// convert — the two "do the math for me" widgets the field page offers.
//
//   decodeWidget({ field, decode })     paste a raw value → the TA's meaning
//   epochWidget({ field })              paste ms-since-epoch → UTC and local time
//
// In-browser only; no network.

import { h } from "./h.js";

let seq = 0;
const uid = (p) => `${p}-${++seq}`;

export function decodeWidget({ field, decode }) {
  const id = uid("decode");
  const values = (decode && decode.values) || {};
  const out = h("output", { class: "r-convert__out", for: id, "aria-live": "polite" });
  const input = h("input", {
    id,
    class: "r-field__input r-convert__in",
    type: "text",
    inputmode: "numeric",
    placeholder: "raw value, e.g. " + (Object.keys(values)[0] ?? "0"),
    autocomplete: "off",
    spellcheck: "false",
  });
  const render = () => {
    const v = input.value.trim();
    out.replaceChildren();
    if (!v) return;
    const key = Object.prototype.hasOwnProperty.call(values, v) ? v : (String(Number(v)) in values ? String(Number(v)) : null);
    if (key !== null) {
      out.append(h("code", null, key), " → ", h("strong", null, values[key]), h("span", { class: "r-muted" }, ` (${decode.meaning_field})`));
    } else {
      out.append(h("span", { class: "r-convert__miss" }, `not in the TA's ${decode.lookup} — `),
        h("span", { class: "r-muted" }, `${Object.keys(values).length} known values`));
    }
  };
  input.addEventListener("input", render);
  return h(
    "div",
    { class: "r-convert" },
    h("label", { class: "r-field__label", for: id }, h("code", null, field), h("span", { class: "r-muted" }, " → meaning")),
    input,
    out,
  );
}

const pad = (n, w = 2) => String(n).padStart(w, "0");
function fmtUTC(d) {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)} UTC`;
}
function fmtLocal(d) {
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const tz = `${sign}${pad(Math.floor(Math.abs(off) / 60))}:${pad(Math.abs(off) % 60)}`;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)} ${tz}`;
}

export function epochWidget({ field }) {
  const id = uid("epoch");
  const out = h("output", { class: "r-convert__out", for: id, "aria-live": "polite" });
  const input = h("input", {
    id,
    class: "r-field__input r-convert__in",
    type: "text",
    inputmode: "numeric",
    placeholder: "ms since epoch, e.g. 1726500000000",
    autocomplete: "off",
    spellcheck: "false",
  });
  const render = () => {
    const raw = input.value.trim();
    out.replaceChildren();
    if (!raw) return;
    if (!/^\d+(\.\d+)?$/.test(raw)) {
      out.append(h("span", { class: "r-convert__miss" }, "digits only — FDR timestamps are numeric"));
      return;
    }
    const n = Number(raw);
    // FDR carries ms; a 10-digit value is read as seconds, and the output says so.
    const isSeconds = n < 1e11;
    const d = new Date(isSeconds ? n * 1000 : n);
    if (Number.isNaN(d.getTime())) {
      out.append(h("span", { class: "r-convert__miss" }, "out of range"));
      return;
    }
    out.append(
      h("div", null, h("code", null, fmtUTC(d))),
      h("div", null, h("code", null, fmtLocal(d)), h("span", { class: "r-muted" }, " (this browser's zone)")),
      h("div", { class: "r-muted" }, isSeconds ? "read as seconds (10 digits); FDR fields are normally milliseconds" : "read as milliseconds"),
    );
  };
  input.addEventListener("input", render);
  return h(
    "div",
    { class: "r-convert" },
    h("label", { class: "r-field__label", for: id }, h("code", null, field), h("span", { class: "r-muted" }, " → human time")),
    input,
    out,
    h("p", { class: "r-muted r-convert__note" }, "timestamp and ContextTimeStamp are sensor-side; _time is when Splunk indexed the event."),
  );
}
