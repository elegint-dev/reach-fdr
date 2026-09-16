// Contrast invariants for app/styles/tokens.css (ARCHITECTURE §4.1).
//
// Parses the token file with regexes — no CSS parser, no dependencies — and
// checks WCAG 2.x contrast for the pairs the contract names:
//   every --trust-*-fg (and --hazard-fg) on --bg-1, and on its own -bg,
//   in both themes.
// It also checks the two light declarations are identical, that the text
// tokens are readable on the surfaces they sit on, and that the expected
// number of pairs was actually found (an empty match must not pass).
//
// Run: node --test tests/contrast.test.js

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, "..", "app", "styles", "tokens.css"), "utf8");

const TRUST = ["confirmed", "asserted", "suggested", "inferred"];
const MIN = 4.5;

// --- WCAG maths ------------------------------------------------------------

function channel(v) {
  const c = v / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}
function luminance(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) throw new Error(`not a 6-digit hex colour: ${hex}`);
  const n = parseInt(m[1], 16);
  return (
    0.2126 * channel((n >> 16) & 255) +
    0.7152 * channel((n >> 8) & 255) +
    0.0722 * channel(n & 255)
  );
}
export function contrast(a, b) {
  const la = luminance(a);
  const lb = luminance(b);
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

// --- token-file parsing -----------------------------------------------------

// Strip comments, then find `selector { … }` blocks. Blocks nested in @media
// are found by first pulling the @media body out.
const stripped = css.replace(/\/\*[\s\S]*?\*\//g, "");

function blockAfter(source, selectorRe) {
  const m = selectorRe.exec(source);
  if (!m) return null;
  let depth = 0;
  let start = -1;
  for (let i = m.index + m[0].length - 1; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) return source.slice(start, i);
    }
  }
  return null;
}

function tokens(block) {
  const out = {};
  const re = /--([a-z0-9-]+)\s*:\s*([^;]+);/gi;
  let m;
  while ((m = re.exec(block))) out[m[1]] = m[2].trim();
  return out;
}

const darkBlock = blockAfter(stripped, /(^|\n)\s*:root\s*\{/);
const mediaBody = blockAfter(stripped, /@media\s*\(prefers-color-scheme:\s*light\)\s*\{/);
const mediaLightBlock = mediaBody && blockAfter(mediaBody, /:root:not\(\[data-theme="dark"\]\)[^{]*\{/);
const explicitLightBlock = blockAfter(stripped, /(^|\n)\s*:root\[data-theme="light"\][^{]*\{/);

const dark = darkBlock ? tokens(darkBlock) : null;
const light = explicitLightBlock ? tokens(explicitLightBlock) : null;
const lightMedia = mediaLightBlock ? tokens(mediaLightBlock) : null;

// --- the pair list (shared shape with app/gallery.html) --------------------

export function pairsFor(theme) {
  const names = [...TRUST.map((t) => [`trust-${t}`, `trust-${t}-fg`, `trust-${t}-bg`]), ["hazard", "hazard-fg", "hazard-bg"]];
  const pairs = [];
  for (const [label, fg, bg] of names) {
    pairs.push({ label: `${label}-fg on bg-1`, fg: theme[fg], bg: theme["bg-1"] });
    pairs.push({ label: `${label}-fg on ${bg}`, fg: theme[fg], bg: theme[bg] });
  }
  return pairs;
}

// --- tests ------------------------------------------------------------------

test("tokens.css has a dark :root block and both light blocks", () => {
  assert.ok(darkBlock, "no `:root {` block found");
  assert.ok(mediaLightBlock, "no `:root:not([data-theme=\"dark\"])` block inside @media (prefers-color-scheme: light)");
  assert.ok(explicitLightBlock, "no `:root[data-theme=\"light\"]` block found");
});

test("both light declarations are identical", () => {
  assert.deepEqual(lightMedia, light, "the @media light block and the [data-theme=light] block drifted apart");
});

test("every contract token exists in the dark theme", () => {
  const required = [
    "font-sans", "font-mono",
    "fs-1", "fs-2", "fs-3", "fs-4", "fs-5", "fs-6", "lh-body", "lh-tight",
    "sp-1", "sp-2", "sp-3", "sp-4", "sp-5", "sp-6", "sp-7",
    "radius-1", "radius-2",
    "bg-0", "bg-1", "bg-2", "bg-3", "fg-0", "fg-1", "fg-2", "line", "accent",
    ...TRUST.flatMap((t) => [`trust-${t}`, `trust-${t}-fg`, `trust-${t}-bg`]),
    "hazard", "hazard-fg", "hazard-bg",
    "layer-fg", "layer-bg", "focus-ring",
  ];
  for (const name of required) assert.ok(name in dark, `missing --${name} on :root`);
  // Light must redeclare every colour token.
  for (const name of required.filter((n) => /^(bg|fg|line|accent|trust|hazard|layer)/.test(n))) {
    assert.ok(name in light, `missing --${name} in the light theme`);
  }
});

test("scale tokens match the contract values", () => {
  assert.equal(dark["fs-1"], "12px"); assert.equal(dark["fs-2"], "13px"); assert.equal(dark["fs-3"], "14px");
  assert.equal(dark["fs-4"], "16px"); assert.equal(dark["fs-5"], "20px"); assert.equal(dark["fs-6"], "24px");
  assert.equal(dark["lh-body"], "1.45"); assert.equal(dark["lh-tight"], "1.2");
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7].map((i) => dark[`sp-${i}`]), ["4px", "8px", "12px", "16px", "24px", "32px", "48px"]);
  assert.equal(dark["radius-1"], "2px"); assert.equal(dark["radius-2"], "4px");
  assert.match(dark["focus-ring"], /^2px solid var\(--accent\)$/);
});

for (const [themeName, theme] of [["dark", dark], ["light", light]]) {
  test(`${themeName}: trust foregrounds pass ${MIN}:1 on bg-1 and on their own bg`, () => {
    assert.ok(theme, `${themeName} theme not parsed`);
    const pairs = pairsFor(theme);
    assert.equal(pairs.length, 10, "expected 5 trust colours × 2 surfaces");
    const failures = [];
    for (const p of pairs) {
      assert.ok(p.fg && p.bg, `${p.label}: token missing`);
      const r = contrast(p.fg, p.bg);
      if (r < MIN) failures.push(`${p.label}: ${p.fg} on ${p.bg} = ${r.toFixed(2)}`);
    }
    assert.deepEqual(failures, [], `contrast below ${MIN}:\n  ${failures.join("\n  ")}`);
  });

  test(`${themeName}: text and accent tokens are readable on their surfaces`, () => {
    const checks = [
      ["fg-0", "bg-0"], ["fg-0", "bg-1"], ["fg-0", "bg-2"], ["fg-0", "bg-3"],
      ["fg-1", "bg-0"], ["fg-1", "bg-1"], ["fg-1", "bg-2"],
      ["fg-2", "bg-0"], ["fg-2", "bg-1"],
      ["accent", "bg-0"], ["accent", "bg-1"],
      ["layer-fg", "layer-bg"], ["layer-fg", "bg-1"],
      ["accent", "accent-bg"],
    ];
    const failures = [];
    for (const [fg, bg] of checks) {
      const r = contrast(theme[fg], theme[bg]);
      if (r < MIN) failures.push(`--${fg} on --${bg} = ${r.toFixed(2)}`);
    }
    assert.deepEqual(failures, [], `contrast below ${MIN}:\n  ${failures.join("\n  ")}`);
  });
}

test("trust tints stay close to bg-1 so the chip does not read as a surface change", () => {
  for (const theme of [dark, light]) {
    for (const t of [...TRUST.map((t) => `trust-${t}-bg`), "hazard-bg"]) {
      const r = contrast(theme[t], theme["bg-1"]);
      assert.ok(r < 1.6, `--${t} ${theme[t]} is ${r.toFixed(2)} from bg-1; tints should be subtle`);
    }
  }
});
