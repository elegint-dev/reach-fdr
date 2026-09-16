// app/lib/spl.js is the only module that produces SPL (ARCHITECTURE §3).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../app/', import.meta.url).pathname;
const SPL_SHAPES = [
  /\bsearch index=/, /\|\s*stats\b/, /\|\s*eval\b/, /\|\s*table\b/, /\|\s*where\b/,
  /\|\s*join\b/, /\|\s*map\b/, /\|\s*lookup\b/, /sourcetype=crowdstrike:/,
];

function files(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
    d.isDirectory() ? files(join(dir, d.name)) : d.name.endsWith('.js') ? [join(dir, d.name)] : []);
}

test('no SPL literal exists outside app/lib/spl.js', () => {
  const offenders = [];
  for (const f of [...files(join(ROOT, 'views')), ...files(join(ROOT, 'components')), join(ROOT, 'app.js')]) {
    const src = readFileSync(f, 'utf8');
    for (const re of SPL_SHAPES) {
      if (re.test(src)) offenders.push(`${f.replace(ROOT, 'app/')} matches ${re}`);
    }
  }
  assert.deepEqual(offenders, [], 'views and components must call spl.generate(), never build SPL');
});
