import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parse, build, start, navigate, ROUTES, parseQuery, buildQuery } from '../app/lib/router.js';
import { install, handleKeydown, isEditable, KEYMAP, actionFor } from '../app/lib/keys.js';

describe('router.parse', () => {
  test('start', () => {
    for (const h of ['', '#', '#/', '/', '#!/']) assert.deepEqual(parse(h), { route: 'start', params: {} }, JSON.stringify(h));
  });

  test('every route in ARCHITECTURE §1', () => {
    assert.deepEqual(parse('#/f/ResponsiblePid'), { route: 'field', params: { name: 'ResponsiblePid' } });
    assert.deepEqual(parse('#/e/DnsRequest'), { route: 'event', params: { name: 'DnsRequest' } });
    assert.deepEqual(parse('#/w/pid?aid=abc&pid=4820&earliest=-1h&latest=now'), {
      route: 'workflow', params: { id: 'pid', aid: 'abc', pid: '4820', earliest: '-1h', latest: 'now' },
    });
    assert.deepEqual(parse('#/v/10.1.2.3'), { route: 'value', params: { value: '10.1.2.3' } });
    assert.deepEqual(parse('#/search?q=Responsible'), { route: 'search', params: { q: 'Responsible' } });
    assert.deepEqual(parse('#/unknown/ResponsibleProcessId'), { route: 'unknown', params: { name: 'ResponsibleProcessId' } });
    assert.deepEqual(ROUTES.map((r) => r.route), ['start', 'field', 'event', 'workflow', 'value', 'search', 'unknown']);
  });

  test('field page query params (on, sel) are decoded', () => {
    const r = parse('#/f/ResponsiblePid?on=LoginItemAdded&sel=e_context_to_target');
    assert.deepEqual(r, { route: 'field', params: { name: 'ResponsiblePid', on: 'LoginItemAdded', sel: 'e_context_to_target' } });
  });

  test('query values are percent-decoded, keys too; bare keys are empty strings', () => {
    assert.deepEqual(parseQuery('q=a%20b%26c&flag&x%3Dy=1'), { q: 'a b&c', flag: '', 'x=y': '1' });
    assert.deepEqual(parseQuery(''), {});
    assert.deepEqual(parse('#/search?q=%E2%9C%93').params, { q: '✓' });
  });

  test('unknown paths are notfound, never a throw', () => {
    assert.equal(parse('#/nope').route, 'notfound');
    assert.equal(parse('#/f').route, 'notfound');
    assert.equal(parse('#/f/a/b').route, 'notfound');
    assert.equal(parse('#/search/extra').route, 'notfound');
    assert.equal(parse('#/f/%E0%A4%A').route, 'field'); // malformed escape survives
  });
});

describe('router.build ↔ parse round-trips', () => {
  const cases = [
    ['start', {}],
    ['field', { name: 'ResponsiblePid' }],
    ['field', { name: 'threat.tactic.id', on: 'Event_DetectionSummaryEvent', sel: 'row/with/slash' }],
    ['event', { name: 'DnsRequest' }],
    ['workflow', { id: 'pid', aid: 'abc', pid: '4820', earliest: '-1h@h', latest: 'now' }],
    ['workflow', { id: 'ioc', field: 'CommandLine', value: 'C:\\Windows\\x.exe /c "a&b=c#d?e"' }],
    ['value', { value: 'C:\\Windows\\System32\\cmd.exe' }],
    ['value', { value: 'evil.example.com/path?x=1' }],
    ['value', { value: '2001:db8::1' }],
    ['search', { q: 'Responsible ProcessId' }],
    ['unknown', { name: 'ResponsibleProcessId' }],
  ];
  for (const [route, params] of cases) {
    test(`${route} ${JSON.stringify(params)}`, () => {
      const hash = build(route, params);
      assert.match(hash, /^#\//);
      assert.ok(!/[ "<>]/.test(hash), 'no raw unsafe chars');
      assert.deepEqual(parse(hash), { route, params });
    });
  }

  test('dots and slashes in path values are encoded', () => {
    assert.equal(build('field', { name: 'threat.tactic.id' }), '#/f/threat.tactic.id');
    assert.equal(build('value', { value: 'a/b' }), '#/v/a%2Fb');
    assert.equal(parse('#/v/a%2Fb').params.value, 'a/b');
  });

  test('empty / null query params are dropped; the path param is required', () => {
    assert.equal(build('field', { name: 'x', on: '', sel: null, z: undefined }), '#/f/x');
    assert.equal(buildQuery({}), '');
    assert.throws(() => build('field', {}), /needs name/);
    assert.throws(() => build('nope', {}), /unknown route/);
  });

  test('build of a route with no path param carries only the query', () => {
    assert.equal(build('search', { q: 'a b' }), '#/search?q=a%20b');
    assert.equal(build('start', {}), '#/');
  });
});

describe('router.start', () => {
  function fakeWindow(hash) {
    const listeners = {};
    return {
      location: { hash },
      addEventListener(t, fn) { (listeners[t] ||= []).push(fn); },
      removeEventListener(t, fn) { listeners[t] = (listeners[t] || []).filter((f) => f !== fn); },
      fire(t) { for (const fn of listeners[t] || []) fn(); },
      count(t) { return (listeners[t] || []).length; },
    };
  }

  test('fires immediately with the current state, then on every hashchange; stop() unlistens', () => {
    const w = fakeWindow('#/f/aid');
    const seen = [];
    const stop = start((s) => seen.push(s), w);
    assert.deepEqual(seen, [{ route: 'field', params: { name: 'aid' } }]);
    w.location.hash = '#/e/DnsRequest';
    w.fire('hashchange');
    assert.equal(seen.length, 2);
    assert.deepEqual(seen[1], { route: 'event', params: { name: 'DnsRequest' } });
    stop();
    assert.equal(w.count('hashchange'), 0);
    w.fire('hashchange');
    assert.equal(seen.length, 2);
  });

  test('start with no window still calls back with start', () => {
    const seen = [];
    start((s) => seen.push(s), null);
    assert.deepEqual(seen, [{ route: 'start', params: {} }]);
  });

  test('navigate returns the hash it would set', () => {
    assert.equal(navigate('field', { name: 'aid' }), '#/f/aid');
  });
});

describe('keys', () => {
  const ev = (key, extra = {}) => {
    const e = { key, prevented: false, preventDefault() { this.prevented = true; }, target: null, ...extra };
    return e;
  };
  const spy = () => { const calls = []; const fn = (e) => { calls.push(e); }; fn.calls = calls; return fn; };

  test('KEYMAP covers ARCHITECTURE §4.3 with labels', () => {
    const keys = KEYMAP.map((k) => k.key);
    for (const k of ['/', 'Esc', '↑', '↓', 'Enter', 'c', 'e', '1', '2', '3', '4', '[', ']', '?', 't']) assert.ok(keys.includes(k), k);
    for (const k of KEYMAP) { assert.equal(typeof k.label, 'string'); assert.ok(k.label.length > 0); assert.ok(k.action); }
    assert.equal(actionFor('ArrowUp'), 'up');
    assert.equal(actionFor('Escape'), 'escape');
    assert.equal(actionFor('x'), null);
  });

  test('handlers fire and preventDefault by default; returning false lets the event through', () => {
    const h = { focusSearch: spy(), copy: () => false };
    const e = ev('/');
    assert.equal(handleKeydown(e, h), 'focusSearch');
    assert.equal(h.focusSearch.calls.length, 1);
    assert.equal(e.prevented, true);
    const c = ev('c');
    assert.equal(handleKeydown(c, h), 'copy');
    assert.equal(c.prevented, false);
    assert.equal(handleKeydown(ev('z'), h), null);
    assert.equal(handleKeydown(ev('e'), h), null); // no handler bound
  });

  test('keys do not fire in inputs / textareas / contenteditable, except Esc', () => {
    const h = { focusSearch: spy(), escape: spy(), copy: spy(), card1: spy() };
    for (const target of [
      { tagName: 'INPUT' }, { tagName: 'textarea' }, { tagName: 'SELECT' },
      { tagName: 'DIV', isContentEditable: true },
      { tagName: 'DIV', getAttribute: (n) => (n === 'contenteditable' ? '' : null) },
    ]) {
      assert.ok(isEditable(target));
      assert.equal(handleKeydown(ev('/', { target }), h), null);
      assert.equal(handleKeydown(ev('c', { target }), h), null);
      assert.equal(handleKeydown(ev('1', { target }), h), null);
      assert.equal(handleKeydown(ev('Escape', { target }), h), 'escape');
    }
    assert.equal(h.focusSearch.calls.length, 0);
    assert.equal(h.escape.calls.length, 5);
    assert.ok(!isEditable({ tagName: 'DIV', getAttribute: () => null }));
    assert.ok(!isEditable(null));
    assert.equal(handleKeydown(ev('/', { target: { tagName: 'TR' } }), h), 'focusSearch');
  });

  test('modifier chords are never intercepted (Cmd+C stays the browser copy)', () => {
    const h = { copy: spy(), focusSearch: spy() };
    for (const mod of ['ctrlKey', 'metaKey', 'altKey']) {
      const e = ev('c', { [mod]: true });
      assert.equal(handleKeydown(e, h), null);
      assert.equal(e.prevented, false);
    }
    assert.equal(h.copy.calls.length, 0);
    assert.equal(handleKeydown(ev('/', { shiftKey: true }), h), 'focusSearch');
  });

  test('install binds keydown on the target and returns an uninstaller', () => {
    const listeners = {};
    const target = {
      addEventListener(t, fn) { (listeners[t] ||= []).push(fn); },
      removeEventListener(t, fn) { listeners[t] = listeners[t].filter((f) => f !== fn); },
    };
    const h = { help: spy() };
    const off = install({ handlers: h, target });
    assert.equal(listeners.keydown.length, 1);
    listeners.keydown[0](ev('?'));
    assert.equal(h.help.calls.length, 1);
    off();
    assert.equal(listeners.keydown.length, 0);
    assert.equal(typeof install({ handlers: h, target: null }), 'function');
  });
});
