// Keyboard map. Contract: docs/ARCHITECTURE.md §4.3.
// Keys never fire while an input / textarea / select / contenteditable is focused, except Esc.
// Modifier chords (Ctrl / Meta / Alt) are never intercepted, so Cmd+C stays the browser's.
//
// install({ handlers, target }) → uninstall()
// handlers: { [action]: (event) => void|boolean }  — return false to let the event through.

export const KEYMAP = Object.freeze([
  { key: '/', action: 'focusSearch', label: 'focus search' },
  { key: 'Esc', action: 'escape', label: 'back to search / close' },
  { key: '↑', action: 'up', label: 'move up in the focused list' },
  { key: '↓', action: 'down', label: 'move down in the focused list' },
  { key: 'Enter', action: 'select', label: 'select / open' },
  { key: 'c', action: 'copy', label: 'copy SPL' },
  { key: 'e', action: 'cycleEvent', label: 'cycle event scope' },
  { key: '1', action: 'card1', label: 'start: host' },
  { key: '2', action: 'card2', label: 'start: OS PID' },
  { key: '3', action: 'card3', label: 'start: detection' },
  { key: '4', action: 'card4', label: 'start: IOC' },
  { key: '[', action: 'back', label: 'history back' },
  { key: ']', action: 'forward', label: 'history forward' },
  { key: '?', action: 'help', label: 'key map' },
  { key: 't', action: 'theme', label: 'toggle theme' },
]);

// KeyboardEvent.key → action
const KEY_TO_ACTION = new Map([
  ['/', 'focusSearch'],
  ['Escape', 'escape'],
  ['Esc', 'escape'],
  ['ArrowUp', 'up'],
  ['ArrowDown', 'down'],
  ['Enter', 'select'],
  ['c', 'copy'],
  ['e', 'cycleEvent'],
  ['1', 'card1'],
  ['2', 'card2'],
  ['3', 'card3'],
  ['4', 'card4'],
  ['[', 'back'],
  [']', 'forward'],
  ['?', 'help'],
  ['t', 'theme'],
]);

export function actionFor(key) {
  return KEY_TO_ACTION.get(key) || null;
}

const EDITABLE_TAGS = new Set(['INPUT', 'TEXTAREA', 'SELECT']);

export function isEditable(el) {
  if (!el) return false;
  const tag = String(el.tagName || '').toUpperCase();
  if (EDITABLE_TAGS.has(tag)) return true;
  if (el.isContentEditable === true) return true;
  const ce = el.getAttribute ? el.getAttribute('contenteditable') : el.contentEditable;
  return ce === '' || ce === 'true' || ce === 'plaintext-only';
}

// Pure dispatch: returns the action fired, or null. Used by install() and by tests.
export function handleKeydown(event, handlers) {
  if (!event || event.defaultPrevented) return null;
  if (event.ctrlKey || event.metaKey || event.altKey) return null;
  const action = actionFor(event.key);
  if (!action) return null;
  if (action !== 'escape' && isEditable(event.target)) return null;
  const fn = handlers && handlers[action];
  if (typeof fn !== 'function') return null;
  const r = fn(event);
  if (r !== false && typeof event.preventDefault === 'function') event.preventDefault();
  return action;
}

export function install({ handlers = {}, target } = {}) {
  const t = target || (typeof globalThis !== 'undefined' && globalThis.document ? globalThis.document : null);
  if (!t || typeof t.addEventListener !== 'function') return () => {};
  const listener = (ev) => handleKeydown(ev, handlers);
  t.addEventListener('keydown', listener);
  return () => t.removeEventListener('keydown', listener);
}
