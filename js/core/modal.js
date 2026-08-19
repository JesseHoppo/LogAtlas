// Every overlay in the app goes on one stack, whether it is one of the static
// overlays in index.html or a div built on the fly. Escape closes the top one
// only, so a picker opened over a preview no longer takes the preview with it.

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]',
].join(',');

// Nothing that destroys data gets focus handed to it by an opening modal.
const DESTRUCTIVE_LABEL = /\b(delete|remove|discard|erase|revoke|clear all)\b/i;

const stack = [];
let titleSeq = 0;

function isRendered(el) {
  return el.getClientRects().length > 0;
}

// A named radio group is one tab stop, and it is the checked radio the user
// lands on — the trap has to agree with that or Tab walks straight out of a
// dialog whose checked radio is not the first one in the group.
function radioStops(items) {
  const stops = new Map();
  for (const el of items) {
    if (el.type !== 'radio' || !el.name) continue;
    const held = stops.get(el.name);
    if (!held || (el.checked && !held.checked)) stops.set(el.name, el);
  }
  return stops;
}

function focusableWithin(overlay) {
  const items = [...overlay.querySelectorAll(FOCUSABLE_SELECTOR)]
    .filter((el) => !el.hasAttribute('disabled') && el.tabIndex !== -1 && isRendered(el));
  const stops = radioStops(items);
  if (stops.size === 0) return items;
  return items.filter((el) => el.type !== 'radio' || !el.name || stops.get(el.name) === el);
}

function isDestructive(el) {
  const label = `${el.getAttribute('class') || ''} ${el.textContent || ''}`;
  return DESTRUCTIVE_LABEL.test(label);
}

function preferredFocus(overlay, initialFocus) {
  if (initialFocus) {
    const el = typeof initialFocus === 'string' ? overlay.querySelector(initialFocus) : initialFocus;
    if (el && isRendered(el)) return el;
  }
  return focusableWithin(overlay).find((el) => !isDestructive(el)) || null;
}

function nextTitleId() {
  let id;
  do {
    id = `modal-title-${++titleSeq}`;
  } while (document.getElementById(id));
  return id;
}

// What an overlay is called in the markup, so a name given for one open does
// not linger over the next one.
const markupNames = new WeakMap();

function setOrClear(overlay, attr, value) {
  if (value === null) overlay.removeAttribute(attr);
  else overlay.setAttribute(attr, value);
}

function restoreMarkupName(overlay) {
  if (!markupNames.has(overlay)) {
    markupNames.set(overlay, {
      label: overlay.getAttribute('aria-label'),
      labelledby: overlay.getAttribute('aria-labelledby'),
    });
  }
  const { label, labelledby } = markupNames.get(overlay);
  setOrClear(overlay, 'aria-label', label);
  setOrClear(overlay, 'aria-labelledby', labelledby);
}

function nameDialog(overlay, label, labelledby) {
  restoreMarkupName(overlay);

  const source = labelledby instanceof HTMLElement
    ? labelledby
    : (labelledby ? document.getElementById(labelledby) : null);
  if (source) {
    if (!source.id) source.id = nextTitleId();
    overlay.setAttribute('aria-labelledby', source.id);
    overlay.removeAttribute('aria-label');
    return;
  }
  if (label) {
    overlay.setAttribute('aria-label', label);
    overlay.removeAttribute('aria-labelledby');
    return;
  }

  if (overlay.getAttribute('aria-label') || overlay.getAttribute('aria-labelledby')) return;
  const heading = overlay.querySelector('h1, h2, h3, h4');
  if (!heading) return;
  if (!heading.id) heading.id = nextTitleId();
  overlay.setAttribute('aria-labelledby', heading.id);
}

function ensureDialog(overlay, { label, labelledby }) {
  if (!overlay.getAttribute('role')) overlay.setAttribute('role', 'dialog');
  if (!overlay.hasAttribute('tabindex')) overlay.tabIndex = -1;
  nameDialog(overlay, label, labelledby);
}

// ARIA leaves two simultaneous aria-modal dialogs undefined, so the attribute
// follows the top of the stack rather than being set once and left behind.
function syncAriaModal() {
  const top = stack.length - 1;
  stack.forEach((entry, index) => {
    if (index === top) entry.overlay.setAttribute('aria-modal', 'true');
    else entry.overlay.removeAttribute('aria-modal');
  });
}

function finish(entry, dismissed) {
  const index = stack.indexOf(entry);
  if (index === -1) return;
  stack.splice(index, 1);

  if (entry.transient) entry.overlay.remove();
  else entry.overlay.classList.remove('visible');
  entry.overlay.removeAttribute('aria-modal');
  syncAriaModal();

  // Only the modal the user was actually in hands focus back; closing one
  // buried under another must not pull focus out of the one on top.
  const wasTop = index === stack.length;
  const back = entry.returnFocus;
  if (wasTop && back instanceof HTMLElement && back.isConnected) back.focus();

  if (dismissed) entry.onDismiss?.();
}

// An overlay hidden by its own code, rather than through here, still has to
// leave the stack — and it counts as dismissed, because nothing else is going
// to run the caller's teardown for it.
function prune() {
  for (let i = stack.length - 1; i >= 0; i--) {
    const entry = stack[i];
    const gone = !entry.overlay.isConnected
      || (!entry.transient && !entry.overlay.classList.contains('visible'));
    if (gone) finish(entry, true);
  }
}

function dismiss(overlay) {
  const entry = stack.find((candidate) => candidate.overlay === overlay);
  if (entry) finish(entry, true);
}

function adopt(overlay, options) {
  const { transient = false, signature = null, onDismiss, label, labelledby, initialFocus } = options;
  if (!transient) overlay.classList.add('visible');
  ensureDialog(overlay, { label, labelledby });

  const entry = {
    overlay,
    transient,
    signature,
    onDismiss,
    returnFocus: document.activeElement,
    handle: null,
  };
  entry.handle = { overlay, close: () => finish(entry, false) };
  stack.push(entry);
  syncAriaModal();

  (preferredFocus(overlay, initialFocus) || overlay).focus();
  return entry.handle;
}

function trapTab(overlay, event) {
  const items = focusableWithin(overlay);
  if (items.length === 0) {
    event.preventDefault();
    overlay.focus();
    return;
  }

  const first = items[0];
  const last = items[items.length - 1];
  const active = document.activeElement;

  if (!overlay.contains(active)) {
    event.preventDefault();
    (event.shiftKey ? last : first).focus();
    return;
  }
  if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  } else if (event.shiftKey && active === first) {
    event.preventDefault();
    last.focus();
  }
}

function onKeydown(event) {
  if (event.key !== 'Escape' && event.key !== 'Tab') return;
  prune();
  const entry = stack[stack.length - 1];
  if (!entry) return;

  if (event.key === 'Tab') {
    trapTab(entry.overlay, event);
    return;
  }
  event.preventDefault();
  event.stopImmediatePropagation();
  closeTopModal();
}

// One listener for the whole stack. It stays silent while nothing is open so
// the page keeps its own Escape bindings. The headless reporters in scripts/
// import the parsers, which reach this module through the extractor, and there
// is no document to bind to there.
if (typeof document !== 'undefined') {
  document.addEventListener('keydown', onKeydown);
}

// Adopts one of the overlays that already lives in index.html. `label` or
// `labelledby` names the dialog for this open, where a static name in the
// markup is too vague to say which file or row it is showing.
export function openModal(overlayEl, { onDismiss, initialFocus, label, labelledby } = {}) {
  if (!overlayEl) return null;
  prune();
  const existing = stack.find((entry) => entry.overlay === overlayEl);
  if (existing) {
    if (onDismiss) existing.onDismiss = onDismiss;
    if (label || labelledby) nameDialog(overlayEl, label, labelledby);
    return existing.handle;
  }
  return adopt(overlayEl, { onDismiss, initialFocus, label, labelledby });
}

// Builds and shows an overlay. A repeat click that would put a second copy of
// the same overlay on screen is refused; a different modal on top is not.
export function openTransientModal(innerHtml, { onDismiss, label, labelledby } = {}) {
  prune();
  if (stack.some((entry) => entry.transient && entry.signature === innerHtml)) return null;

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.innerHTML = innerHtml;
  document.body.appendChild(overlay);

  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) dismiss(overlay);
  });

  return adopt(overlay, { transient: true, signature: innerHtml, onDismiss, label, labelledby });
}

// Closes without running onDismiss — the caller already knows the outcome.
export function closeModal(overlayEl) {
  const entry = stack.find((candidate) => candidate.overlay === overlayEl);
  if (entry) finish(entry, false);
}

export function closeTopModal() {
  prune();
  const entry = stack[stack.length - 1];
  if (!entry) return false;
  finish(entry, true);
  return true;
}

export function isModalOpen() {
  prune();
  return stack.length > 0;
}

export function topModal() {
  prune();
  return stack[stack.length - 1]?.overlay || null;
}
