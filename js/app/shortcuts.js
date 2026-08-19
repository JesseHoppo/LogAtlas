import { state } from '../core/state.js';
import { PAGE_IDS } from '../pages/registry.js';
import { escapeHtml } from '../core/utils.js';
import { openModal, openTransientModal, closeModal, isModalOpen, topModal } from '../core/modal.js';

// The help modal is built from this table, so a binding and its description
// cannot drift apart. Keys bound in the browser, the preview and the pickers
// are listed too — the modal describes the whole app, not just this file.
const SHORTCUTS = [
  { keys: ['?'], description: 'Show this help' },
  { keys: ['/'], description: 'Search from anywhere' },
  { keys: ['g', 'Ctrl+K'], description: 'Go to page' },
  { keys: ['Esc'], description: 'Close preview / modal' },
  { keys: ['Enter'], description: 'Execute search / next match' },
  { keys: ['Shift+Enter'], description: 'Previous search match' },
  { keys: ['Backspace'], description: 'Navigate up in file browser' },
  { keys: ['↑ ↓'], description: 'Move between files (in file browser)' },
  { keys: ['Enter'], description: 'Open folder / preview file (in file browser)' },
  { keys: ['Space'], description: 'Select the focused file' },
  { keys: ['1-9'], description: 'Select file type (in type modal)' },
];

// Every shape of search field the pages put on screen. Whichever one the
// current page owns is what `/` reaches for.
const SEARCH_FIELD = '.data-page-search, .search-page-input, .search-input';

// Only controls that take typed text count. A checkbox or a button holding
// focus is not someone typing, and swallowing the key there would make the
// shortcut look broken on half the pages.
const TEXT_INPUT_TYPES = new Set(['text', 'search', 'password', 'email', 'url', 'tel', 'number']);

const JUMP_LIST_ID = 'jumpPageList';

function isEditableTarget() {
  const active = document.activeElement;
  if (!active) return false;
  if (active.isContentEditable || active.tagName === 'TEXTAREA') return true;
  return active.tagName === 'INPUT' && TEXT_INPUT_TYPES.has(active.type);
}

function isBrowserPage() {
  return Boolean(document.getElementById(PAGE_IDS.browser)?.classList.contains('active'));
}

// Below the drawer breakpoint the sidebar sits off-canvas, so handing focus to
// a nav item there would put it somewhere the user cannot see.
function isDrawerLayout() {
  return Boolean(document.getElementById('sidebarToggle')?.getClientRects().length);
}

function renderShortcutList(container) {
  if (!container) return;
  container.innerHTML = SHORTCUTS.map(({ keys, description }) => `
    <div class="shortcut-row">${keys.map((key) => `<kbd>${escapeHtml(key)}</kbd>`).join('')}<span>${escapeHtml(description)}</span></div>
  `).join('');
}

function pageTitle(pageName) {
  const page = document.getElementById(PAGE_IDS[pageName]);
  return page?.querySelector('.page-title')?.textContent.trim() || '';
}

// The sidebar is the list of destinations: it already knows the order, the
// labels, the grouping, and which pages this case has data for.
function jumpDestinations() {
  return [...document.querySelectorAll('#sidebarNav .sidebar-nav-item')]
    .filter((button) => !button.disabled)
    .map((button) => {
      const label = button.textContent.trim();
      const title = pageTitle(button.dataset.page);
      return {
        button,
        label,
        section: button.closest('.sidebar-section')?.querySelector('.sidebar-section-label')?.textContent.trim() || '',
        // The sidebar's short label is what is shown, but the page's own
        // heading is what an analyst may remember, so "credit" finds Cards.
        haystack: `${label} ${title === label ? '' : title}`.toLowerCase(),
      };
    });
}

function openJumpPalette() {
  const destinations = jumpDestinations();

  const modal = openTransientModal(`
    <div class="modal">
      <h3>Go to page</h3>
      <div class="search-page-bar">
        <input type="text" class="search-page-input" id="jumpFilter" placeholder="Filter pages..."
          autocomplete="off" role="combobox" aria-expanded="true" aria-autocomplete="list"
          aria-controls="${JUMP_LIST_ID}" aria-label="Filter pages">
      </div>
      <div class="filetype-options" id="${JUMP_LIST_ID}" role="listbox" aria-label="Pages"></div>
      <div class="filetype-pending hidden" id="jumpEmpty" role="status">No page matches that.</div>
      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" id="jumpCancel">Cancel</button>
      </div>
    </div>
  `);
  if (!modal) return;

  const { overlay, close } = modal;
  const filter = overlay.querySelector('#jumpFilter');
  const list = overlay.querySelector(`#${JUMP_LIST_ID}`);
  const empty = overlay.querySelector('#jumpEmpty');

  let shown = destinations;
  let activeIndex = 0;

  function setActive(index) {
    const options = [...list.querySelectorAll('.filetype-option')];
    if (options.length === 0) {
      filter.removeAttribute('aria-activedescendant');
      return;
    }
    activeIndex = Math.max(0, Math.min(index, options.length - 1));
    options.forEach((option, position) => {
      const isActive = position === activeIndex;
      option.classList.toggle('active', isActive);
      option.setAttribute('aria-selected', String(isActive));
      if (!isActive) return;
      filter.setAttribute('aria-activedescendant', option.id);
      option.scrollIntoView({ block: 'nearest' });
    });
  }

  function paint() {
    list.innerHTML = shown.map((destination, index) => `
      <button class="filetype-option" role="option" tabindex="-1" id="jumpOption${index}" data-index="${index}" data-key="${escapeHtml(destination.section)}">
        <span class="filetype-icon">${escapeHtml(destination.label)}</span>
      </button>
    `).join('');
    empty.classList.toggle('hidden', shown.length > 0);
    setActive(0);
  }

  function go(index) {
    const destination = shown[index];
    if (!destination) return;
    close();
    destination.button.click();
    // Landing on the nav item the jump chose keeps the keyboard where the user
    // left off; the modal layer's own restore would drop it back on the body.
    if (!isDrawerLayout()) destination.button.focus();
  }

  filter.addEventListener('input', () => {
    const query = filter.value.trim().toLowerCase();
    shown = query ? destinations.filter((destination) => destination.haystack.includes(query)) : destinations;
    paint();
  });

  // Home and End belong to the text field while the cursor is in it.
  overlay.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') setActive(activeIndex + 1);
    else if (event.key === 'ArrowUp') setActive(activeIndex - 1);
    else if (event.key === 'Enter') go(activeIndex);
    else return;
    event.preventDefault();
  });

  list.addEventListener('click', (event) => {
    const option = event.target.closest('.filetype-option');
    if (option) go(Number(option.dataset.index));
  });

  overlay.querySelector('#jumpCancel').addEventListener('click', () => close());

  paint();
}

// Pages without a field of their own hand the key to the global search rather
// than swallowing it, so `/` always ends with a cursor in a search box.
function focusSearch() {
  const page = document.querySelector('.page.active');
  const field = [...(page?.querySelectorAll(SEARCH_FIELD) || [])]
    .find((candidate) => candidate.getClientRects().length > 0);
  if (field) {
    field.focus();
    field.select();
    return;
  }

  const searchNav = document.querySelector('#sidebarNav [data-page="search"]');
  if (!searchNav || searchNav.disabled) return;
  searchNav.click();
  document.getElementById('globalSearchInput')?.focus();
}

export function initKeyboardShortcuts({ navigateTo }) {
  const shortcutsModal = document.getElementById('shortcutsModal');
  renderShortcutList(shortcutsModal?.querySelector('.shortcuts-list'));

  document.getElementById('shortcutsClose')?.addEventListener('click', () => {
    closeModal(shortcutsModal);
  });

  shortcutsModal?.addEventListener('click', (event) => {
    if (event.target === shortcutsModal) closeModal(shortcutsModal);
  });

  // Escape belongs to the modal stack, which handles it before this listener
  // ever runs; every overlay in the app is opened through it.
  document.addEventListener('keydown', (event) => {
    // The one binding that survives a text field: a chord cannot be typed by
    // accident, and it is the key people arrive at a palette expecting.
    if ((event.ctrlKey || event.metaKey) && !event.shiftKey && !event.altKey && event.key.toLowerCase() === 'k') {
      if (isModalOpen()) return;
      event.preventDefault();
      openJumpPalette();
      return;
    }

    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (isEditableTarget()) return;

    // Help stays reachable from inside another dialog — the stack keeps the two
    // independent, and Escape closes only the one on top.
    if (event.key === '?') {
      event.preventDefault();
      if (topModal() === shortcutsModal) closeModal(shortcutsModal);
      else openModal(shortcutsModal, { initialFocus: '#shortcutsClose' });
      return;
    }

    // Everything below acts on the page behind whatever is open.
    if (isModalOpen()) return;

    if (event.key === 'g') {
      event.preventDefault();
      openJumpPalette();
      return;
    }

    if (event.key === '/') {
      event.preventDefault();
      focusSearch();
      return;
    }

    if (event.key === 'Backspace') {
      if (!isBrowserPage() || state.currentPath.length === 0) return;
      event.preventDefault();
      navigateTo(state.currentPath.slice(0, -1));
    }
  });
}
