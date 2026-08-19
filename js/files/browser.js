// File browser

import { state, on, emit } from '../core/state.js';
import { getNodeAtPath, getChildrenList, countChildren, flattenTree, loadFileContent, applyManualType } from './extractor.js';
import {
  escapeHtml,
  formatBytes,
  getFileIcon,
} from '../core/utils.js';
import { downloadBlob, copyToClipboard, randomPassword, showNotification } from '../core/shared.js';
import { toCSV } from '../transforms/shared.js';
import { buildFileTypeOptionsHtml, getNodeFileType, getNodeHintBadges } from './fileTypeRegistry.js';
import { canTransformStructuredFile, parseStructuredFile } from './structuredTransforms.js';
import { countLabel, emitPreview, openTransientModal } from '../pages/shared.js';
import { topModal } from '../core/modal.js';

let elBreadcrumb;
let elFileGrid;
let elFileList;
let elSearchInput;

const selectedFiles = new Set();

// Where a shift-extension started, and the selection as it stood when it did.
// The range is re-derived from the anchor on every keystroke, so turning back
// shrinks it instead of leaving a trail, and anything picked beforehand
// survives the walk.
let anchorKey = null;
let rangeBase = null;

const TOOLBAR_BUTTON_IDS = [
  'selectionSelectAll',
  'selectionSetType',
  'selectionExportZip',
  'selectionClear',
];

// Navigation

function navigateTo(pathSegments) {
  state.currentPath = pathSegments;
  state.filterText = '';
  if (elSearchInput) elSearchInput.value = '';
  clearSelection();
  render();
}

// Selection

function currentContainer() {
  return state.viewMode === 'grid' ? elFileGrid : elFileList;
}

function setAnchor(key) {
  anchorKey = key;
  rangeBase = null;
}

function clearSelection() {
  selectedFiles.clear();
  setAnchor(null);
  updateSelectionUI();
  updateSelectionToolbar();
}

function itemKey(name) {
  return [...state.currentPath, name].join('/');
}

function toggleSelection(key) {
  if (selectedFiles.has(key)) {
    selectedFiles.delete(key);
  } else {
    selectedFiles.add(key);
  }
  setAnchor(key);
  updateSelectionUI();
  updateSelectionToolbar();
}

// Only file rows carry aria-selected, so this is what a range can span, in the
// order it is on screen rather than the order the keys went into the set.
function selectableRows(container) {
  return container ? [...container.querySelectorAll('[aria-selected]')] : [];
}

function extendSelectionTo(container, toKey) {
  const keys = selectableRows(container).map(row => row.dataset.path);
  const to = keys.indexOf(toKey);
  if (to < 0) return;

  if (keys.indexOf(anchorKey) < 0) anchorKey = toKey;
  if (!rangeBase) rangeBase = new Set(selectedFiles);
  const from = keys.indexOf(anchorKey);

  selectedFiles.clear();
  for (const key of rangeBase) selectedFiles.add(key);
  for (let i = Math.min(from, to); i <= Math.max(from, to); i++) selectedFiles.add(keys[i]);

  updateSelectionUI();
  updateSelectionToolbar();
}

// What Select all works on: the files of the folder on screen, narrowed to the
// matches when the filter box is in use.
function viewSelection(items) {
  const keys = items.filter(item => item.type === 'file').map(item => itemKey(item.name));
  return { keys, chosen: keys.filter(key => selectedFiles.has(key)).length };
}

function toggleSelectAll() {
  const { keys, chosen } = viewSelection(getItems());
  if (keys.length === 0) return;
  const selecting = chosen < keys.length;
  for (const key of keys) {
    if (selecting) selectedFiles.add(key);
    else selectedFiles.delete(key);
  }
  setAnchor(null);
  updateSelectionUI();
  updateSelectionToolbar();
}

function updateSelectionUI() {
  const container = currentContainer();
  if (!container) return;
  for (const el of container.querySelectorAll('[data-path]')) {
    const key = el.dataset.path;
    const cb = el.querySelector('.file-select-cb');
    if (cb) cb.checked = selectedFiles.has(key);
    if (el.hasAttribute('aria-selected')) el.setAttribute('aria-selected', String(selectedFiles.has(key)));
    el.classList.toggle('selected', selectedFiles.has(key));
  }
}

// The button names what it would take, which is the only thing on the page that
// says files can be picked at all before one has been.
function selectAllLabel(total, chosen) {
  if (total === 0) return 'Select all';
  if (chosen === total) return 'Deselect all';
  if (state.filterText) return `Select ${countLabel(total, 'match', 'matches')}`;
  // "Select all 1 file" reads as a mistake, and a third of the corpus's folders
  // hold exactly one.
  if (total === 1) return 'Select 1 file';
  return `Select all ${countLabel(total, 'file')}`;
}

// The toolbar stays on screen for as long as an archive is loaded: Select all is
// the only way into a selection without a mouse, so hiding it until a selection
// exists locks keyboard users out of Set type and Download ZIP entirely.
function updateSelectionToolbar(items = getItems()) {
  const toolbar = document.getElementById('selectionToolbar');
  if (!toolbar) return;
  toolbar.classList.toggle('visible', !!state.fileTree);
  toolbar.classList.toggle('has-selection', selectedFiles.size > 0);

  const count = document.getElementById('selectionCount');
  if (count) {
    count.textContent = selectedFiles.size === 0
      ? 'No files selected'
      : `${countLabel(selectedFiles.size, 'file')} selected`;
  }

  const { keys, chosen } = viewSelection(items);
  const selectAll = document.getElementById('selectionSelectAll');
  if (selectAll) selectAll.textContent = selectAllLabel(keys.length, chosen);

  const live = {
    selectionSelectAll: keys.length > 0,
    selectionSetType: selectedFiles.size > 0,
    selectionExportZip: selectedFiles.size > 0,
    selectionClear: selectedFiles.size > 0,
  };

  const active = document.activeElement;
  let handoff = null;
  for (const id of TOOLBAR_BUTTON_IDS) {
    const btn = document.getElementById(id);
    if (!btn) continue;
    btn.disabled = !live[id];
    if (!btn.disabled && !handoff) handoff = btn;
  }
  // Disabling the button the user is standing on drops focus to <body>. Hand it
  // to whatever in the bar is still live, or to the filter box, which is where
  // a view with nothing to select was most likely typed into being.
  if (active instanceof HTMLElement && active.disabled && TOOLBAR_BUTTON_IDS.includes(active.id)) {
    (handoff || elSearchInput)?.focus();
  }
}

function getSelectedEntries() {
  const results = [];
  for (const key of selectedFiles) {
    const segments = key.split('/');
    const node = getNodeAtPath(segments);
    if (node && node.type === 'file') {
      results.push({
        name: segments[segments.length - 1],
        path: segments,
        node,
      });
    }
  }
  return results;
}

// Breadcrumb

// Ancestors are buttons so the path can be walked from the keyboard. The
// segment the user is already on is a span: focusing it would offer a stop
// that does nothing.
function breadcrumbSegment(label, pathStr, isCurrent) {
  if (isCurrent) {
    return `<span class="breadcrumb-item current" aria-current="page">${escapeHtml(label)}</span>`;
  }
  return `<button type="button" class="breadcrumb-item" ` +
    `data-path="${escapeHtml(pathStr)}">${escapeHtml(label)}</button>`;
}

function renderBreadcrumb() {
  const parts = state.currentPath;
  let html = breadcrumbSegment(state.rootZipName, '', parts.length === 0);

  for (let i = 0; i < parts.length; i++) {
    html += `<span class="breadcrumb-sep">\u203A</span>`;
    html += breadcrumbSegment(parts[i], parts.slice(0, i + 1).join('/'), i === parts.length - 1);
  }

  elBreadcrumb.innerHTML = html;
}

function onBreadcrumbClick(e) {
  const item = e.target.closest('.breadcrumb-item');
  if (!item || item.classList.contains('current')) return;
  const pathStr = item.dataset.path;
  navigateTo(pathStr ? pathStr.split('/') : []);
}

// Filtered item list

function getItems() {
  const query = state.filterText.toLowerCase();
  const node = getNodeAtPath(state.currentPath);
  if (!node) return [];
  let items = getChildrenList(node);
  if (query) {
    items = items.filter(item => item.name.toLowerCase().includes(query));
  }
  return items;
}

function renderItemBadges(item, badgeClass, nestedLabel) {
  let html = '';

  if (item.encrypted) {
    html += `<div class="${badgeClass} encrypted">encrypted</div>`;
  } else if (item.isNestedArchive) {
    html += `<div class="${badgeClass}">${nestedLabel}</div>`;
  }

  // Every hint, not just the first: a file analysis reads as both credentials
  // and cookies should say so.
  for (const badge of getNodeHintBadges(item)) {
    const classSuffix = badge.className ? ` ${badge.className}` : '';
    html += `<div class="${badgeClass}${classSuffix}">${escapeHtml(badge.label.toLowerCase())}</div>`;
  }

  return html;
}

function emptyStateHtml() {
  const message = state.filterText
    ? `No files match "${escapeHtml(state.filterText)}"`
    : 'This folder is empty';
  return `<div class="empty-folder">` +
    `<div class="empty-folder-icon">--</div><div>${message}</div></div>`;
}

// Grid/list views share markup; they differ only by class prefix, the nested-archive
// label, and badges-vs-meta ordering. Wrapper/back classes don't derive cleanly from
// the child prefix, so they're passed explicitly.

function renderItems(items, { prefix, itemClass, backClass, nestedLabel, badgesBeforeMeta }) {
  let html = '';
  // Roving tab stop: one row is in the tab order, arrows move between the rest.
  let tabStopTaken = false;

  if (state.currentPath.length > 0) {
    tabStopTaken = true;
    html += `<div class="${backClass}" data-action="back" role="option" tabindex="0" aria-label="Go up one folder">` +
      `<div class="${prefix}-icon">&larr;</div>` +
      `<div class="${prefix}-name">..</div>` +
      `<div class="${prefix}-meta">Go back</div></div>`;
  }

  if (items.length === 0) {
    return html + emptyStateHtml();
  }

  for (const item of items) {
    const isDir = item.type === 'directory';
    const icon = getFileIcon(item.name, isDir, item.isArchive);
    const key = itemKey(item.name);
    const selected = selectedFiles.has(key);
    const checked = selected ? 'checked' : '';
    const selectedClass = selected ? ' selected' : '';
    const verb = isDir ? `Open folder ${item.name}` : `Preview ${item.name}`;
    const tabIndex = tabStopTaken ? -1 : 0;
    tabStopTaken = true;

    html += `<div class="${itemClass}${selectedClass}" data-name="${escapeHtml(item.name)}" ` +
      `data-path="${escapeHtml(key)}" ` +
      `data-folder="${isDir}" data-size="${item.size}" role="option" ` +
      `${isDir ? '' : `aria-selected="${selected}" `}` +
      `tabindex="${tabIndex}" aria-label="${escapeHtml(verb)}">`;

    if (!isDir) {
      // The row carries the selected state for assistive tech; the box is the
      // mouse target for it, so it stays out of the accessibility tree.
      html += `<input type="checkbox" class="file-select-cb" ${checked} tabindex="-1" aria-hidden="true">`;
    }

    html += `<div class="${prefix}-icon">${icon}</div>` +
      `<div class="${prefix}-name">${escapeHtml(item.name)}</div>`;

    let meta = '';
    if (isDir) {
      const count = countChildren(item);
      meta = `<div class="${prefix}-meta">${count.toLocaleString()} item${count !== 1 ? 's' : ''}</div>`;
    } else if (item.size > 0) {
      meta = `<div class="${prefix}-meta">${formatBytes(item.size)}</div>`;
    }

    const badges = renderItemBadges(item, `${prefix}-badge`, nestedLabel);

    html += badgesBeforeMeta ? badges + meta : meta + badges;

    html += `</div>`;
  }

  return html;
}

// Grid view

function renderGrid(items) {
  elFileGrid.innerHTML = renderItems(items, {
    prefix: 'file-item',
    itemClass: 'file-item',
    backClass: 'file-item back-item',
    nestedLabel: 'nested archive',
    badgesBeforeMeta: false,
  });
}

// List view

function renderList(items) {
  elFileList.innerHTML = renderItems(items, {
    prefix: 'file-list',
    itemClass: 'file-list-item',
    backClass: 'file-list-item',
    nestedLabel: 'nested',
    badgesBeforeMeta: true,
  });
}

function activateItem(el) {
  if (el.dataset.action === 'back') {
    navigateTo(state.currentPath.slice(0, -1));
    return;
  }

  const isFolder = el.dataset.folder === 'true';
  if (isFolder) {
    navigateTo([...state.currentPath, el.dataset.name]);
  } else {
    const name = el.dataset.name;
    const size = parseInt(el.dataset.size, 10) || 0;
    emitPreview({ name, size }, [...state.currentPath]);
  }
}

function onItemClick(e) {
  if (e.target.classList.contains('file-select-cb')) {
    const el = e.target.closest('[data-path]');
    if (el) {
      e.stopPropagation();
      if (e.shiftKey) extendSelectionTo(e.currentTarget, el.dataset.path);
      else toggleSelection(el.dataset.path);
    }
    return;
  }

  const el = e.target.closest('[data-action="back"], [data-name]');
  if (!el) return;
  // Shift takes a run of files rather than opening the one under the pointer.
  if (e.shiftKey && el.hasAttribute('aria-selected')) {
    extendSelectionTo(e.currentTarget, el.dataset.path);
    return;
  }
  activateItem(el);
}

function rowsIn(container) {
  return Array.from(container.querySelectorAll('[role="option"]'));
}

function setTabStop(container, el) {
  for (const row of rowsIn(container)) {
    row.tabIndex = row === el ? 0 : -1;
  }
}

function onItemFocusIn(e) {
  const el = e.target.closest('[role="option"]');
  if (el) setTabStop(e.currentTarget, el);
}

function onItemKeyDown(e) {
  const el = e.target.closest('[data-action="back"], [data-name]');
  if (!el || el.getAttribute('role') !== 'option') return;

  if (e.key === 'Enter') {
    e.preventDefault();
    activateItem(el);
    return;
  }

  // Space selects where selection is possible; on folders and the back tile
  // there is nothing to select, so it keeps its old meaning.
  if (e.key === ' ' || e.key === 'Spacebar') {
    e.preventDefault();
    if (el.hasAttribute('aria-selected')) toggleSelection(el.dataset.path);
    else activateItem(el);
    return;
  }

  if ((e.ctrlKey || e.metaKey) && (e.key === 'a' || e.key === 'A')) {
    e.preventDefault();
    toggleSelectAll();
    return;
  }

  // Escape only means the selection while there is one; otherwise it belongs to
  // whatever else on the page wants it.
  if (e.key === 'Escape' && selectedFiles.size > 0) {
    e.preventDefault();
    clearSelection();
    return;
  }

  if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown' && e.key !== 'Home' && e.key !== 'End') return;

  const items = rowsIn(e.currentTarget);
  const idx = items.indexOf(el);
  if (idx < 0) return;

  e.preventDefault();
  let nextIdx = idx;
  if (e.key === 'ArrowDown') nextIdx = Math.min(idx + 1, items.length - 1);
  else if (e.key === 'ArrowUp') nextIdx = Math.max(idx - 1, 0);
  else if (e.key === 'Home') nextIdx = 0;
  else if (e.key === 'End') nextIdx = items.length - 1;

  items[nextIdx]?.focus();
}

// Set Type action

function showTypeMenu() {
  const nodes = getSelectedEntries().map(({ node }) => node);
  if (nodes.length === 0) return;

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.id = 'setTypeModal';
  overlay.innerHTML = `
    <div class="modal modal-filetype">
      <h3>Set Type for ${nodes.length} File(s)</h3>
      <div class="filetype-options">${buildFileTypeOptionsHtml({ includeRemove: true })}</div>
    </div>
  `;
  document.body.appendChild(overlay);

  function close() {
    overlay.remove();
    document.removeEventListener('keydown', onKey);
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
  }
  document.addEventListener('keydown', onKey);

  overlay.querySelector('.filetype-options').addEventListener('click', (ev) => {
    const btn = ev.target.closest('.filetype-option');
    if (!btn) return;
    const type = btn.dataset.type;

    for (const node of nodes) {
      applyManualType(node, type);
    }

    if (state.fileTree) {
      state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
    }

    close();
    clearSelection();
    render();
    emit('reanalyze');
  });

  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) close();
  });
}

// Export selected files to ZIP

async function exportSelectedZip() {
  const entries = getSelectedEntries();
  if (entries.length === 0) return;

  const hasTransformable = entries.some(({ node, name }) => canOfferTransformAction(node, name));

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.id = 'exportSelectionModal';
  overlay.innerHTML = `
    <div class="modal">
      <h3>Export ${entries.length} File(s)</h3>
      ${hasTransformable ? `<label class="remember-password" style="margin-bottom: 0.5rem; display: block;">
        <input type="checkbox" id="exportSelTransform"> Export structured files as CSV when possible
      </label>` : ''}
      <label class="remember-password" style="margin-bottom: 1rem; display: block;">
        <input type="checkbox" id="exportSelPwProtect"> Password protect
      </label>
      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" id="exportSelCancel">Cancel</button>
        <button class="modal-btn modal-btn-submit" id="exportSelDownload">Download ZIP</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const result = await new Promise((resolve) => {
    overlay.querySelector('#exportSelCancel').addEventListener('click', () => {
      overlay.remove();
      resolve(null);
    });
    overlay.querySelector('#exportSelDownload').addEventListener('click', () => {
      const pw = overlay.querySelector('#exportSelPwProtect').checked;
      const transformEl = overlay.querySelector('#exportSelTransform');
      const transform = transformEl ? transformEl.checked : false;
      overlay.remove();
      resolve({ passwordProtect: pw, applyTransforms: transform });
    });
    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) { overlay.remove(); resolve(null); }
    });
  });

  if (!result) return;

  let zipPassword = null;
  if (result.passwordProtect) {
    zipPassword = randomPassword(16);

    const pwOverlay = document.createElement('div');
    pwOverlay.className = 'modal-overlay visible';
    pwOverlay.innerHTML = `
      <div class="modal">
        <h3>ZIP Password</h3>
        <p>Copy this password before proceeding.</p>
        <div class="export-password-display">
          <code class="export-password-value">${escapeHtml(zipPassword)}</code>
          <button class="export-password-copy" id="selPwCopy">Copy</button>
        </div>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="selPwCancel">Cancel</button>
          <button class="modal-btn modal-btn-submit" id="selPwProceed">Continue</button>
        </div>
      </div>
    `;
    document.body.appendChild(pwOverlay);

    pwOverlay.querySelector('#selPwCopy').addEventListener('click', async () => {
      const ok = await copyToClipboard(zipPassword);
      const btn = pwOverlay.querySelector('#selPwCopy');
      btn.textContent = ok ? 'Copied' : 'Failed';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });

    const proceed = await new Promise((resolve) => {
      pwOverlay.querySelector('#selPwCancel').addEventListener('click', () => {
        pwOverlay.remove(); resolve(false);
      });
      pwOverlay.querySelector('#selPwProceed').addEventListener('click', () => {
        pwOverlay.remove(); resolve(true);
      });
      pwOverlay.addEventListener('click', (ev) => {
        if (ev.target === pwOverlay) { pwOverlay.remove(); resolve(false); }
      });
    });

    if (!proceed) return;
  }

  try {
    const blobWriter = new zip.BlobWriter('application/zip');
    const writerOpts = zipPassword ? { password: zipPassword } : {};
    const writer = new zip.ZipWriter(blobWriter, writerOpts);

    for (const entry of entries) {
      try {
        const { node, path } = entry;
        const content = await loadFileContent(node);
        if (!content) continue;

        if (result.applyTransforms) {
          const parsed = parseStructuredFile({
            node,
            content,
            fileName: node.name || '',
            sourcePath: path.join('/'),
            allowUntypedFallback: true,
          });
          const csv = parsed && parsed.rows.length > 0 ? toCSV(parsed) : '';
          if (csv) {
            const csvBlob = new Blob([csv], { type: 'text/csv' });
            const baseName = node.name.replace(/\.[^.]+$/, '');
            await writer.add(baseName + '.csv', new zip.BlobReader(csvBlob));
          } else {
            const blob = new Blob([content]);
            await writer.add(node.name, new zip.BlobReader(blob));
          }
        } else {
          const blob = new Blob([content]);
          await writer.add(node.name, new zip.BlobReader(blob));
        }
      } catch {
        // skip files that fail
      }
    }

    await writer.close();
    const zipBlob = await blobWriter.getData();
    downloadBlob(zipBlob, 'selected_files.zip', 'application/zip');
  } catch (err) {
    showNotification(`Failed to export ZIP: ${err.message}`, 'error');
  }
}

// Render

function updateViewModeButtons() {
  const gridBtn = document.getElementById('gridViewBtn');
  const listBtn = document.getElementById('listViewBtn');
  gridBtn.classList.toggle('active', state.viewMode === 'grid');
  listBtn.classList.toggle('active', state.viewMode === 'list');
  gridBtn.setAttribute('aria-pressed', state.viewMode === 'grid');
  listBtn.setAttribute('aria-pressed', state.viewMode === 'list');
}

function renderCurrentView(items) {
  if (state.viewMode === 'grid') {
    renderGrid(items);
    return;
  }
  renderList(items);
}

// Replacing innerHTML destroys whatever the keyboard was on, which drops focus
// to <body> and strands the user outside the list. Only a caret that was already
// in the list is moved: the same row if it survived the render, otherwise the
// first one, which is the back tile when there is somewhere to go back to.
function focusedRowKey() {
  const active = document.activeElement;
  if (!active) return null;
  if (!elFileGrid.contains(active) && !elFileList.contains(active)) return null;
  const row = active.closest('[data-path], [data-action="back"]');
  if (!row) return null;
  return row.dataset.path ?? 'back';
}

function restoreRowFocus(container, key) {
  if (!key) return;
  const selector = key === 'back' ? '[data-action="back"]' : `[data-path="${CSS.escape(key)}"]`;
  const row = container.querySelector(selector) || container.querySelector('[role="option"]');
  row?.focus();
}

function render() {
  const items = getItems();
  const focusKey = focusedRowKey();
  renderBreadcrumb();
  updateViewModeButtons();

  elFileGrid.classList.toggle('active', state.viewMode === 'grid');
  elFileList.classList.toggle('active', state.viewMode === 'list');
  renderCurrentView(items);
  updateSelectionToolbar(items);
  restoreRowFocus(currentContainer(), focusKey);
}

// View mode toggle

function setViewMode(mode) {
  if (state.viewMode === mode) return;
  state.viewMode = mode;
  render();
}

// Init

function initBrowser() {
  elBreadcrumb = document.getElementById('breadcrumb');
  elFileGrid = document.getElementById('fileGrid');
  elFileList = document.getElementById('fileList');
  elSearchInput = document.getElementById('searchInput');

  elBreadcrumb.addEventListener('click', onBreadcrumbClick);
  elFileGrid.addEventListener('click', onItemClick);
  elFileList.addEventListener('click', onItemClick);
  elFileGrid.addEventListener('keydown', onItemKeyDown);
  elFileList.addEventListener('keydown', onItemKeyDown);
  elFileGrid.addEventListener('focusin', onItemFocusIn);
  elFileList.addEventListener('focusin', onItemFocusIn);

  document.getElementById('gridViewBtn').addEventListener('click', () => setViewMode('grid'));
  document.getElementById('listViewBtn').addEventListener('click', () => setViewMode('list'));

  let searchTimer = null;
  elSearchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filterText = elSearchInput.value.trim();
      render();
    }, 150);
  });

  // A selection made from the keyboard changes nothing that is announced on its
  // own, so the count carries it into the accessibility tree.
  const selectionCount = document.getElementById('selectionCount');
  if (selectionCount) {
    selectionCount.setAttribute('role', 'status');
    selectionCount.setAttribute('aria-live', 'polite');
    selectionCount.setAttribute('aria-atomic', 'true');
  }

  document.getElementById('selectionSelectAll').addEventListener('click', toggleSelectAll);
  document.getElementById('selectionSetType').addEventListener('click', showTypeMenu);
  document.getElementById('selectionExportZip').addEventListener('click', exportSelectedZip);
  document.getElementById('selectionClear').addEventListener('click', clearSelection);

  on('extracted', () => {
    state.currentPath = [];
    state.filterText = '';
    elSearchInput.value = '';
    clearSelection();
    render();
  });

  on('reanalyze', () => {
    render();
  });

  on('reset', () => {
    elFileGrid.innerHTML = '';
    elFileList.innerHTML = '';
    elBreadcrumb.innerHTML = '';
    elSearchInput.value = '';
    state.filterText = '';
    clearSelection();
  });
}

export { initBrowser, navigateTo };
