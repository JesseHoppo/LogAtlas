// File browser

import { state, on, emit } from '../core/state.js';
import { getNodeAtPath, getChildrenList, countChildren, flattenTree, loadFileContent, applyManualType } from './extractor.js';
import {
  escapeHtml,
  escapeAttr,
  formatBytes,
  getFileIcon,
} from '../core/utils.js';
import { downloadBlob, copyToClipboard, randomPassword, showNotification } from '../core/shared.js';
import { toCSV } from '../transforms/shared.js';
import { buildFileTypeOptionsHtml } from './fileTypeRegistry.js';
import { canOfferTransformAction, parseStructuredFile } from './structuredTransforms.js';
import { emitPreview } from '../pages/shared.js';

let elBreadcrumb;
let elFileGrid;
let elFileList;
let elSearchInput;

const selectedFiles = new Set();
const BADGE_DEFINITIONS = Object.freeze([
  { hint: '_passwordFileHint', label: 'credentials', className: 'password-file' },
  { hint: '_cookieFileHint', label: 'cookies', className: 'cookie-file' },
  { hint: '_autofillHint', label: 'autofill', className: 'autofill-file' },
  { hint: '_historyHint', label: 'history', className: 'history-file' },
  { hint: '_cryptoWalletHint', label: 'wallets' },
  { hint: '_notesHint', label: 'notes' },
  { hint: '_grabbedFileHint', label: 'grabbed' },
]);

// Navigation

function navigateTo(pathSegments) {
  state.currentPath = pathSegments;
  state.filterText = '';
  if (elSearchInput) elSearchInput.value = '';
  clearSelection();
  render();
}

// Selection

function clearSelection() {
  selectedFiles.clear();
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
  updateSelectionUI();
  updateSelectionToolbar();
}

function updateSelectionUI() {
  const container = state.viewMode === 'grid' ? elFileGrid : elFileList;
  if (!container) return;
  for (const el of container.querySelectorAll('[data-path]')) {
    const key = el.dataset.path;
    const cb = el.querySelector('.file-select-cb');
    if (cb) cb.checked = selectedFiles.has(key);
    el.classList.toggle('selected', selectedFiles.has(key));
  }
}

function updateSelectionToolbar() {
  const toolbar = document.getElementById('selectionToolbar');
  if (!toolbar) return;
  if (selectedFiles.size > 0) {
    toolbar.classList.add('visible');
    document.getElementById('selectionCount').textContent =
      `${selectedFiles.size} selected`;
  } else {
    toolbar.classList.remove('visible');
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

function renderBreadcrumb() {
  const parts = state.currentPath;
  let html = '';

  const rootClass = parts.length === 0 ? 'current' : '';
  html += `<div class="breadcrumb-item ${rootClass}" data-path="">` +
    `${escapeHtml(state.rootZipName)}</div>`;

  for (let i = 0; i < parts.length; i++) {
    const isLast = i === parts.length - 1;
    const pathStr = parts.slice(0, i + 1).join('/');
    html += `<span class="breadcrumb-sep">\u203A</span>`;
    html += `<div class="breadcrumb-item ${isLast ? 'current' : ''}" ` +
      `data-path="${escapeAttr(pathStr)}">${escapeHtml(parts[i])}</div>`;
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

  for (const definition of BADGE_DEFINITIONS) {
    if (!item[definition.hint]) continue;
    const classSuffix = definition.className ? ` ${definition.className}` : '';
    html += `<div class="${badgeClass}${classSuffix}">${definition.label}</div>`;
  }

  return html;
}

// Grid/list views share markup; they differ only by class prefix, the nested-archive
// label, and badges-vs-meta ordering. Wrapper/back classes don't derive cleanly from
// the child prefix, so they're passed explicitly.

function renderItems(items, { prefix, itemClass, backClass, nestedLabel, badgesBeforeMeta }) {
  let html = '';

  if (state.currentPath.length > 0) {
    html += `<div class="${backClass}" data-action="back" role="button" tabindex="0" aria-label="Go up one folder">` +
      `<div class="${prefix}-icon">&larr;</div>` +
      `<div class="${prefix}-name">..</div>` +
      `<div class="${prefix}-meta">Go back</div></div>`;
  }

  if (items.length === 0 && state.currentPath.length === 0) {
    return `<div class="empty-folder">` +
      `<div class="empty-folder-icon">--</div><div>No files found</div></div>`;
  }

  for (const item of items) {
    const isDir = item.type === 'directory';
    const icon = getFileIcon(item.name, isDir, item.isArchive);
    const key = itemKey(item.name);
    const checked = selectedFiles.has(key) ? 'checked' : '';
    const selectedClass = selectedFiles.has(key) ? ' selected' : '';
    const verb = isDir ? `Open folder ${item.name}` : `Preview ${item.name}`;

    html += `<div class="${itemClass}${selectedClass}" data-name="${escapeAttr(item.name)}" ` +
      `data-path="${escapeAttr(key)}" ` +
      `data-folder="${isDir}" data-size="${item.size}" role="button" tabindex="0" aria-label="${escapeAttr(verb)}">`;

    if (!isDir) {
      html += `<input type="checkbox" class="file-select-cb" ${checked} tabindex="-1" aria-label="Select ${escapeAttr(item.name)}">`;
    }

    html += `<div class="${prefix}-icon">${icon}</div>` +
      `<div class="${prefix}-name">${escapeHtml(item.name)}</div>`;

    let meta = '';
    if (isDir) {
      const count = countChildren(item);
      meta = `<div class="${prefix}-meta">${count} item${count !== 1 ? 's' : ''}</div>`;
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
      toggleSelection(el.dataset.path);
    }
    return;
  }

  const el = e.target.closest('[data-action="back"], [data-name]');
  if (!el) return;
  activateItem(el);
}

function focusableSiblings(container) {
  return Array.from(container.querySelectorAll('[role="button"][tabindex="0"]'));
}

function onItemKeyDown(e) {
  const el = e.target.closest('[data-action="back"], [data-name]');
  if (!el || el.getAttribute('role') !== 'button') return;

  if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
    e.preventDefault();
    activateItem(el);
    return;
  }

  if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown' && e.key !== 'Home' && e.key !== 'End') return;

  const items = focusableSiblings(e.currentTarget);
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

function render() {
  const items = getItems();
  renderBreadcrumb();
  updateViewModeButtons();

  elFileGrid.classList.toggle('active', state.viewMode === 'grid');
  elFileList.classList.toggle('active', state.viewMode === 'list');
  renderCurrentView(items);
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

  document.getElementById('selectionSelectAll').addEventListener('click', () => {
    const items = getItems();
    for (const item of items) {
      if (item.type === 'file') {
        selectedFiles.add(itemKey(item.name));
      }
    }
    updateSelectionUI();
    updateSelectionToolbar();
  });

  document.getElementById('selectionSetType').addEventListener('click', showTypeMenu);
  document.getElementById('selectionExportZip').addEventListener('click', exportSelectedZip);
  document.getElementById('selectionClear').addEventListener('click', () => {
    clearSelection();
    render();
  });

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
