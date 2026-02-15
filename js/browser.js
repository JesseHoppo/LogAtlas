// File browser

import { state, on, emit } from './state.js';
import { getNodeAtPath, getChildrenList, countChildren, flattenTree, loadFileContent, applyManualType } from './extractor.js';
import {
  escapeHtml,
  escapeAttr,
  formatBytes,
  getFileIcon,
} from './utils.js';
import { downloadBlob, copyToClipboard } from './shared.js';
import { escapeCSV } from './dataPages.js';
import { parsePasswordFile, parseCookieFile, toCSV } from './transforms.js';

let elBreadcrumb;
let elFileGrid;
let elFileList;
let elFileBrowser;
let elSearchInput;

const selectedFiles = new Set();
let selectionMode = false;

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
  selectionMode = false;
  updateSelectionToolbar();
}

function toggleSelection(name) {
  if (selectedFiles.has(name)) {
    selectedFiles.delete(name);
  } else {
    selectedFiles.add(name);
  }
  selectionMode = selectedFiles.size > 0;
  updateSelectionUI();
  updateSelectionToolbar();
}

function updateSelectionUI() {
  const allItems = elFileBrowser.querySelectorAll('[data-name]');
  for (const el of allItems) {
    const name = el.dataset.name;
    const cb = el.querySelector('.file-select-cb');
    if (cb) cb.checked = selectedFiles.has(name);
    el.classList.toggle('selected', selectedFiles.has(name));
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

function getSelectedNodes() {
  const node = getNodeAtPath(state.currentPath);
  if (!node || !node.children) return [];
  const results = [];
  for (const name of selectedFiles) {
    const child = node.children[name];
    if (child && child.type === 'file') {
      results.push(child);
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

// Grid view

function renderGrid(items) {
  let html = '';

  if (state.currentPath.length > 0) {
    html += `<div class="file-item back-item" data-action="back">` +
      `<div class="file-item-icon">&larr;</div>` +
      `<div class="file-item-name">..</div>` +
      `<div class="file-item-meta">Go back</div></div>`;
  }

  if (items.length === 0 && state.currentPath.length === 0) {
    elFileGrid.innerHTML = `<div class="empty-folder">` +
      `<div class="empty-folder-icon">--</div><div>No files found</div></div>`;
    return;
  }

  for (const item of items) {
    const isDir = item.type === 'directory';
    const icon = getFileIcon(item.name, isDir, item.isArchive);
    const checked = selectedFiles.has(item.name) ? 'checked' : '';
    const selectedClass = selectedFiles.has(item.name) ? ' selected' : '';

    html += `<div class="file-item${selectedClass}" data-name="${escapeAttr(item.name)}" ` +
      `data-folder="${isDir}" data-size="${item.size}">`;

    if (!isDir) {
      html += `<input type="checkbox" class="file-select-cb" ${checked} tabindex="-1">`;
    }

    html += `<div class="file-item-icon">${icon}</div>` +
      `<div class="file-item-name">${escapeHtml(item.name)}</div>`;

    if (isDir) {
      const count = countChildren(item);
      html += `<div class="file-item-meta">${count} item${count !== 1 ? 's' : ''}</div>`;
    } else if (item.size > 0) {
      html += `<div class="file-item-meta">${formatBytes(item.size)}</div>`;
    }

    if (item.encrypted) {
      html += `<div class="file-item-badge encrypted">encrypted</div>`;
    } else if (item.isNestedArchive) {
      html += `<div class="file-item-badge">nested archive</div>`;
    }

    if (item._passwordFileHint) html += `<div class="file-item-badge password-file">credentials</div>`;
    if (item._cookieFileHint) html += `<div class="file-item-badge cookie-file">cookies</div>`;
    if (item._autofillHint) html += `<div class="file-item-badge autofill-file">autofill</div>`;
    if (item._historyHint) html += `<div class="file-item-badge history-file">history</div>`;

    html += `</div>`;
  }

  elFileGrid.innerHTML = html;
}

// List view

function renderList(items) {
  let html = '';

  if (state.currentPath.length > 0) {
    html += `<div class="file-list-item" data-action="back">` +
      `<div class="file-list-icon">&larr;</div>` +
      `<div class="file-list-name">..</div>` +
      `<div class="file-list-meta">Go back</div></div>`;
  }

  if (items.length === 0 && state.currentPath.length === 0) {
    elFileList.innerHTML = `<div class="empty-folder">` +
      `<div class="empty-folder-icon">--</div><div>No files found</div></div>`;
    return;
  }

  for (const item of items) {
    const isDir = item.type === 'directory';
    const icon = getFileIcon(item.name, isDir, item.isArchive);
    const checked = selectedFiles.has(item.name) ? 'checked' : '';
    const selectedClass = selectedFiles.has(item.name) ? ' selected' : '';

    html += `<div class="file-list-item${selectedClass}" data-name="${escapeAttr(item.name)}" ` +
      `data-folder="${isDir}" data-size="${item.size}">`;

    if (!isDir) {
      html += `<input type="checkbox" class="file-select-cb" ${checked} tabindex="-1">`;
    }

    html += `<div class="file-list-icon">${icon}</div>` +
      `<div class="file-list-name">${escapeHtml(item.name)}</div>`;

    if (item.encrypted) {
      html += `<div class="file-list-badge encrypted">encrypted</div>`;
    } else if (item.isNestedArchive) {
      html += `<div class="file-list-badge">nested</div>`;
    }

    if (item._passwordFileHint) html += `<div class="file-list-badge password-file">credentials</div>`;
    if (item._cookieFileHint) html += `<div class="file-list-badge cookie-file">cookies</div>`;
    if (item._autofillHint) html += `<div class="file-list-badge autofill-file">autofill</div>`;
    if (item._historyHint) html += `<div class="file-list-badge history-file">history</div>`;

    if (isDir) {
      const count = countChildren(item);
      html += `<div class="file-list-meta">${count} item${count !== 1 ? 's' : ''}</div>`;
    } else if (item.size > 0) {
      html += `<div class="file-list-meta">${formatBytes(item.size)}</div>`;
    }

    html += `</div>`;
  }

  elFileList.innerHTML = html;
}

// Click handler (shared between grid & list)

function onItemClick(e) {
  if (e.target.classList.contains('file-select-cb')) {
    const el = e.target.closest('[data-name]');
    if (el) {
      e.stopPropagation();
      toggleSelection(el.dataset.name);
    }
    return;
  }

  const el = e.target.closest('[data-action="back"], [data-name]');
  if (!el) return;

  if (el.dataset.action === 'back') {
    navigateTo(state.currentPath.slice(0, -1));
    return;
  }

  const isFolder = el.dataset.folder === 'true';

  if (isFolder) {
    navigateTo([...state.currentPath, el.dataset.name]);
  } else {
    const name = el.dataset.name;
    const size = parseInt(el.dataset.size) || 0;
    emit('preview:open', { name, size, path: [...state.currentPath] });
  }
}

// Set Type action

function showTypeMenu() {
  const nodes = getSelectedNodes();
  if (nodes.length === 0) return;

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.id = 'setTypeModal';
  overlay.innerHTML = `
    <div class="modal modal-filetype">
      <h3>Set Type for ${nodes.length} File(s)</h3>
      <div class="filetype-options">
        <button class="filetype-option" data-type="credentials" data-key="1">
          <span class="filetype-icon">Credentials</span>
        </button>
        <button class="filetype-option" data-type="cookies" data-key="2">
          <span class="filetype-icon">Cookies</span>
        </button>
        <button class="filetype-option" data-type="autofill" data-key="3">
          <span class="filetype-icon">Autofill</span>
        </button>
        <button class="filetype-option" data-type="history" data-key="4">
          <span class="filetype-icon">History</span>
        </button>
        <button class="filetype-option filetype-option-remove" data-type="none" data-key="5">
          <span class="filetype-icon">Remove Label</span>
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

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

    overlay.remove();
    clearSelection();
    render();
    emit('reanalyze');
  });

  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
}

// Export selected files to ZIP

async function exportSelectedZip() {
  const nodes = getSelectedNodes();
  if (nodes.length === 0) return;

  const hasTransformable = nodes.some(n => n._passwordFileHint || n._cookieFileHint);

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.id = 'exportSelectionModal';
  overlay.innerHTML = `
    <div class="modal">
      <h3>Export ${nodes.length} File(s)</h3>
      ${hasTransformable ? `<label class="remember-password" style="margin-bottom: 0.5rem; display: block;">
        <input type="checkbox" id="exportSelTransform"> Export typed files as CSV
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
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    zipPassword = Array.from(arr, b => charset[b % charset.length]).join('');

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

    for (const node of nodes) {
      try {
        const content = await loadFileContent(node);
        if (!content) continue;

        if (result.applyTransforms && (node._passwordFileHint || node._cookieFileHint)) {
          const decoder = new TextDecoder('utf-8');
          const text = decoder.decode(content);
          let parsed = null;
          if (node._cookieFileHint) {
            parsed = parseCookieFile(text);
          } else {
            parsed = parsePasswordFile(text);
          }
          if (parsed && parsed.rows.length > 0) {
            const csv = toCSV(parsed);
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
  } catch {
    // notify handled upstream
  }
}

// Render

function render() {
  const items = getItems();
  renderBreadcrumb();

  elFileGrid.classList.toggle('active', state.viewMode === 'grid');
  elFileList.classList.toggle('active', state.viewMode === 'list');
  if (state.viewMode === 'grid') {
    renderGrid(items);
  } else {
    renderList(items);
  }
}

// View mode toggle

function setViewMode(mode) {
  state.viewMode = mode;

  const gridBtn = document.getElementById('gridViewBtn');
  const listBtn = document.getElementById('listViewBtn');
  gridBtn.classList.toggle('active', mode === 'grid');
  listBtn.classList.toggle('active', mode === 'list');
  gridBtn.setAttribute('aria-pressed', mode === 'grid');
  listBtn.setAttribute('aria-pressed', mode === 'list');

  elFileGrid.classList.toggle('active', mode === 'grid');
  elFileList.classList.toggle('active', mode === 'list');

  const items = getItems();
  if (mode === 'grid') {
    renderGrid(items);
  } else {
    renderList(items);
  }
}

// Init

function initBrowser() {
  elBreadcrumb = document.getElementById('breadcrumb');
  elFileGrid = document.getElementById('fileGrid');
  elFileList = document.getElementById('fileList');
  elFileBrowser = document.getElementById('fileBrowser');
  elSearchInput = document.getElementById('searchInput');

  elBreadcrumb.addEventListener('click', onBreadcrumbClick);
  elFileGrid.addEventListener('click', onItemClick);
  elFileList.addEventListener('click', onItemClick);

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
        selectedFiles.add(item.name);
      }
    }
    selectionMode = selectedFiles.size > 0;
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

export { initBrowser, navigateTo, render };
