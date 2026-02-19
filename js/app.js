// Main entry -- drag-drop, navigation, dashboard, keyboard shortcuts.

import { state, on, emit, resetState, setMultiFileMode, setManualType } from './state.js';
import { extractFile, flattenTree, loadFileContent, applyManualType, addFilesToTree } from './extractor.js';
import { initBrowser, navigateTo } from './browser.js';
import { initPreview, closePreview } from './preview.js';
import { initPasswordModal, closePasswordModal } from './password.js';
import { initFileTypeModal, promptForFileType } from './fileTypeModal.js';
import { formatBytes, escapeHtml, escapeAttr, isArchiveFile } from './utils.js';
import { runAnalysis, extractIOCs } from './analysis.js';
import { initDataPages, getPasswordsData, escapeCSV } from './dataPages.js';
import { initExports } from './exports.js';
import { initTimeline } from './timeline.js';
import { initIdentityGraph, initIdentityPage } from './identityGraph.js';
import { initColumnMapper } from './columnMapper.js';
import { collectFileNodes, collectHintedNodes, downloadBlob, copyToClipboard, showNotification, MAX_SEARCH_MATCHES_PER_FILE, SEARCH_BATCH_SIZE } from './shared.js';

// DOM refs

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const loading = document.getElementById('loading');
const loadingText = document.getElementById('loadingText');
const results = document.getElementById('results');
const resetZone = document.getElementById('resetZone');
const uploadInfo = document.getElementById('uploadInfo');

let sysInfoSourcePath = null;

// Page navigation

const sidebarNav = document.getElementById('sidebarNav');
const pages = {
  overview: document.getElementById('pageOverview'),
  sysinfo: document.getElementById('pageSysInfo'),
  browser: document.getElementById('pageBrowser'),
  search: document.getElementById('pageSearch'),
  passwords: document.getElementById('pagePasswords'),
  cookies: document.getElementById('pageCookies'),
  autofills: document.getElementById('pageAutofills'),
  history: document.getElementById('pageHistory'),
  timeline: document.getElementById('pageTimeline'),
  identity: document.getElementById('pageIdentity'),
  exports: document.getElementById('pageExports'),
};

function navigateToPage(pageName) {
  if (!pages[pageName]) return;
  const btn = sidebarNav.querySelector(`[data-page="${pageName}"]`);
  if (btn && btn.disabled) return;

  for (const [name, el] of Object.entries(pages)) {
    el.classList.toggle('active', name === pageName);
  }
  for (const item of sidebarNav.querySelectorAll('.sidebar-nav-item')) {
    item.classList.toggle('active', item.dataset.page === pageName);
  }

  if (['passwords', 'cookies', 'autofills', 'history', 'timeline', 'identity'].includes(pageName)) {
    emit('page:' + pageName);
  }
}

sidebarNav.addEventListener('click', (e) => {
  const btn = e.target.closest('.sidebar-nav-item');
  if (!btn || btn.disabled) return;
  navigateToPage(btn.dataset.page);
});

// Loading indicator

on('loading', () => {
  loadingText.textContent = state.loadingText;
});

// After extraction

on('extracted', () => {
  const files = state.flatFiles.filter(f => f.type === 'file');
  const credFiles = state.flatFiles.filter(f => f._passwordFileHint);
  const cookieFiles = state.flatFiles.filter(f => f._cookieFileHint);
  const autofillFiles = state.flatFiles.filter(f => f._autofillHint);

  if (credFiles.length > 0) {
    document.getElementById('dashCredIntel').classList.remove('hidden');
  }
  if (cookieFiles.length > 0) {
    document.getElementById('dashCookieIntel').classList.remove('hidden');
  }
  if (autofillFiles.length > 0) {
    document.getElementById('dashAutofillIntel').classList.remove('hidden');
  }
  if (credFiles.length === 0 && cookieFiles.length === 0) {
    document.getElementById('overviewNoData').classList.remove('hidden');
  }

  // Show extra data type indicators
  const creditCardFiles = state.flatFiles.filter(f => f._creditCardHint);
  const cryptoWalletFiles = state.flatFiles.filter(f => f._cryptoWalletHint);
  const messengerFiles = state.flatFiles.filter(f => f._messengerHint);

  if (creditCardFiles.length > 0 || cryptoWalletFiles.length > 0 || messengerFiles.length > 0) {
    const extraEl = document.getElementById('dashExtraIntel');
    const extraBody = document.getElementById('dashExtraBody');
    extraEl.classList.remove('hidden');

    let html = '<div class="dash-extra-items">';
    if (creditCardFiles.length > 0) {
      html += `<div class="dash-extra-item dash-extra-warning"><span class="dash-extra-icon">CC</span><span>${creditCardFiles.length} credit card file(s) detected</span></div>`;
    }
    if (cryptoWalletFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">W</span><span>${cryptoWalletFiles.length} crypto wallet file(s) detected</span></div>`;
    }
    if (messengerFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">M</span><span>${messengerFiles.length} messenger/token file(s) detected</span></div>`;
    }
    html += '</div>';
    extraBody.innerHTML = html;
  }

  document.getElementById('navSearch').disabled = false;
  document.getElementById('navBrowser').disabled = false;

  const errorList = document.getElementById('errorList');
  const errorItems = document.getElementById('errorListItems');

  if (state.errors.length > 0) {
    errorList.classList.add('visible');
    errorItems.innerHTML = state.errors.map(e => `<li>${escapeHtml(e)}</li>`).join('');
  } else {
    errorList.classList.remove('visible');
  }

  loading.classList.remove('visible');
  results.classList.add('visible');

  navigateToPage('overview');
  runAnalysis(state.fileTree, state.rootZipName);
});

on('reanalyze', () => {
  if (state.fileTree) {
    runAnalysis(state.fileTree, state.rootZipName);
  }
});

// Dashboard listeners

function renderBarList(container, items, maxItems = 10) {
  if (items.length === 0) {
    container.innerHTML = '<div class="dash-bar-empty">None found</div>';
    return;
  }
  const top = items.slice(0, maxItems);
  const maxCount = top[0].count;
  container.innerHTML = top.map(item => {
    const pct = Math.round((item.count / maxCount) * 100);
    return `<div class="dash-bar-row">
      <div class="dash-bar-fill" style="width:${pct}%"></div>
      <span class="dash-bar-label">${escapeHtml(item.value)}</span>
      <span class="dash-bar-count">${item.count}</span>
    </div>`;
  }).join('');
}

on('analysis:credentials', (data) => {
  const summaryEl = document.getElementById('dashCredSummary');
  summaryEl.classList.remove('dash-loading');

  if (data.totalCredentials > 0) {
    let summary = `${data.uniqueCredentials.toLocaleString()} unique credentials from ${data.fileCount} file(s)`;
    if (data.totalCredentials !== data.uniqueCredentials) {
      summary += ` (${data.totalCredentials.toLocaleString()} total, ${(data.totalCredentials - data.uniqueCredentials).toLocaleString()} duplicates removed)`;
    }
    summaryEl.textContent = summary;
    renderBarList(document.getElementById('dashTopDomains'), data.topDomains);
    renderBarList(document.getElementById('dashTopUsernames'), data.topUsernames);
  } else {
    summaryEl.textContent = 'No structured credential data could be parsed.';
  }
});

on('analysis:cookies', (data) => {
  const summaryEl = document.getElementById('dashCookieSummary');
  summaryEl.classList.remove('dash-loading');

  if (data.totalCookies > 0) {
    let summaryHtml = `${data.totalCookies.toLocaleString()} cookies across ${data.uniqueDomains} domains from ${data.fileCount} file(s) &mdash; <span class="cookie-valid">${data.totalValid.toLocaleString()} valid</span>, <span class="cookie-expired">${data.totalExpired.toLocaleString()} expired</span>`;
    if (data.sessionTokens > 0) {
      summaryHtml += ` &mdash; <span class="cookie-auth">${data.sessionTokens.toLocaleString()} session token${data.sessionTokens !== 1 ? 's' : ''}</span>`;
      if (data.validSessionTokens > 0) {
        summaryHtml += ` (<span class="cookie-auth-valid">${data.validSessionTokens.toLocaleString()} valid</span>)`;
      }
    }
    summaryEl.innerHTML = summaryHtml;
    renderCookieBarList(document.getElementById('dashTopCookieDomains'), data.topDomains);
  } else {
    summaryEl.textContent = 'No structured cookie data could be parsed.';
  }
});

function renderCookieBarList(container, items, maxItems = 10) {
  if (items.length === 0) {
    container.innerHTML = '<div class="dash-bar-empty">None found</div>';
    return;
  }
  const top = items.slice(0, maxItems);
  const maxCount = top[0].count;

  let html = '<div class="dash-bar-legend"><span class="dash-bar-legend-item"><span class="dash-bar-legend-swatch dash-bar-legend-valid"></span>Valid</span><span class="dash-bar-legend-item"><span class="dash-bar-legend-swatch dash-bar-legend-expired"></span>Expired</span></div>';

  html += top.map(item => {
    const validPct = Math.round((item.valid / maxCount) * 100);
    const expiredPct = Math.round((item.expired / maxCount) * 100);
    return `<div class="dash-bar-row dash-bar-row-stacked">
      <div class="dash-bar-fill dash-bar-fill-valid" style="width:${validPct}%"></div>
      <div class="dash-bar-fill dash-bar-fill-expired" style="width:${expiredPct}%; left:${validPct}%"></div>
      <span class="dash-bar-label">${escapeHtml(item.value)}</span>
      <span class="dash-bar-count">${item.count}</span>
    </div>`;
  }).join('');

  container.innerHTML = html;
}

on('analysis:sysinfo', (data) => {
  const navBtn = document.getElementById('navSysInfo');
  if (!data) return;

  navBtn.disabled = false;

  const body = document.getElementById('dashSysInfoBody');
  body.innerHTML = Object.entries(data.entries).map(([key, value]) =>
    `<div class="dash-kv-row">
      <span class="dash-kv-key">${escapeHtml(key)}</span>
      <span class="dash-kv-value">${escapeHtml(value)}</span>
    </div>`
  ).join('');

  // Show sysinfo actions toolbar
  document.getElementById('sysInfoActions').classList.remove('hidden');

  if (data.sourceFiles && data.sourceFiles.length > 0) {
    sysInfoSourcePath = data.sourceFiles[0];
    const openBtn = document.getElementById('sysInfoOpenBtn');
    openBtn.classList.remove('hidden');
    openBtn.textContent = `View Source: ${sysInfoSourcePath}`;
  }

  const iocs = extractIOCs(data.entries, data.sysinfoText);
  if (iocs) {
    const iocSection = document.getElementById('dashIOCs');
    const iocBody = document.getElementById('dashIOCBody');
    iocSection.classList.remove('hidden');
    iocBody.innerHTML = iocs.map(ioc =>
      `<div class="dash-ioc-item">
        <span class="dash-ioc-label">${escapeHtml(ioc.label)}</span>
        <span class="dash-ioc-value">${escapeHtml(ioc.value)}</span>
        <button class="dash-ioc-copy" title="Copy" data-copy="${escapeAttr(ioc.value)}">Copy</button>
      </div>`
    ).join('');

    iocBody.addEventListener('click', (e) => {
      const btn = e.target.closest('.dash-ioc-copy');
      if (!btn) return;
      copyToClipboard(btn.dataset.copy).then((ok) => {
        if (ok) {
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        }
      });
    });
  }
});

on('analysis:autofill', (data) => {
  const section = document.getElementById('dashAutofillIntel');
  const summaryEl = document.getElementById('dashAutofillSummary');
  const body = document.getElementById('dashAutofillBody');
  summaryEl.classList.remove('dash-loading');

  if (!data) {
    section.classList.add('hidden');
    return;
  }

  summaryEl.textContent = `${data.totalEntries} entries from ${data.fileCount} file(s)`;

  let html = '<div class="dash-autofill-categories">';

  if (data.emails.length > 0) {
    html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Emails</div>
      ${data.emails.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
  }
  if (data.phones.length > 0) {
    html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Phone Numbers</div>
      ${data.phones.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
  }
  if (data.names.length > 0) {
    html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Names</div>
      ${data.names.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
  }
  if (data.addresses.length > 0) {
    html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Addresses</div>
      ${data.addresses.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
  }
  if (data.other.length > 0) {
    html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Other</div>
      ${data.other.map(e => `<div class="dash-autofill-entry"><span class="dash-autofill-field">${escapeHtml(e.name)}:</span> ${escapeHtml(e.value)}</div>`).join('')}
    </div>`;
  }

  html += '</div>';
  body.innerHTML = html;
});

on('analysis:fingerprint', (data) => {
  const section = document.getElementById('dashFingerprint');
  const body = document.getElementById('dashFingerprintBody');

  if (!data) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');

  const confidenceLabel = data.confidence.charAt(0).toUpperCase() + data.confidence.slice(1) + ' confidence';
  const signalsId = 'fingerprintSignals_' + Date.now();

  body.innerHTML = `
    <div>
      <div class="dash-fingerprint-result">
        <span class="dash-fingerprint-badge">${escapeHtml(data.family)}</span>
        <span class="dash-fingerprint-confidence">
          <span class="dash-fingerprint-dot dash-fingerprint-dot-${data.confidence}"></span>
          ${escapeHtml(confidenceLabel)}
        </span>
      </div>
      <div class="dash-fingerprint-signals">
        <button class="dash-fingerprint-toggle" id="${signalsId}Btn">&#9656; Matched signals (${data.matchedSignals.length})</button>
        <ul class="dash-fingerprint-list" id="${signalsId}">
          ${data.matchedSignals.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
        </ul>
      </div>
    </div>`;

  const toggleBtn = document.getElementById(signalsId + 'Btn');
  const signalList = document.getElementById(signalsId);
  toggleBtn.addEventListener('click', () => {
    const expanded = signalList.classList.toggle('expanded');
    toggleBtn.innerHTML = (expanded ? '&#9662;' : '&#9656;') + ` Matched signals (${data.matchedSignals.length})`;
  });
});

on('analysis:screenshot', async (data) => {
  if (!data || !data.node) return;

  const section = document.getElementById('dashScreenshot');
  const body = document.getElementById('dashScreenshotBody');

  try {
    const content = await loadFileContent(data.node);
    if (!content) return;

    const ext = data.node.name.split('.').pop().toLowerCase();
    const mimeMap = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', bmp: 'image/bmp', gif: 'image/gif', webp: 'image/webp' };
    const mime = mimeMap[ext] || 'image/png';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);

    body.innerHTML = `<img class="dash-screenshot-img dash-screenshot-clickable" src="${url}" alt="Screenshot from log (click to enlarge)">`;
    section.classList.remove('hidden');

    const img = body.querySelector('.dash-screenshot-img');
    img.addEventListener('click', () => {
      const lightbox = document.createElement('div');
      lightbox.className = 'screenshot-lightbox';
      lightbox.innerHTML = `<img src="${url}" alt="Screenshot enlarged">`;
      lightbox.addEventListener('click', () => lightbox.remove());
      document.body.appendChild(lightbox);
    });
  } catch {
    // skip if screenshot fails to load
  }
});

// Global search

const globalSearchInput = document.getElementById('globalSearchInput');
const globalSearchBtn = document.getElementById('globalSearchBtn');
const searchResults = document.getElementById('searchResults');
const searchStatus = document.getElementById('searchStatus');

async function runGlobalSearch(query) {
  if (!query || !state.fileTree) return;

  const lowerQuery = query.toLowerCase();
  searchResults.innerHTML = '';
  searchStatus.textContent = 'Searching...';
  searchStatus.className = 'search-page-status dash-loading';

  const allNodes = [];
  collectFileNodes(state.fileTree, state.rootZipName, allNodes);

  const matches = [];
  let searched = 0;

  // Process files in batches for better performance
  const BATCH = SEARCH_BATCH_SIZE;
  for (let batchStart = 0; batchStart < allNodes.length; batchStart += BATCH) {
    const batch = allNodes.slice(batchStart, batchStart + BATCH);
    const batchPromises = batch.map(async ({ node, path }) => {
      const nameMatch = node.name.toLowerCase().includes(lowerQuery);
      let contentMatches = [];
      const hasHint = node._passwordFileHint || node._cookieFileHint || node._autofillHint || node._historyHint || node._sysInfoHint;
      if (node.previewable || hasHint) {
        try {
          const content = await loadFileContent(node);
          if (content) {
            const text = new TextDecoder('utf-8').decode(content);
            const lines = text.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].toLowerCase().includes(lowerQuery)) {
                contentMatches.push({ lineNum: i + 1, line: lines[i] });
                if (contentMatches.length >= MAX_SEARCH_MATCHES_PER_FILE) break;
              }
            }
          }
        } catch {
          // skip unreadable files
        }
      }
      return { node, path, nameMatch, contentMatches };
    });

    const results = await Promise.all(batchPromises);
    for (const result of results) {
      searched++;
      if (result.nameMatch || result.contentMatches.length > 0) {
        matches.push(result);
      }
    }

    // Yield to UI between batches
    searchStatus.textContent = `Searching... (${searched}/${allNodes.length} files)`;
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  searchStatus.classList.remove('dash-loading');

  if (matches.length === 0) {
    searchStatus.textContent = `No results for "${query}" (searched ${allNodes.length} files)`;
    return;
  }

  searchStatus.textContent = `${matches.length} file(s) matched "${query}" (searched ${allNodes.length} files)`;

  function cleanDisplayPath(fullPath) {
    let cleaned = fullPath;
    if (state.rootZipName && cleaned.startsWith(state.rootZipName + '/')) {
      cleaned = cleaned.slice(state.rootZipName.length + 1);
    }
    const archiveBase = (state.rootZipName || '').replace(/\.(zip|7z|rar|tar|tar\.gz|tgz)$/i, '');
    if (archiveBase && cleaned.startsWith(archiveBase + '/')) {
      cleaned = cleaned.slice(archiveBase.length + 1);
    }
    return cleaned || fullPath;
  }

  function getPathSegments(fullPath) {
    let rel = fullPath;
    if (state.rootZipName && rel.startsWith(state.rootZipName + '/')) {
      rel = rel.slice(state.rootZipName.length + 1);
    }
    return rel.split('/').filter(s => s);
  }

  searchResults.innerHTML = matches.map((m, idx) => {
    const displayPath = cleanDisplayPath(m.path);
    let html = `<div class="search-result-item">
      <div class="search-result-path search-result-clickable" data-result-idx="${idx}">${escapeHtml(displayPath)}</div>`;

    if (m.contentMatches.length > 0) {
      html += '<div class="search-result-lines">';
      for (const cm of m.contentMatches) {
        const escaped = escapeHtml(cm.line.trim());
        const lowerEscaped = escaped.toLowerCase();
        const lowerQ = escapeHtml(query).toLowerCase();
        const highlightIdx = lowerEscaped.indexOf(lowerQ);
        let highlighted = escaped;
        if (highlightIdx >= 0) {
          highlighted = escaped.substring(0, highlightIdx) +
            '<mark class="search-highlight">' + escaped.substring(highlightIdx, highlightIdx + lowerQ.length) + '</mark>' +
            escaped.substring(highlightIdx + lowerQ.length);
        }
        html += `<div class="search-result-line"><span class="search-result-linenum">${cm.lineNum}</span>${highlighted}</div>`;
      }
      html += '</div>';
    }

    html += '</div>';
    return html;
  }).join('');

  searchResults.querySelectorAll('.search-result-clickable').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.resultIdx, 10);
      const match = matches[idx];
      if (!match) return;

      const segments = getPathSegments(match.path);
      const fileName = segments.pop();
      const folderPath = segments;

      navigateTo(folderPath);
      navigateToPage('browser');

      emit('preview:open', {
        name: match.node.name,
        size: match.node.size,
        path: folderPath,
      });
    });
  });
}

globalSearchBtn.addEventListener('click', () => {
  runGlobalSearch(globalSearchInput.value.trim());
});

globalSearchInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    runGlobalSearch(globalSearchInput.value.trim());
  }
});

// File handling

async function handleFiles(files) {
  const fileArray = Array.from(files);
  if (fileArray.length === 0) return;

  const isMultiFile = fileArray.length > 1 ||
    (fileArray.length === 1 && !isArchiveFile(fileArray[0].name));

  if (state.fileTree && state.isMultiFileMode) {
    await handleAddMoreFiles(fileArray);
    return;
  }

  resetState();
  setMultiFileMode(isMultiFile);

  dropZone.style.display = 'none';
  uploadInfo.style.display = 'none';
  resetZone.classList.add('visible');

  const addMoreBtn = document.getElementById('addMoreBtn');
  if (isMultiFile) {
    const totalSize = fileArray.reduce((sum, f) => sum + f.size, 0);
    document.getElementById('currentFileName').textContent =
      fileArray.length === 1 ? fileArray[0].name : `${fileArray.length} files`;
    document.getElementById('currentFileSize').textContent = formatBytes(totalSize);
    addMoreBtn.classList.remove('hidden');
  } else {
    document.getElementById('currentFileName').textContent = fileArray[0].name;
    document.getElementById('currentFileSize').textContent = formatBytes(fileArray[0].size);
    addMoreBtn.classList.add('hidden');
  }

  results.classList.remove('visible');
  document.getElementById('errorList').classList.remove('visible');
  loading.classList.add('visible');

  try {
    if (isMultiFile) {
      const needsTypeSelection = await addFilesToTree(fileArray);
      await processTypeSelectionQueue(needsTypeSelection);
      emit('extracted');
    } else {
      await extractFile(fileArray[0]);
    }
  } catch (err) {
    loading.classList.remove('visible');
    showNotification(`Failed to process files: ${err.message}`, 'error');
    resetUI();
  }
}

// Add more files

async function handleAddMoreFiles(files) {
  const fileArray = Array.from(files);
  if (fileArray.length === 0) return;

  loading.classList.add('visible');

  try {
    const needsTypeSelection = await addFilesToTree(fileArray);
    await processTypeSelectionQueue(needsTypeSelection);

    const totalFiles = state.flatFiles.filter(f => f.type === 'file').length;
    const totalSize = state.flatFiles.reduce((sum, f) => sum + (f.size || 0), 0);
    document.getElementById('currentFileName').textContent = `${totalFiles} files`;
    document.getElementById('currentFileSize').textContent = formatBytes(totalSize);

    loading.classList.remove('visible');
    runAnalysis(state.fileTree, state.rootZipName);
    emit('reanalyze');
    showNotification(`Added ${fileArray.length} file(s). Analysis updated.`, 'info');
  } catch (err) {
    loading.classList.remove('visible');
    showNotification(`Failed to add files: ${err.message}`, 'error');
  }
}

// Manual type selection queue

async function processTypeSelectionQueue(files) {
  for (let i = 0; i < files.length; i++) {
    const { file, node } = files[i];
    const remaining = files.length - i - 1;

    const selectedType = await promptForFileType(file.name, remaining);
    applyManualType(node, selectedType);
    setManualType(file.name, selectedType);
  }

  if (files.length > 0 && state.fileTree) {
    state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
  }
}

// Reset

function resetUI() {
  resetState();
  dropZone.style.display = '';
  uploadInfo.style.display = '';
  resetZone.classList.remove('visible');
  results.classList.remove('visible');
  loading.classList.remove('visible');
  fileInput.value = '';
  document.getElementById('addMoreInput').value = '';
  document.getElementById('addMoreBtn').classList.add('hidden');

  document.getElementById('dashCredIntel').classList.add('hidden');
  document.getElementById('dashCookieIntel').classList.add('hidden');
  document.getElementById('overviewNoData').classList.add('hidden');
  document.getElementById('dashCredSummary').classList.add('dash-loading');
  document.getElementById('dashCredSummary').textContent = 'Analyzing credential files...';
  document.getElementById('dashCookieSummary').classList.add('dash-loading');
  document.getElementById('dashCookieSummary').textContent = 'Analyzing cookie files...';

  document.getElementById('navSysInfo').disabled = true;
  document.getElementById('dashSysInfoBody').innerHTML =
    '<div class="no-data" id="sysInfoNoData">No system information files detected.</div>';

  document.getElementById('dashIOCs').classList.add('hidden');
  document.getElementById('dashIOCBody').innerHTML = '';

  document.getElementById('dashFingerprint').classList.add('hidden');
  document.getElementById('dashFingerprintBody').innerHTML = '';

  document.getElementById('dashScreenshot').classList.add('hidden');
  document.getElementById('dashScreenshotBody').innerHTML = '';

  document.getElementById('dashAutofillIntel').classList.add('hidden');
  document.getElementById('dashExtraIntel').classList.add('hidden');
  document.getElementById('dashExtraBody').innerHTML = '';
  document.getElementById('dashAutofillSummary').classList.add('dash-loading');
  document.getElementById('dashAutofillSummary').textContent = 'Analyzing autofill files...';
  document.getElementById('dashAutofillBody').innerHTML = '';

  document.getElementById('navSearch').disabled = true;
  document.getElementById('navBrowser').disabled = true;
  document.getElementById('navExports').disabled = true;
  document.getElementById('navTimeline').disabled = true;
  globalSearchInput.value = '';
  searchResults.innerHTML = '';
  searchStatus.textContent = '';

  document.getElementById('sysInfoOpenBtn').classList.add('hidden');
  document.getElementById('sysInfoActions').classList.add('hidden');
  sysInfoSourcePath = null;

  navigateToPage('overview');
}

// Export

function exportCSV() {
  const headers = ['Path', 'Name', 'Type', 'Size (bytes)', 'Depth', 'Is Nested Archive', 'Encrypted'];
  const rows = state.flatFiles.map(f => [
    f.path, f.name, f.type, f.size, f.depth,
    f.isNestedArchive ? 'Yes' : 'No',
    f.encrypted ? 'Yes' : 'No',
  ]);
  const csv = [headers, ...rows]
    .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    .join('\n');
  downloadBlob(csv, 'file-list.csv', 'text/csv');
}

function exportJSON() {
  const data = {
    exportedAt: new Date().toISOString(),
    totalFiles: state.flatFiles.filter(f => f.type === 'file').length,
    totalFolders: state.flatFiles.filter(f => f.type === 'directory').length,
    errors: state.errors,
    files: state.flatFiles,
  };
  downloadBlob(JSON.stringify(data, null, 2), 'file-list.json', 'application/json');
}

function exportCredentials() {
  const data = getPasswordsData();
  if (!data || data.rows.length === 0) {
    showNotification('No credential data available to export.', 'error');
    return;
  }

  const headers = ['Source File', ...data.headers];
  let csv = headers.map(escapeCSV).join(',') + '\n';
  for (const { row, source } of data.rows) {
    csv += [source, ...row].map(escapeCSV).join(',') + '\n';
  }

  downloadBlob(csv, 'all_credentials.csv', 'text/csv');
  showNotification(`Exported ${data.rows.length} credentials from ${data.fileCount} file(s).`, 'info');
}

// Drag & drop / file input

dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', (e) => {
  if (!dropZone.contains(e.relatedTarget)) {
    dropZone.classList.remove('drag-over');
  }
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const files = e.dataTransfer.files;
  if (files.length > 0) handleFiles(files);
});

fileInput.addEventListener('change', (e) => {
  const files = e.target.files;
  if (files.length > 0) handleFiles(files);
});

document.getElementById('addMoreBtn').addEventListener('click', () => {
  document.getElementById('addMoreInput').click();
});

document.getElementById('addMoreInput').addEventListener('change', (e) => {
  const files = e.target.files;
  if (files.length > 0) {
    handleAddMoreFiles(files);
    e.target.value = '';
  }
});

// Buttons

document.getElementById('resetBtn').addEventListener('click', resetUI);
document.getElementById('exportCsv').addEventListener('click', exportCSV);
document.getElementById('exportJson').addEventListener('click', exportJSON);
document.getElementById('exportCredentials').addEventListener('click', exportCredentials);

// Sysinfo actions
document.getElementById('sysInfoCopyAll').addEventListener('click', () => {
  const rows = document.querySelectorAll('#dashSysInfoBody .dash-kv-row');
  const text = Array.from(rows).map(r => {
    const key = r.querySelector('.dash-kv-key')?.textContent || '';
    const value = r.querySelector('.dash-kv-value')?.textContent || '';
    return `${key}: ${value}`;
  }).join('\n');
  copyToClipboard(text).then(ok => {
    if (ok) showNotification('System info copied to clipboard.');
  });
});

document.getElementById('sysInfoExportCsv').addEventListener('click', () => {
  const rows = document.querySelectorAll('#dashSysInfoBody .dash-kv-row');
  const escape = (s) => `"${String(s).replace(/"/g, '""')}"`;
  let csv = 'Key,Value\n';
  for (const r of rows) {
    const key = r.querySelector('.dash-kv-key')?.textContent || '';
    const value = r.querySelector('.dash-kv-value')?.textContent || '';
    csv += `${escape(key)},${escape(value)}\n`;
  }
  downloadBlob(csv, 'system_info.csv', 'text/csv');
});

document.getElementById('sysInfoOpenBtn').addEventListener('click', () => {
  if (!sysInfoSourcePath || !state.fileTree) return;

  function findNodeByName(node, name, path) {
    if (!node) return null;
    if (node.name === name && node.type === 'file') {
      return { node, path };
    }
    if (node.children) {
      for (const child of Object.values(node.children)) {
        const found = findNodeByName(child, name, [...path, child.name]);
        if (found) return found;
      }
    }
    return null;
  }

  const result = findNodeByName(state.fileTree, sysInfoSourcePath, []);
  if (result) {
    const folderPath = result.path.slice(0, -1);
    navigateTo(folderPath);
    navigateToPage('browser');
    emit('preview:open', {
      name: result.node.name,
      size: result.node.size,
      path: folderPath,
    });
  }
});

// Keyboard shortcuts

// Shortcuts modal
const shortcutsModal = document.getElementById('shortcutsModal');
document.getElementById('shortcutsClose').addEventListener('click', () => {
  shortcutsModal.classList.remove('visible');
});
shortcutsModal.addEventListener('click', (e) => {
  if (e.target === shortcutsModal) shortcutsModal.classList.remove('visible');
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (shortcutsModal.classList.contains('visible')) {
      shortcutsModal.classList.remove('visible');
      return;
    }
    const previewOverlay = document.getElementById('previewOverlay');
    const passwordModal = document.getElementById('passwordModal');
    if (previewOverlay.classList.contains('visible')) {
      closePreview();
    } else if (passwordModal.classList.contains('visible')) {
      closePasswordModal(null);
    }
  }
  // ? key opens shortcuts help (when not typing in an input)
  if (e.key === '?' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
    e.preventDefault();
    shortcutsModal.classList.toggle('visible');
  }
  if (e.key === 'Backspace' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
    const previewOverlay = document.getElementById('previewOverlay');
    const passwordModal = document.getElementById('passwordModal');
    if (!previewOverlay.classList.contains('visible') && !passwordModal.classList.contains('visible') && !shortcutsModal.classList.contains('visible')) {
      if (state.currentPath.length > 0) {
        e.preventDefault();
        navigateTo(state.currentPath.slice(0, -1));
      }
    }
  }
});

// Init (wrapped individually so one failure doesn't block the rest)

try { initPasswordModal(); } catch (e) { console.error('initPasswordModal failed:', e); }
try { initFileTypeModal(); } catch (e) { console.error('initFileTypeModal failed:', e); }
try { initColumnMapper(); } catch (e) { console.error('initColumnMapper failed:', e); }
try { initBrowser(); } catch (e) { console.error('initBrowser failed:', e); }
try { initPreview(); } catch (e) { console.error('initPreview failed:', e); }
try { initDataPages(); } catch (e) { console.error('initDataPages failed:', e); }
try { initExports(); } catch (e) { console.error('initExports failed:', e); }
try { initTimeline(); } catch (e) { console.error('initTimeline failed:', e); }
try { initIdentityGraph(); } catch (e) { console.error('initIdentityGraph failed:', e); }
try { initIdentityPage(); } catch (e) { console.error('initIdentityPage failed:', e); }

document.getElementById('sidebarToggle').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

// Dark mode toggle
const themeToggle = document.getElementById('themeToggle');
const savedTheme = localStorage.getItem('logAtlasTheme');
if (savedTheme === 'dark') {
  document.documentElement.setAttribute('data-theme', 'dark');
  themeToggle.textContent = 'Light';
}
themeToggle.addEventListener('click', (e) => {
  e.stopPropagation();
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  if (isDark) {
    document.documentElement.removeAttribute('data-theme');
    themeToggle.textContent = 'Dark';
    localStorage.setItem('logAtlasTheme', 'light');
  } else {
    document.documentElement.setAttribute('data-theme', 'dark');
    themeToggle.textContent = 'Light';
    localStorage.setItem('logAtlasTheme', 'dark');
  }
});
