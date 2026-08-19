import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { collectFileNodes, SHARED_TEXT_DECODER } from '../core/shared.js';
import { escapeHtml, isTextFile, looksLikeText } from '../core/utils.js';
import { LIMITS } from '../core/definitions/patterns.js';
import { navigateTo } from '../files/browser.js';
import { emitPreview, buildShowMoreButton, PAGE_SIZE } from '../pages/shared.js';

const TEXT_INDEX_CHAR_BUDGET = 16 * 1024 * 1024;

// Lowercased text per file, so repeat searches skip the decode + lowercase pass.
const textIndex = new Map();
let indexedChars = 0;

function clearTextIndex() {
  textIndex.clear();
  indexedChars = 0;
}

function getLowerText(node, content) {
  const cached = textIndex.get(node);
  if (cached !== undefined) return cached;

  const lower = SHARED_TEXT_DECODER.decode(content).toLowerCase();
  if (indexedChars + lower.length <= TEXT_INDEX_CHAR_BUDGET) {
    textIndex.set(node, lower);
    indexedChars += lower.length;
  }
  return lower;
}

function stripRootPrefix(fullPath) {
  let trimmed = fullPath;
  if (state.rootZipName && trimmed.startsWith(state.rootZipName + '/')) {
    trimmed = trimmed.slice(state.rootZipName.length + 1);
  }
  return trimmed;
}

function getPathSegments(fullPath) {
  return stripRootPrefix(fullPath).split('/').filter(Boolean);
}

// The path shown has to be the path clicking it navigates to, so both come
// from the same segments.
function cleanDisplayPath(fullPath) {
  return getPathSegments(fullPath).join('/') || fullPath;
}

// Highlight on the raw line, escape each fragment afterwards, so the marker can
// never land inside an entity produced by escaping.
function highlightLine(line, lowerQuery) {
  const lower = line.toLowerCase();
  const start = lowerQuery ? lower.indexOf(lowerQuery) : -1;
  if (start < 0 || lower.length !== line.length) return escapeHtml(line);

  const end = start + lowerQuery.length;
  return escapeHtml(line.slice(0, start))
    + `<mark class="search-highlight">${escapeHtml(line.slice(start, end))}</mark>`
    + escapeHtml(line.slice(end));
}

function buildResultHtml(match, idx, lowerQuery) {
  let html = `<div class="search-result-item">
      <div class="search-result-path search-result-clickable" data-result-idx="${idx}">${escapeHtml(cleanDisplayPath(match.path))}</div>`;

  if (match.contentMatches.length > 0) {
    html += '<div class="search-result-lines">';
    for (const cm of match.contentMatches) {
      html += `<div class="search-result-line"><span class="search-result-linenum">${cm.lineNum}</span>${highlightLine(cm.line.trim(), lowerQuery)}</div>`;
    }
    html += '</div>';
  }

  return html + '</div>';
}

export function initSearch(navigateToPage) {
  const globalSearchInput = document.getElementById('globalSearchInput');
  const globalSearchBtn = document.getElementById('globalSearchBtn');
  const searchResults = document.getElementById('searchResults');
  const searchStatus = document.getElementById('searchStatus');
  const searchHints = document.getElementById('searchHints');
  // #searchStatus rewrites itself once per batch; a live region on it would
  // queue a dozen progress readings ahead of the answer. Only the start and
  // the outcome are announced.
  const searchAnnouncer = document.createElement('div');
  searchAnnouncer.className = 'sr-only';
  searchAnnouncer.setAttribute('role', 'status');
  searchAnnouncer.setAttribute('aria-live', 'polite');
  searchStatus.insertAdjacentElement('afterend', searchAnnouncer);
  let searchRunId = 0;
  let currentMatches = [];
  let currentQuery = '';
  let shownResults = 0;

  function resetSearchUi() {
    // Cancels any scan still yielding between batches. Without this a slow
    // search over the previous case finished after the next one loaded and
    // painted its results, paths and count over the new case's page.
    searchRunId += 1;
    currentMatches = [];
    currentQuery = '';
    shownResults = 0;
    searchResults.innerHTML = '';
    searchStatus.textContent = '';
    searchStatus.className = 'search-page-status';
    searchHints?.classList.remove('hidden');
  }

  function renderMoreResults() {
    const end = Math.min(shownResults + PAGE_SIZE, currentMatches.length);
    let html = '';
    for (let idx = shownResults; idx < end; idx++) {
      html += buildResultHtml(currentMatches[idx], idx, currentQuery);
    }

    searchResults.querySelector('.data-show-more')?.remove();
    searchResults.insertAdjacentHTML('beforeend', html);
    shownResults = end;

    const remaining = currentMatches.length - shownResults;
    if (remaining > 0) {
      searchResults.insertAdjacentHTML('beforeend', buildShowMoreButton(remaining, 'search'));
    }
  }

  function hasStructuredSearchHint(node) {
    return Boolean(
      node._passwordFileHint
      || node._cookieFileHint
      || node._autofillHint
      || node._historyHint
      || node._sysInfoHint
    );
  }

  async function findContentMatches(node, lowerQuery, allowBinaryFallback) {
    const content = await loadFileContent(node);
    if (!(content instanceof Uint8Array)) return [];

    const isSearchableText = isTextFile(node.name) || looksLikeText(content);
    if (!isSearchableText && !allowBinaryFallback) return [];

    const lower = getLowerText(node, content);
    if (!lower.includes(lowerQuery)) return [];

    const matches = [];
    const lines = SHARED_TEXT_DECODER.decode(content).split('\n');
    const lowerLines = lower.split('\n');
    for (let i = 0; i < lowerLines.length; i++) {
      if (!lowerLines[i].includes(lowerQuery)) continue;
      matches.push({ lineNum: i + 1, line: lines[i] ?? lowerLines[i] });
      if (matches.length >= LIMITS.searchMatchesPerFile) break;
    }
    return matches;
  }

  async function runGlobalSearch(query) {
    const runId = ++searchRunId;
    if (!query || !state.fileTree) {
      resetSearchUi();
      return;
    }

    const lowerQuery = query.toLowerCase();
    resetSearchUi();
    searchHints?.classList.add('hidden');
    searchStatus.textContent = 'Searching...';
    searchStatus.className = 'search-page-status dash-loading';

    const allNodes = [];
    collectFileNodes(state.fileTree, state.rootZipName, allNodes);

    const matches = [];
    let searched = 0;

    const BATCH = LIMITS.searchBatchSize;
    for (let batchStart = 0; batchStart < allNodes.length; batchStart += BATCH) {
      if (runId !== searchRunId) return;
      const batch = allNodes.slice(batchStart, batchStart + BATCH);
      const batchPromises = batch.map(async ({ node, path }) => {
        const nameMatch = node.name.toLowerCase().includes(lowerQuery);
        let contentMatches = [];
        const hasHint = hasStructuredSearchHint(node);
        if (hasHint || isTextFile(node.name)) {
          try {
            contentMatches = await findContentMatches(node, lowerQuery, hasHint);
          } catch {
            // skip unreadable files
          }
        }
        return { node, path, nameMatch, contentMatches };
      });

      const results = await Promise.all(batchPromises);
      if (runId !== searchRunId) return;
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

    if (runId !== searchRunId) return;
    searchStatus.classList.remove('dash-loading');

    if (matches.length === 0) {
      searchStatus.textContent = `No results for "${query}" (searched ${allNodes.length} files)`;
      return;
    }

    searchStatus.textContent = `${matches.length} file(s) matched "${query}" (searched ${allNodes.length} files)`;

    currentMatches = matches;
    currentQuery = lowerQuery;
    shownResults = 0;
    renderMoreResults();
  }

  searchResults.addEventListener('click', (e) => {
    if (e.target.closest('.data-show-more')) {
      renderMoreResults();
      return;
    }

    const row = e.target.closest('.search-result-clickable');
    if (!row) return;

    const match = currentMatches[parseInt(row.dataset.resultIdx, 10)];
    if (!match) return;

    const segments = getPathSegments(match.path);
    segments.pop();

    navigateTo(segments);
    navigateToPage('browser');

    emitPreview(match.node, segments);
  });

  globalSearchBtn.addEventListener('click', () => {
    runGlobalSearch(globalSearchInput.value.trim());
  });

  globalSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      runGlobalSearch(globalSearchInput.value.trim());
    }
  });

  on('reset', () => {
    clearTextIndex();
    resetSearchUi();
  });
  on('extracted', () => {
    clearTextIndex();
    searchRunId += 1;
  });
  // Added files and retyped files change what a query would match. The index
  // stays — it is keyed by node, and a file's bytes never change — but the
  // answer on screen is now about a case that no longer exists.
  on('reanalyze', () => {
    const hadResults = searchStatus.textContent !== '';
    resetSearchUi();
    if (hadResults) {
      searchStatus.textContent = 'Case changed — run the search again';
      searchAnnouncer.textContent = searchStatus.textContent;
    }
  });
}
