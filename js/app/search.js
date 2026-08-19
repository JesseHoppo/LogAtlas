import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { collectFileNodes, decodeNodeCached } from '../core/shared.js';
import { escapeHtml, isTextFile, looksLikeText, getFileExtension, isImageFile, isArchiveFile } from '../core/utils.js';
import { LIMITS } from '../core/definitions/patterns.js';
import { navigateTo } from '../files/browser.js';
import { isOfficeOpenXmlFile, extractOfficeOpenXmlPreview } from '../files/preview.js';
import { HINT_KEYS } from '../files/fileTypeRegistry.js';
import { countLabel, emitPreview, buildShowMoreButton, PAGE_SIZE } from '../pages/shared.js';

const TEXT_INDEX_CHAR_BUDGET = 16 * 1024 * 1024;

// Large archives arrive with a .txt split across `Name.txt [Part 1 of 2]`
// entries; the suffix hides the extension from every extension test.
const PART_SUFFIX = /\s*\[Part \d+ of \d+\]\s*$/i;

// Formats whose bytes are never plain text. Everything else reaches the byte
// sniff, so extension-less stealer output (LevelDB LOG/CURRENT, notes.dat) is
// read rather than assumed binary.
const OPAQUE_EXTENSIONS = new Set([
  'pdf',
  'doc', 'docx', 'docm', 'dot', 'dotx', 'dotm',
  'xls', 'xlsx', 'xlsm', 'xlt', 'xltx', 'xltm',
  'ppt', 'pptx', 'pptm', 'pot', 'potx', 'potm',
  'exe', 'dll', 'sys', 'msi', 'bin', 'dmg', 'iso', 'so', 'dylib',
  'mp3', 'mp4', 'avi', 'mov', 'mkv', 'wav', 'ogg', 'webm', 'flac',
  'ttf', 'otf', 'woff', 'woff2', 'eot',
]);

// A hinted file is read even when the leading bytes are binary — a cookie
// store keeps its hosts in plain text behind a binary header. Screenshots and
// whatever the victim had on their desktop carry no text to find.
const TEXT_HINT_KEYS = HINT_KEYS.filter(key => key !== '_screenshotHint' && key !== '_grabbedFileHint');

function isOpaqueToSearch(name) {
  if (isOfficeOpenXmlFile(name)) return false;
  return OPAQUE_EXTENSIONS.has(getFileExtension(name)) || isImageFile(name) || isArchiveFile(name);
}

// Lowercased text per file, so repeat searches skip the decode + lowercase pass.
const textIndex = new Map();
// A Word/Excel/PowerPoint file keeps its text as XML inside a zip, so the raw
// bytes match nothing. The extracted text is kept per file, since pulling it
// back out means re-reading the inner archive.
const officeIndex = new Map();
let indexedChars = 0;

function clearTextIndex() {
  textIndex.clear();
  officeIndex.clear();
  indexedChars = 0;
}

function budgetedSet(index, node, text) {
  if (indexedChars + text.length > TEXT_INDEX_CHAR_BUDGET) return;
  index.set(node, text);
  indexedChars += text.length;
}

function getLowerText(node, text) {
  const cached = textIndex.get(node);
  if (cached !== undefined) return cached;

  const lower = text.toLowerCase();
  budgetedSet(textIndex, node, lower);
  return lower;
}

// Null when the document could not be opened — a legacy .doc carrying an OOXML
// extension, or a file cut short by the archive.
async function getOfficeText(node, content) {
  const cached = officeIndex.get(node);
  if (cached !== undefined) return cached;

  let text;
  try {
    text = await extractOfficeOpenXmlPreview(content, node.name) || '';
  } catch {
    return null;
  }
  budgetedSet(officeIndex, node, text);
  return text;
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
      <div class="search-result-path search-result-clickable" role="button" tabindex="0" data-result-idx="${idx}">${escapeHtml(cleanDisplayPath(match.path))}</div>`;

  if (match.contentMatches.length > 0) {
    html += '<div class="search-result-lines">';
    for (const cm of match.contentMatches) {
      html += `<div class="search-result-line"><span class="search-result-linenum">${cm.lineNum}</span>${highlightLine(cm.line.trim(), lowerQuery)}</div>`;
    }
    if (match.totalMatches > match.contentMatches.length) {
      html += `<div class="search-result-line"><span class="search-result-linenum">…</span>showing ${match.contentMatches.length.toLocaleString()} of ${countLabel(match.totalMatches, 'matching line')} — open the file for the rest</div>`;
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

  // The rows and the pager are flat siblings here, so new rows go in above the
  // button and the button itself is kept — removing it drops the focus of
  // whoever is paging by keyboard.
  function renderMoreResults() {
    const end = Math.min(shownResults + PAGE_SIZE, currentMatches.length);
    let html = '';
    for (let idx = shownResults; idx < end; idx++) {
      html += buildResultHtml(currentMatches[idx], idx, currentQuery);
    }
    shownResults = end;
    const remaining = currentMatches.length - shownResults;

    const btn = searchResults.querySelector('.data-show-more');
    if (!btn) {
      searchResults.insertAdjacentHTML('beforeend', html);
      if (remaining > 0) {
        searchResults.insertAdjacentHTML('beforeend', buildShowMoreButton(remaining, 'search'));
      }
      return;
    }

    btn.insertAdjacentHTML('beforebegin', html);
    if (remaining > 0) {
      btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE).toLocaleString()} more (${remaining.toLocaleString()} remaining)`;
    } else {
      btn.remove();
    }
  }

  function hasStructuredSearchHint(node) {
    return TEXT_HINT_KEYS.some(key => node[key]);
  }

  // Null when the file was never read as text, so the status line can say how
  // much of the archive the search actually looked inside.
  async function findContentMatches(node, lowerQuery, allowBinaryFallback) {
    const content = await loadFileContent(node);
    if (!(content instanceof Uint8Array)) return null;

    let text;
    if (isOfficeOpenXmlFile(node.name)) {
      text = await getOfficeText(node, content);
      if (text === null) return null;
    } else {
      const isSearchableText = isTextFile(node.name.replace(PART_SUFFIX, '')) || looksLikeText(content);
      if (!isSearchableText && !allowBinaryFallback) return null;
      text = decodeNodeCached(node, content);
    }

    const lower = getLowerText(node, text);
    if (!lower.includes(lowerQuery)) return { matches: [], total: 0 };

    const matches = [];
    let total = 0;
    const lines = text.split('\n');
    const lowerLines = lower.split('\n');
    for (let i = 0; i < lowerLines.length; i++) {
      if (!lowerLines[i].includes(lowerQuery)) continue;
      total++;
      if (matches.length < LIMITS.searchMatchesPerFile) {
        matches.push({ lineNum: i + 1, line: lines[i] ?? lowerLines[i] });
      }
    }
    return { matches, total };
  }

  async function runGlobalSearch(query) {
    // The reset cancels the previous run by bumping the id, so this run has to
    // take its own id afterwards or it cancels itself.
    resetSearchUi();
    if (!query || !state.fileTree) return;
    const runId = searchRunId;

    const lowerQuery = query.toLowerCase();
    searchHints?.classList.add('hidden');
    searchStatus.textContent = 'Searching...';
    searchStatus.className = 'search-page-status dash-loading';
    searchAnnouncer.textContent = `Searching for "${query}"`;

    const allNodes = [];
    collectFileNodes(state.fileTree, state.rootZipName, allNodes);

    const matches = [];
    let searched = 0;
    let readAsText = 0;

    const BATCH = LIMITS.searchBatchSize;
    for (let batchStart = 0; batchStart < allNodes.length; batchStart += BATCH) {
      if (runId !== searchRunId) return;
      const batch = allNodes.slice(batchStart, batchStart + BATCH);
      const batchPromises = batch.map(async ({ node, path }) => {
        const nameMatch = node.name.toLowerCase().includes(lowerQuery);
        let found = null;
        const hasHint = hasStructuredSearchHint(node);
        if (hasHint || !isOpaqueToSearch(node.name)) {
          try {
            found = await findContentMatches(node, lowerQuery, hasHint);
          } catch {
            // skip unreadable files
          }
        }
        return {
          node,
          path,
          nameMatch,
          contentMatches: found ? found.matches : [],
          totalMatches: found ? found.total : 0,
          readAsText: found !== null,
        };
      });

      const results = await Promise.all(batchPromises);
      if (runId !== searchRunId) return;
      for (const result of results) {
        searched++;
        if (result.readAsText) readAsText++;
        if (result.nameMatch || result.contentMatches.length > 0) {
          matches.push(result);
        }
      }

      // Yield to UI between batches
      searchStatus.textContent = `Searching... (${searched.toLocaleString()}/${allNodes.length.toLocaleString()} files)`;
      await new Promise(resolve => setTimeout(resolve, 0));
    }

    if (runId !== searchRunId) return;
    searchStatus.classList.remove('dash-loading');

    // Only the files whose bytes were decoded were searched for the query; the
    // rest matched on their name or not at all.
    const coverage = `read the contents of ${readAsText.toLocaleString()} of ${countLabel(allNodes.length, 'file')}`;

    if (matches.length === 0) {
      searchStatus.textContent = `No results for "${query}" (${coverage})`;
      searchAnnouncer.textContent = searchStatus.textContent;
      return;
    }

    searchStatus.textContent = `${countLabel(matches.length, 'file')} matched "${query}" (${coverage})`;
    searchAnnouncer.textContent = searchStatus.textContent;

    currentMatches = matches;
    currentQuery = lowerQuery;
    shownResults = 0;
    renderMoreResults();
  }

  function openResult(row) {
    const match = currentMatches[parseInt(row.dataset.resultIdx, 10)];
    if (!match) return;

    const segments = getPathSegments(match.path);
    segments.pop();

    navigateTo(segments);
    navigateToPage('browser');

    emitPreview(match.node, segments);
  }

  searchResults.addEventListener('click', (e) => {
    if (e.target.closest('.data-show-more')) {
      renderMoreResults();
      return;
    }

    const row = e.target.closest('.search-result-clickable');
    if (row) openResult(row);
  });

  // The pager is a real button and raises its own click from the keyboard;
  // only the result rows need the key handling.
  searchResults.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const row = e.target.closest('.search-result-clickable');
    if (!row) return;
    e.preventDefault();
    openResult(row);
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
