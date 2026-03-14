import { state, emit } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { collectFileNodes, MAX_SEARCH_MATCHES_PER_FILE, SEARCH_BATCH_SIZE } from '../core/shared.js';
import { escapeHtml, isTextFile, looksLikeText } from '../core/utils.js';
import { navigateTo } from '../files/browser.js';

export function initSearch(navigateToPage) {
  const globalSearchInput = document.getElementById('globalSearchInput');
  const globalSearchBtn = document.getElementById('globalSearchBtn');
  const searchResults = document.getElementById('searchResults');
  const searchStatus = document.getElementById('searchStatus');
  const textDecoder = new TextDecoder('utf-8');
  let searchRunId = 0;

  function resetSearchUi() {
    searchResults.innerHTML = '';
    searchStatus.textContent = '';
    searchStatus.className = 'search-page-status';
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

    const text = textDecoder.decode(content);
    const matches = [];
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].toLowerCase().includes(lowerQuery)) continue;
      matches.push({ lineNum: i + 1, line: lines[i] });
      if (matches.length >= MAX_SEARCH_MATCHES_PER_FILE) break;
    }
    return matches;
  }

  function stripRootPrefix(fullPath) {
    let trimmed = fullPath;
    if (state.rootZipName && trimmed.startsWith(state.rootZipName + '/')) {
      trimmed = trimmed.slice(state.rootZipName.length + 1);
    }
    return trimmed;
  }

  async function runGlobalSearch(query) {
    const runId = ++searchRunId;
    if (!query || !state.fileTree) {
      resetSearchUi();
      return;
    }

    const lowerQuery = query.toLowerCase();
    resetSearchUi();
    searchStatus.textContent = 'Searching...';
    searchStatus.className = 'search-page-status dash-loading';

    const allNodes = [];
    collectFileNodes(state.fileTree, state.rootZipName, allNodes);

    const matches = [];
    let searched = 0;

    // Process files in batches for better performance
    const BATCH = SEARCH_BATCH_SIZE;
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

    function cleanDisplayPath(fullPath) {
      let cleaned = stripRootPrefix(fullPath);
      const archiveBase = (state.rootZipName || '').replace(/\.(zip|7z|rar|tar|tar\.gz|tgz)$/i, '');
      if (archiveBase && cleaned.startsWith(archiveBase + '/')) {
        cleaned = cleaned.slice(archiveBase.length + 1);
      }
      return cleaned || fullPath;
    }

    function getPathSegments(fullPath) {
      return stripRootPrefix(fullPath).split('/').filter(Boolean);
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
        segments.pop();
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

  // Return references needed by other modules
  return { globalSearchInput, searchResults, searchStatus };
}
