// File preview modal

import { state, on, emit } from '../core/state.js';
import { getNodeAtPath, loadFileContent, applyManualType, flattenTree } from './extractor.js';
import {
  escapeHtml,
  formatBytes,
  getFileIcon,
  getFileExtension,
  getMimeType,
  isTextFile,
  isImageFile,
  looksLikeText,
  syntaxHighlightJSON,
  MAX_PREVIEW_SIZE,
} from '../core/utils.js';
import { LIMITS } from '../core/definitions/patterns.js';
import { toCSV } from '../transforms/shared.js';
import { downloadBlob, copyToClipboard, SHARED_TEXT_DECODER } from '../core/shared.js';
import { openColumnMapper } from './columnMapper.js';
import { buildFileTypeOptionsHtml, getFileTypeLabel, getNodeFileType } from './fileTypeRegistry.js';
import {
  canOfferTransformAction,
  canTransformStructuredFile,
  getColumnMappingFileType,
  parseStructuredFile,
} from './structuredTransforms.js';

let elOverlay;
let elBody;
let elActions;
let elSearchBar;
let elSearchInput;
let elSearchCount;
let elSearchPrev;
let elSearchNext;
let elTitleIcon;
let elTitleName;
let elTitleSize;
let elSetTypeBtn;
let elDownloadBtn;
let elCopyBtn;
let currentFile = null;
let currentContent = null;
let currentNode = null;
let currentDecodedText = null;
let currentParsedData = null;
let activeBlobUrls = [];
let previewRequestId = 0;
let showingAllTextLines = false;

let searchMatches = [];
let currentMatchIndex = -1;

const ROW_CAP = LIMITS.previewRowCap;
const LINE_CAP = LIMITS.previewLineCap;
const WORD_OPEN_XML_EXTENSIONS = new Set(['docx', 'docm', 'dotx', 'dotm']);
const SHEET_OPEN_XML_EXTENSIONS = new Set(['xlsx', 'xlsm', 'xltx', 'xltm']);
const SLIDE_OPEN_XML_EXTENSIONS = new Set(['pptx', 'pptm', 'potx', 'potm']);

function isOfficeOpenXmlFile(fileName) {
  const ext = getFileExtension(fileName);
  return WORD_OPEN_XML_EXTENSIONS.has(ext) || SHEET_OPEN_XML_EXTENSIONS.has(ext) || SLIDE_OPEN_XML_EXTENSIONS.has(ext);
}

function decodeXmlEntities(text) {
  return String(text || '')
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function normaliseExtractedText(text) {
  return String(text || '')
    .replace(/\r/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function parseXmlDocument(xmlText) {
  const doc = new DOMParser().parseFromString(String(xmlText || ''), 'application/xml');
  return doc.getElementsByTagName('parsererror').length === 0 ? doc : null;
}

function collectXmlText(node) {
  if (!node || !node.childNodes) return '';

  let text = '';
  for (const child of Array.from(node.childNodes)) {
    if (child.nodeType === 3) {
      if (/\S/.test(child.textContent || '')) text += child.textContent;
      continue;
    }
    if (child.nodeType !== 1) continue;

    const localName = child.localName || child.nodeName.split(':').pop();
    if (localName === 'tab') {
      text += '\t';
      continue;
    }
    if (localName === 'br' || localName === 'cr') {
      text += '\n';
      continue;
    }

    text += collectXmlText(child);
  }

  return decodeXmlEntities(text);
}

async function readZipEntryText(entry, budgetState) {
  const size = entry.uncompressedSize || 0;
  if (size > LIMITS.ooxmlInnerMemberMaxBytes) return null;
  if (budgetState && budgetState.totalDecoded + size > LIMITS.ooxmlTotalMaxBytes) return null;
  const data = await entry.getData(new zip.Uint8ArrayWriter());
  if (budgetState) budgetState.totalDecoded += size;
  return SHARED_TEXT_DECODER.decode(data);
}

async function extractWordOpenXmlPreview(entryMap, budgetState) {
  const mainEntry = entryMap.get('word/document.xml');
  if (!mainEntry) return '';

  const text = await readZipEntryText(mainEntry, budgetState);
  if (text === null) return '';
  const doc = parseXmlDocument(text);
  if (!doc) return '';

  const paragraphs = Array.from(doc.getElementsByTagNameNS('*', 'p'));
  const blocks = [];
  for (const paragraph of paragraphs) {
    const text = normaliseExtractedText(collectXmlText(paragraph));
    if (text) blocks.push(text);
  }

  return blocks.join('\n\n');
}

async function extractSlideOpenXmlPreview(entryMap, budgetState) {
  const slideEntries = Array.from(entryMap.entries())
    .filter(([name]) => /^ppt\/slides\/slide\d+\.xml$/i.test(name))
    .sort((a, b) => {
      const aNum = Number((a[0].match(/slide(\d+)\.xml/i) || [])[1] || 0);
      const bNum = Number((b[0].match(/slide(\d+)\.xml/i) || [])[1] || 0);
      return aNum - bNum;
    });

  const blocks = [];
  for (const [name, entry] of slideEntries) {
    const text = await readZipEntryText(entry, budgetState);
    if (text === null) return '';
    const doc = parseXmlDocument(text);
    if (!doc) continue;

    const textNodes = Array.from(doc.getElementsByTagNameNS('*', 't'))
      .map(node => normaliseExtractedText(node.textContent || ''))
      .filter(Boolean);

    if (textNodes.length === 0) continue;

    const slideNumber = Number((name.match(/slide(\d+)\.xml/i) || [])[1] || blocks.length + 1);
    blocks.push(`Slide ${slideNumber}\n${textNodes.join('\n')}`);
  }

  return blocks.join('\n\n');
}

function readWorkbookRelationships(relsText) {
  const relsDoc = parseXmlDocument(relsText);
  if (!relsDoc) return new Map();

  const map = new Map();
  const relNodes = Array.from(relsDoc.getElementsByTagNameNS('*', 'Relationship'));
  for (const rel of relNodes) {
    const id = rel.getAttribute('Id');
    const target = rel.getAttribute('Target');
    if (!id || !target) continue;
    const normalised = target.replace(/^\/+/, '').replace(/^xl\//i, '');
    map.set(id, `xl/${normalised}`);
  }
  return map;
}

function extractSharedStrings(sharedStringsText) {
  const sharedDoc = parseXmlDocument(sharedStringsText);
  if (!sharedDoc) return [];

  return Array.from(sharedDoc.getElementsByTagNameNS('*', 'si'))
    .map(node => normaliseExtractedText(collectXmlText(node)));
}

function readWorkbookSheets(workbookText, relMap) {
  const workbookDoc = parseXmlDocument(workbookText);
  if (!workbookDoc) return [];

  const sheets = [];
  const sheetNodes = Array.from(workbookDoc.getElementsByTagNameNS('*', 'sheet'));
  for (const sheet of sheetNodes) {
    const name = sheet.getAttribute('name') || 'Sheet';
    const relId = sheet.getAttribute('r:id') || sheet.getAttributeNS('http://schemas.openxmlformats.org/officeDocument/2006/relationships', 'id');
    const target = relMap.get(relId || '');
    if (!target) continue;
    sheets.push({ name, target });
  }
  return sheets;
}

function extractWorksheetValues(sheetText, sharedStrings) {
  const sheetDoc = parseXmlDocument(sheetText);
  if (!sheetDoc) return [];

  const values = [];
  const cellNodes = Array.from(sheetDoc.getElementsByTagNameNS('*', 'c'));
  for (const cell of cellNodes) {
    if (values.length >= 200) break;

    const ref = cell.getAttribute('r') || `Cell ${values.length + 1}`;
    const type = cell.getAttribute('t') || '';
    let value = '';

    if (type === 'inlineStr') {
      const inlineNode = cell.getElementsByTagNameNS('*', 'is')[0];
      value = normaliseExtractedText(collectXmlText(inlineNode));
    } else {
      const valueNode = cell.getElementsByTagNameNS('*', 'v')[0];
      const rawValue = valueNode ? String(valueNode.textContent || '').trim() : '';
      if (!rawValue) continue;

      if (type === 's') {
        value = sharedStrings[Number(rawValue)] || '';
      } else if (type === 'b') {
        value = rawValue === '1' ? 'TRUE' : 'FALSE';
      } else {
        value = rawValue;
      }
    }

    value = normaliseExtractedText(value);
    if (!value) continue;
    values.push(`${ref}\t${value}`);
  }

  return values;
}

async function extractSheetOpenXmlPreview(entryMap, budgetState) {
  const workbookEntry = entryMap.get('xl/workbook.xml');
  if (!workbookEntry) return '';

  const workbookText = await readZipEntryText(workbookEntry, budgetState);
  if (workbookText === null) return '';

  const relsEntry = entryMap.get('xl/_rels/workbook.xml.rels');
  const relsText = relsEntry ? await readZipEntryText(relsEntry, budgetState) : null;
  const relMap = relsText === null ? new Map() : readWorkbookRelationships(relsText);

  const sharedStringsEntry = entryMap.get('xl/sharedStrings.xml');
  const sharedStringsText = sharedStringsEntry ? await readZipEntryText(sharedStringsEntry, budgetState) : null;
  const sharedStrings = sharedStringsText === null ? [] : extractSharedStrings(sharedStringsText);

  let sheets = readWorkbookSheets(workbookText, relMap);
  if (sheets.length === 0) {
    sheets = Array.from(entryMap.keys())
      .filter(name => /^xl\/worksheets\/sheet\d+\.xml$/i.test(name))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      .map((target, index) => ({ name: `Sheet ${index + 1}`, target }));
  }

  const blocks = [];
  for (const sheet of sheets) {
    const entry = entryMap.get(sheet.target);
    if (!entry) continue;

    const sheetText = await readZipEntryText(entry, budgetState);
    if (sheetText === null) return '';
    const values = extractWorksheetValues(sheetText, sharedStrings);
    if (values.length === 0) continue;
    blocks.push(`${sheet.name}\n${values.join('\n')}`);
  }

  return blocks.join('\n\n');
}

async function extractOfficeOpenXmlPreview(content, fileName) {
  const ext = getFileExtension(fileName);
  const reader = new zip.ZipReader(new zip.BlobReader(new Blob([content])));
  try {
    const entries = await reader.getEntries();
    const entryMap = new Map(entries.filter(entry => !entry.directory).map(entry => [entry.filename, entry]));
    const budgetState = { totalDecoded: 0 };

    if (WORD_OPEN_XML_EXTENSIONS.has(ext)) return extractWordOpenXmlPreview(entryMap, budgetState);
    if (SHEET_OPEN_XML_EXTENSIONS.has(ext)) return extractSheetOpenXmlPreview(entryMap, budgetState);
    if (SLIDE_OPEN_XML_EXTENSIONS.has(ext)) return extractSlideOpenXmlPreview(entryMap, budgetState);
    return '';
  } finally {
    try {
      await reader.close();
    } catch (_) {}
  }
}

// Blob URL lifecycle

function trackBlobUrl(url) {
  activeBlobUrls.push(url);
}

function revokeAllBlobUrls() {
  for (const url of activeBlobUrls) {
    URL.revokeObjectURL(url);
  }
  activeBlobUrls = [];
}

// Type label for the Set Type button

function updateTypeButton() {
  if (!elSetTypeBtn) return;
  const label = getNodeFileType(currentNode);
  if (label) {
    elSetTypeBtn.textContent = getFileTypeLabel(label);
    elSetTypeBtn.className = 'preview-btn preview-type-btn preview-type-' + label;
  } else {
    elSetTypeBtn.textContent = 'Set Type';
    elSetTypeBtn.className = 'preview-btn preview-type-btn';
  }
}

function showPreviewTypeMenu() {
  if (!currentNode) return;

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.innerHTML = `
    <div class="modal modal-filetype">
      <h3>Set File Type</h3>
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
    applyManualType(currentNode, btn.dataset.type);
    if (state.fileTree) {
      state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
    }
    close();
    updateTypeButton();
    emit('reanalyze');
  });

  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) close();
  });
}

// In-preview text search

function clearPreviewSearch(resetInput = true) {
  if (resetInput && elSearchInput) elSearchInput.value = '';
  if (elSearchCount) elSearchCount.textContent = '';
  searchMatches = [];
  currentMatchIndex = -1;
}

function showSearchBar(show, { reset = false } = {}) {
  if (!elSearchBar) return;
  elSearchBar.classList.toggle('hidden', !show);
  if (reset) clearPreviewSearch();
}

function resetPreviewActions() {
  if (elDownloadBtn) elDownloadBtn.textContent = 'Download';
  if (elCopyBtn) {
    elCopyBtn.classList.add('hidden');
    elCopyBtn.textContent = 'Copy';
  }
}

function getPreviewDisplayText(text, fileName) {
  if (getFileExtension(fileName) !== 'json') return text;

  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch (_) {
    return text;
  }
}

function getVisiblePreviewText() {
  if (currentDecodedText == null) return '';
  const displayText = getPreviewDisplayText(currentDecodedText, currentFile?.name || '');
  return showingAllTextLines
    ? displayText
    : displayText.split('\n').slice(0, LINE_CAP).join('\n');
}

function formatPreviewTextContent(text, fileName, lineCap = null) {
  const displayText = getPreviewDisplayText(text, fileName);
  const limitedText = lineCap == null ? displayText : displayText.split('\n').slice(0, lineCap).join('\n');

  if (getFileExtension(fileName) !== 'json') {
    return escapeHtml(limitedText);
  }
  return syntaxHighlightJSON(limitedText);
}

function restoreFormattedPreviewText(textContent, countLabel = '') {
  const fileName = currentFile?.name || '';
  textContent.innerHTML = formatPreviewTextContent(getVisiblePreviewText(), fileName);
  elSearchCount.textContent = countLabel;
}

function performSearch(query) {
  const textContent = elBody.querySelector('.preview-text-content');
  if (!textContent || currentDecodedText == null) return;

  searchMatches = [];
  currentMatchIndex = -1;

  if (!query || query.length < 1) {
    restoreFormattedPreviewText(textContent, '');
    return;
  }

  const visibleText = getVisiblePreviewText();
  const lowerText = visibleText.toLowerCase();
  const lowerQuery = query.toLowerCase();
  let idx = 0;
  const matchPositions = [];
  while ((idx = lowerText.indexOf(lowerQuery, idx)) !== -1) {
    matchPositions.push(idx);
    idx += 1;
  }

  if (matchPositions.length === 0) {
    restoreFormattedPreviewText(textContent, '0 / 0');
    return;
  }

  let html = '';
  let lastEnd = 0;
  for (let i = 0; i < matchPositions.length; i++) {
    const start = matchPositions[i];
    const end = start + query.length;
    html += escapeHtml(visibleText.substring(lastEnd, start));
    const matchClass = i === 0 ? 'preview-search-match preview-search-match-current' : 'preview-search-match';
    html += `<span class="${matchClass}">${escapeHtml(visibleText.substring(start, end))}</span>`;
    lastEnd = end;
  }
  html += escapeHtml(visibleText.substring(lastEnd));

  textContent.innerHTML = html;
  searchMatches = textContent.querySelectorAll('.preview-search-match');
  currentMatchIndex = 0;
  elSearchCount.textContent = `1 / ${matchPositions.length}`;
  scrollToCurrentMatch();
}

function scrollToCurrentMatch() {
  if (searchMatches.length === 0 || currentMatchIndex < 0) return;
  searchMatches.forEach(el => el.classList.remove('preview-search-match-current'));
  const currentEl = searchMatches[currentMatchIndex];
  if (currentEl) {
    currentEl.classList.add('preview-search-match-current');
    currentEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  elSearchCount.textContent = `${currentMatchIndex + 1} / ${searchMatches.length}`;
}

function navigateMatch(direction) {
  if (searchMatches.length === 0) return;
  if (direction === 'next') {
    currentMatchIndex = (currentMatchIndex + 1) % searchMatches.length;
  } else {
    currentMatchIndex = (currentMatchIndex - 1 + searchMatches.length) % searchMatches.length;
  }
  scrollToCurrentMatch();
}

// Renderers

function renderTextPreview(content, fileName, showAll = false) {
  const displayText = getPreviewDisplayText(content, fileName);
  const allLines = displayText.split('\n');
  const totalLines = allLines.length;
  const capped = !showAll && totalLines > LINE_CAP;
  const displayLineCount = capped ? LINE_CAP : totalLines;

  const lineNumbers = Array.from({ length: displayLineCount }, (_, i) => i + 1).join('\n');
  const formattedContent = formatPreviewTextContent(content, fileName, capped ? LINE_CAP : null);

  let html = '';
  if (capped) {
    html += `<div class="preview-line-cap">Showing first ${LINE_CAP.toLocaleString()} of ${totalLines.toLocaleString()} lines ` +
      `<button class="btn preview-show-all-lines" id="showAllLines">Show all</button></div>`;
  }
  html += `<div class="preview-text-wrapper">` +
    `<div class="preview-line-numbers">${lineNumbers}</div>` +
    `<pre class="preview-text-content">${formattedContent}</pre></div>`;
  return html;
}

function renderImagePreview(data, fileName) {
  const blob = new Blob([data], { type: getMimeType(fileName) });
  const url = URL.createObjectURL(blob);
  trackBlobUrl(url);
  return `<div class="preview-image-container">` +
    `<img src="${url}" class="preview-image" alt="${escapeHtml(fileName)}" ` +
    `style="opacity:0; transition: opacity 0.3s"></div>`;
}

function renderPdfPreview(data, fileName) {
  const blob = new Blob([data], { type: getMimeType(fileName) });
  const url = URL.createObjectURL(blob);
  trackBlobUrl(url);
  return `<div class="preview-pdf-container">` +
    `<iframe src="${url}" class="preview-pdf-frame" sandbox title="${escapeHtml(fileName)}"></iframe></div>`;
}

function attachShowAllLinesHandler() {
  const btn = document.getElementById('showAllLines');
  if (btn && currentDecodedText != null && currentFile) {
    btn.addEventListener('click', () => {
      showTextView({ showAll: true, preserveSearch: Boolean(elSearchInput?.value) });
    });
  }
}

function attachImageLoadHandler() {
  const img = elBody.querySelector('.preview-image');
  if (img) img.addEventListener('load', () => { img.style.opacity = '1'; });
}

function renderUnsupported(fileName) {
  const ext = getFileExtension(fileName);
  return `<div class="preview-unsupported">` +
    `<div class="preview-unsupported-icon">?</div>` +
    `<h3>Preview not available</h3>` +
    `<p>${ext ? `".${escapeHtml(ext)}" files` : 'This file type'} cannot be previewed in the browser.</p>` +
    `<p style="margin-top: 1rem; font-size: 0.8rem;">You can download the file to view it.</p></div>`;
}

function renderLoading() {
  return `<div class="preview-loading"><div class="spinner"></div><div>Loading preview...</div></div>`;
}

function renderError(message) {
  return `<div class="preview-error">` +
    `<div class="preview-error-icon">!</div>` +
    `<p>${escapeHtml(message)}</p></div>`;
}

// CSV table renderer

function renderCSVTable(parsed, showAll) {
  const totalRows = parsed.rows.length;
  const capped = !showAll && totalRows > ROW_CAP;
  const displayRows = capped ? parsed.rows.slice(0, ROW_CAP) : parsed.rows;

  let html = '<div class="preview-csv-wrapper">';
  html += '<div class="preview-csv-stats">';
  html += `<span>${totalRows} records / ${parsed.headers.length} columns`;
  if (capped) html += ` / showing first ${ROW_CAP}`;
  html += '</span>';
  html += '<span class="preview-csv-controls">';
  html += '<button class="mapper-adjust-btn" id="csvAdjustColumns">Adjust columns\u2026</button>';
  html += '<button class="mapper-adjust-btn" id="csvBackToText">Back to Text</button>';
  html += '<button class="mapper-adjust-btn" id="csvDownloadCsv">Download CSV</button>';
  html += '</span>';
  html += '</div>';
  html += '<div class="preview-csv-table-container">';
  html += '<table class="preview-csv-table">';
  html += '<thead><tr>';
  for (const h of parsed.headers) {
    html += `<th>${escapeHtml(h)}</th>`;
  }
  html += '</tr></thead><tbody>';
  for (const row of displayRows) {
    html += '<tr>';
    for (const cell of row) {
      html += `<td>${escapeHtml(cell)}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';

  if (capped) {
    html += `<button class="btn preview-csv-show-all" id="csvShowAll">Show all ${totalRows} records</button>`;
  }

  html += '</div>';
  return html;
}

// Transform buttons

function clearTransformButtons() {
  const btns = elActions.querySelectorAll('.preview-btn-transform, .preview-btn-try-transform, .preview-btn-back-text, .preview-btn-download-csv');
  btns.forEach(b => b.remove());
}

function parsePreviewText(text, node, overrideConfig = null) {
  if (!text) return null;
  const sourcePath = currentFile ? [...currentFile.path, currentFile.name].join('/') : (node?.name || '');
  return parseStructuredFile({
    node,
    content: currentContent,
    text,
    fileName: currentFile?.name || node?.name || '',
    sourcePath,
    allowUntypedFallback: true,
    overrideConfig,
  });
}

function addTransformButton(prominent) {
  clearTransformButtons();
  const btn = document.createElement('button');
  btn.className = `preview-btn ${prominent ? 'preview-btn-transform' : 'preview-btn-try-transform'}`;
  btn.textContent = prominent ? 'Transform to CSV' : 'Try Transform';
  btn.addEventListener('click', () => {
    if (!currentParsedData && currentDecodedText != null) {
      const parsed = parsePreviewText(currentDecodedText, currentNode);
      if (parsed && parsed.rows.length > 0) {
        currentParsedData = parsed;
      } else {
        showTransformError();
        return;
      }
    }
    if (currentParsedData) showCSVView(false);
  });
  elActions.insertBefore(btn, elActions.firstChild);
}

function addCSVViewButtons() {
  clearTransformButtons();
  elDownloadBtn.textContent = 'Download Original';
}

// View switching

function showCSVView(showAll) {
  if (!currentParsedData) return;
  showSearchBar(false);
  elBody.innerHTML = renderCSVTable(currentParsedData, showAll);
  addCSVViewButtons();

  const columnMappingType = getColumnMappingFileType(currentNode);
  if (!columnMappingType) {
    document.getElementById('csvAdjustColumns')?.remove();
  }

  const showAllBtn = document.getElementById('csvShowAll');
  if (showAllBtn) {
    showAllBtn.addEventListener('click', () => showCSVView(true));
  }

  const backBtn = document.getElementById('csvBackToText');
  if (backBtn) backBtn.addEventListener('click', () => showTextView());

  const dlBtn = document.getElementById('csvDownloadCsv');
  if (dlBtn) dlBtn.addEventListener('click', downloadCurrentCSV);

  const adjustBtn = document.getElementById('csvAdjustColumns');
  if (adjustBtn && currentNode && currentDecodedText != null) {
    adjustBtn.addEventListener('click', async () => {
      const fileName = currentFile ? currentFile.name : 'Unknown file';
      const config = await openColumnMapper(currentDecodedText, fileName, columnMappingType);
      if (!config) return;
      if (currentNode) currentNode._parseConfig = config;
      const parsed = parsePreviewText(currentDecodedText, currentNode, config);
      if (parsed && parsed.rows.length > 0) {
        currentParsedData = parsed;
        showCSVView(false);
      }
      emit('reanalyze');
    });
  }
}

function showTextView({ showAll = false, preserveSearch = false } = {}) {
  if (currentDecodedText == null || !currentFile) return;

  const activeQuery = preserveSearch ? (elSearchInput?.value || '') : '';
  showingAllTextLines = Boolean(showAll);
  showSearchBar(true, { reset: !preserveSearch });
  if (preserveSearch && elSearchInput) {
    elSearchInput.value = activeQuery;
  }

  elBody.innerHTML = renderTextPreview(currentDecodedText, currentFile.name, showingAllTextLines);
  attachShowAllLinesHandler();

  elDownloadBtn.textContent = 'Download';

  if (currentParsedData || canTransformStructuredFile(currentNode)) {
    addTransformButton(true);
  } else if (canOfferTransformAction(currentNode, currentFile.name, currentContent)) {
    addTransformButton(false);
  }

  if (activeQuery) performSearch(activeQuery);
}

function showTransformError() {
  const existing = document.querySelector('.preview-transform-error');
  if (existing) existing.remove();

  const el = document.createElement('div');
  el.className = 'preview-transform-error';
  el.textContent = 'No structured data detected in this file.';
  elBody.insertBefore(el, elBody.firstChild);
  setTimeout(() => el.remove(), 4000);
}

function downloadCurrentCSV() {
  if (!currentParsedData || !currentFile) return;
  const csvText = toCSV(currentParsedData);
  const baseName = currentFile.name.replace(/\.[^.]+$/, '');
  downloadBlob(csvText, `${baseName}_transformed.csv`, 'text/csv');
}

// Show / Close

async function showPreview(name, size, pathSegments) {
  const requestId = ++previewRequestId;
  revokeAllBlobUrls();
  clearTransformButtons();
  clearPreviewSearch();
  showSearchBar(false);
  resetPreviewActions();

  currentFile = { name, size, path: pathSegments };
  currentContent = null;
  currentDecodedText = null;
  currentParsedData = null;
  currentNode = null;
  showingAllTextLines = false;

  elTitleIcon.textContent = getFileIcon(name, false, false);
  elTitleName.textContent = name;
  elTitleSize.textContent = formatBytes(size);

  elBody.innerHTML = renderLoading();
  elOverlay.classList.add('visible');

  const fullPath = [...pathSegments, name];
  const node = getNodeAtPath(fullPath);
  currentNode = node;
  updateTypeButton();

  if (!node) {
    elBody.innerHTML = renderError('File not found in archive.');
    return;
  }

  if (node.size > MAX_PREVIEW_SIZE) {
    elBody.innerHTML = renderError(`File is too large to preview (${formatBytes(node.size)}). Maximum preview size is ${formatBytes(MAX_PREVIEW_SIZE)}. Use the download button instead.`);
    return;
  }

  const content = await loadFileContent(node);
  if (requestId !== previewRequestId) return;
  currentContent = content;

  if (!content) {
    elBody.innerHTML = renderError('File content not available for preview. This may be due to encryption or file size limits.');
    return;
  }

  if (isImageFile(name)) {
    elBody.innerHTML = renderImagePreview(content, name);
    attachImageLoadHandler();
  } else if (getFileExtension(name) === 'pdf') {
    elBody.innerHTML = renderPdfPreview(content, name);
  } else if (isOfficeOpenXmlFile(name)) {
    try {
      const text = normaliseExtractedText(await extractOfficeOpenXmlPreview(content, name));
      if (requestId !== previewRequestId) return;
      if (!text) {
        elBody.innerHTML = renderError('Limited preview is not available for this Office file.');
        return;
      }

      currentDecodedText = text;
      currentParsedData = null;
      showTextView();
      elCopyBtn.classList.remove('hidden');
    } catch (_) {
      if (requestId !== previewRequestId) return;
      elBody.innerHTML = renderError('Failed to extract text from this Office file.');
    }
  } else if (isTextFile(name)) {
    try {
      const text = SHARED_TEXT_DECODER.decode(content);
      currentDecodedText = text;
      const parsed = parsePreviewText(text, node);
      currentParsedData = parsed && parsed.rows.length > 0 ? parsed : null;
      showTextView();
      elCopyBtn.classList.remove('hidden');
    } catch (_) {
      elBody.innerHTML = renderError('Failed to decode file content.');
    }
  } else if (looksLikeText(content)) {
    // Extension not recognised but content looks like text
    try {
      const text = SHARED_TEXT_DECODER.decode(content);
      currentDecodedText = text;
      currentParsedData = null;
      showTextView();
      elCopyBtn.classList.remove('hidden');
    } catch (_) {
      elBody.innerHTML = renderUnsupported(name);
    }
  } else {
    elBody.innerHTML = renderUnsupported(name);
  }
}

function closePreview() {
  previewRequestId += 1;
  elOverlay.classList.remove('visible');
  revokeAllBlobUrls();
  clearTransformButtons();
  clearPreviewSearch();
  showSearchBar(false);
  resetPreviewActions();
  currentFile = null;
  currentContent = null;
  currentNode = null;
  currentDecodedText = null;
  currentParsedData = null;
  showingAllTextLines = false;
}

async function downloadCurrentFile() {
  if (!currentFile || !currentNode) return;

  const activeFile = currentFile;
  const activeNode = currentNode;
  let content = currentContent;
  if (!content) {
    content = await loadFileContent(activeNode);
    if (currentFile !== activeFile || currentNode !== activeNode) return;
    currentContent = content;
  }

  if (!content) return;
  downloadBlob(content, activeFile.name, getMimeType(activeFile.name));
}

// Init

function initPreview() {
  elOverlay = document.getElementById('previewOverlay');
  elBody = document.getElementById('previewBody');
  elActions = document.querySelector('.preview-actions');
  elTitleIcon = document.getElementById('previewIcon');
  elTitleName = document.getElementById('previewName');
  elTitleSize = document.getElementById('previewSize');
  elSetTypeBtn = document.getElementById('previewSetType');
  elDownloadBtn = document.getElementById('previewDownload');
  elCopyBtn = document.getElementById('previewCopy');

  elSearchBar = document.getElementById('previewSearch');
  elSearchInput = document.getElementById('previewSearchInput');
  elSearchCount = document.getElementById('previewSearchCount');
  elSearchPrev = document.getElementById('previewSearchPrev');
  elSearchNext = document.getElementById('previewSearchNext');

  document.getElementById('previewClose').addEventListener('click', closePreview);
  elDownloadBtn.addEventListener('click', downloadCurrentFile);
  elSetTypeBtn.addEventListener('click', showPreviewTypeMenu);

  elCopyBtn.addEventListener('click', () => {
    if (currentDecodedText == null) return;
    copyToClipboard(currentDecodedText).then(ok => {
      if (ok) {
        elCopyBtn.textContent = 'Copied';
        setTimeout(() => { elCopyBtn.textContent = 'Copy'; }, 1500);
      }
    });
  });

  let searchDebounce = null;
  elSearchInput.addEventListener('input', () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => {
      performSearch(elSearchInput.value);
    }, 150);
  });

  elSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      navigateMatch(e.shiftKey ? 'prev' : 'next');
    }
    if (e.key === 'Escape') {
      elSearchInput.value = '';
      performSearch('');
    }
  });

  elSearchPrev.addEventListener('click', () => navigateMatch('prev'));
  elSearchNext.addEventListener('click', () => navigateMatch('next'));

  elOverlay.addEventListener('click', (e) => {
    if (e.target === elOverlay) closePreview();
  });

  on('preview:open', ({ name, size, path }) => {
    showPreview(name, size, path);
  });

  on('reset', () => {
    closePreview();
  });
}

export { initPreview, closePreview };
