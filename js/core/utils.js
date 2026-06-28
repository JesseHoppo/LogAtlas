import { LIMITS } from './definitions/patterns.js';

const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, ch => ESC_MAP[ch]);
}

function escapeAttr(str) {
  return escapeHtml(str);
}

function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(
    Math.floor(Math.log(Math.abs(value)) / Math.log(k)),
    sizes.length - 1
  );
  return parseFloat((value / Math.pow(k, exponent)).toFixed(1)) + ' ' + sizes[exponent];
}

const TEXT_EXTENSIONS = new Set([
  'txt', 'log', 'csv', 'tsv', 'json', 'xml', 'html', 'htm', 'css', 'js',
  'md', 'conf', 'cfg', 'ini', 'yaml', 'yml', 'toml', 'sql', 'sh', 'bat',
  'ps1', 'py', 'rb', 'php',
]);

const IMAGE_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'svg',
]);

const OFFICE_PREVIEW_EXTENSIONS = new Set([
  'docx', 'docm', 'dotx', 'dotm',
  'xlsx', 'xlsm', 'xltx', 'xltm',
  'pptx', 'pptm', 'potx', 'potm',
]);

const JUNK_FILES = new Set([
  '.ds_store', 'thumbs.db', 'desktop.ini',
]);

const MAX_PREVIEW_SIZE = LIMITS.previewMaxBytes;

function getFileExtension(name) {
  const parts = name.split('.');
  return parts.length > 1 ? parts.pop().toLowerCase() : '';
}

function isZipFile(name) {
  return name.toLowerCase().endsWith('.zip');
}

const ARCHIVE_EXTENSIONS = new Set([
  'zip', '7z', 'rar', 'tar', 'gz', 'tgz', 'bz2', 'tbz2', 'xz', 'txz', 'lz', 'lzma',
]);

const COMPOUND_ARCHIVE_SUFFIXES = [
  '.tar.gz', '.tar.bz2', '.tar.xz', '.tar.lz', '.tar.lzma',
];

function isArchiveFile(name) {
  const lower = name.toLowerCase();
  if (COMPOUND_ARCHIVE_SUFFIXES.some(s => lower.endsWith(s))) return true;
  return ARCHIVE_EXTENSIONS.has(getFileExtension(lower));
}

function isTextFile(name) {
  return TEXT_EXTENSIONS.has(getFileExtension(name));
}

function isImageFile(name) {
  return IMAGE_EXTENSIONS.has(getFileExtension(name));
}

function isPreviewable(name) {
  const ext = getFileExtension(name);
  return TEXT_EXTENSIONS.has(ext) || IMAGE_EXTENSIONS.has(ext) || ext === 'pdf' || OFFICE_PREVIEW_EXTENSIONS.has(ext);
}

// Quick check if raw bytes look like text (samples the leading window).
function looksLikeText(uint8Array) {
  const len = Math.min(uint8Array.length, LIMITS.looksLikeTextSampleBytes);
  for (let i = 0; i < len; i++) {
    const b = uint8Array[i];
    if (b === 0) return false;
    if (b < 0x20 && b !== 0x09 && b !== 0x0A && b !== 0x0D) return false;
  }
  return true;
}

function isJunkFile(name) {
  return JUNK_FILES.has(name.toLowerCase());
}

function isMacOSMetadata(path) {
  return path.startsWith('__MACOSX');
}

function getFileIcon(name, isDirectory, isArchive) {
  if (isDirectory) return 'DIR';
  if (isArchive || isArchiveFile(name)) return 'ZIP';

  const ext = getFileExtension(name);
  const icons = {
    txt: 'TXT', log: 'LOG', csv: 'CSV', tsv: 'TSV',
    json: 'JSON', xml: 'XML',
    png: 'IMG', jpg: 'IMG', jpeg: 'IMG',
    gif: 'IMG', bmp: 'IMG', webp: 'IMG', svg: 'SVG',
    db: 'DB', sqlite: 'DB', sqlite3: 'DB',
    exe: 'EXE', dll: 'DLL',
    html: 'HTML', htm: 'HTML',
    pdf: 'PDF',
    doc: 'DOC', docx: 'DOC',
    xls: 'XLS', xlsx: 'XLS',
    ini: 'CFG', cfg: 'CFG', conf: 'CFG',
  };
  return icons[ext] || ext.toUpperCase() || '\u2014';
}

function getMimeType(name) {
  const ext = getFileExtension(name);
  const mimeTypes = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
    ico: 'image/x-icon', svg: 'image/svg+xml',
    json: 'application/json', xml: 'application/xml',
    html: 'text/html', htm: 'text/html', css: 'text/css',
    js: 'text/javascript', txt: 'text/plain', pdf: 'application/pdf',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    docm: 'application/vnd.ms-word.document.macroEnabled.12',
    dotx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
    dotm: 'application/vnd.ms-word.template.macroEnabled.12',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    xlsm: 'application/vnd.ms-excel.sheet.macroEnabled.12',
    xltx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
    xltm: 'application/vnd.ms-excel.template.macroEnabled.12',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    pptm: 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
    potx: 'application/vnd.openxmlformats-officedocument.presentationml.template',
    potm: 'application/vnd.ms-powerpoint.template.macroEnabled.12',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

// JSON syntax highlighting from raw JSON text.
function syntaxHighlightJSON(jsonString) {
  const source = String(jsonString);
  const tokenPattern = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\btrue\b|\bfalse\b|\bnull\b|-?\d+\.?\d*(?:[eE][+-]?\d+)?)/g;

  let html = '';
  let lastIndex = 0;
  let match;

  while ((match = tokenPattern.exec(source)) !== null) {
    html += escapeHtml(source.slice(lastIndex, match.index));

    const token = match[0];
    if (token.startsWith('"')) {
      if (token.endsWith(':')) {
        html += `<span class="json-key">${escapeHtml(token.slice(0, -1))}</span><span style="color: var(--text-muted)">:</span>`;
      } else {
        html += `<span class="json-string">${escapeHtml(token)}</span>`;
      }
    } else if (token === 'true' || token === 'false') {
      html += `<span class="json-boolean">${token}</span>`;
    } else if (token === 'null') {
      html += `<span class="json-null">${token}</span>`;
    } else {
      html += `<span class="json-number">${token}</span>`;
    }

    lastIndex = match.index + token.length;
  }

  html += escapeHtml(source.slice(lastIndex));
  return html;
}

export {
  escapeHtml,
  escapeAttr,
  formatBytes,
  getFileExtension,
  isZipFile,
  isArchiveFile,
  isTextFile,
  isImageFile,
  isPreviewable,
  isJunkFile,
  isMacOSMetadata,
  getFileIcon,
  getMimeType,
  syntaxHighlightJSON,
  looksLikeText,
  MAX_PREVIEW_SIZE,
};
