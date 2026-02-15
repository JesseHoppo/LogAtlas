// Misc utility functions.

const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, ch => ESC_MAP[ch]);
}

function escapeAttr(str) {
  return escapeHtml(str);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

const TEXT_EXTENSIONS = new Set([
  'txt', 'log', 'csv', 'tsv', 'json', 'xml', 'html', 'htm', 'css', 'js',
  'md', 'conf', 'cfg', 'ini', 'yaml', 'yml', 'toml', 'sql', 'sh', 'bat',
  'ps1', 'py', 'rb', 'php',
]);

const IMAGE_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'svg',
]);

const JUNK_FILES = new Set([
  '.ds_store', 'thumbs.db', 'desktop.ini',
]);

const MAX_PREVIEW_SIZE = 5 * 1024 * 1024; // 5 MB

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

function isNonZipArchive(name) {
  return isArchiveFile(name) && !isZipFile(name);
}

function isTextFile(name) {
  return TEXT_EXTENSIONS.has(getFileExtension(name));
}

function isImageFile(name) {
  return IMAGE_EXTENSIONS.has(getFileExtension(name));
}

function isPreviewable(name) {
  const ext = getFileExtension(name);
  return TEXT_EXTENSIONS.has(ext) || IMAGE_EXTENSIONS.has(ext);
}

// Quick check if raw bytes look like text (sample first 512 bytes).
function looksLikeText(uint8Array) {
  const len = Math.min(uint8Array.length, 512);
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
  return icons[ext] || ext.toUpperCase() || 'FILE';
}

function getMimeType(name) {
  const ext = getFileExtension(name);
  const mimeTypes = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
    ico: 'image/x-icon', svg: 'image/svg+xml',
    json: 'application/json', xml: 'application/xml',
    html: 'text/html', htm: 'text/html', css: 'text/css',
    js: 'text/javascript', txt: 'text/plain',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

// JSON syntax highlighting (input must be escaped first).
function syntaxHighlightJSON(jsonString) {
  const escaped = escapeHtml(jsonString);
  return escaped
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?)/g, (match) => {
      let cls = 'json-string';
      if (/:$/.test(match)) {
        cls = 'json-key';
        match = match.slice(0, -1) + '<span style="color: var(--text-muted)">:</span>';
      }
      return `<span class="${cls}">${match}</span>`;
    })
    .replace(/\b(true|false)\b/g, '<span class="json-boolean">$1</span>')
    .replace(/\b(null)\b/g, '<span class="json-null">$1</span>')
    .replace(/\b(-?\d+\.?\d*([eE][+-]?\d+)?)\b/g, '<span class="json-number">$1</span>');
}

export {
  escapeHtml,
  escapeAttr,
  formatBytes,
  getFileExtension,
  isZipFile,
  isArchiveFile,
  isNonZipArchive,
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
