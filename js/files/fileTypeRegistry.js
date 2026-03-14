import { escapeHtml } from '../core/utils.js';

const FILE_TYPE_DEFINITIONS = Object.freeze([
  { type: 'credentials', hint: '_passwordFileHint', label: 'Credentials', shortcutKey: '1', transformable: true, columnMappable: true },
  { type: 'cookies', hint: '_cookieFileHint', label: 'Cookies', shortcutKey: '2', transformable: true, columnMappable: true },
  { type: 'autofill', hint: '_autofillHint', label: 'Autofill', shortcutKey: '3', transformable: true, columnMappable: true },
  { type: 'history', hint: '_historyHint', label: 'History', shortcutKey: '4', transformable: true, columnMappable: true },
  { type: 'bookmarks', hint: '_bookmarkHint', label: 'Bookmarks', transformable: true },
  { type: 'browsermeta', hint: '_browserMetadataHint', label: 'Browser Metadata', transformable: true },
  { type: 'sysinfo', hint: '_sysInfoHint', label: 'System Info', shortcutKey: '5', transformable: true },
  { type: 'downloads', hint: '_downloadHint', label: 'Downloads', shortcutKey: '6', transformable: true },
  { type: 'cards', hint: '_creditCardHint', label: 'Credit Cards', shortcutKey: '7', transformable: true },
  { type: 'clipboard', hint: '_clipboardHint', label: 'Clipboard', shortcutKey: '8', transformable: true },
  { type: 'notes', hint: '_notesHint', label: 'Notes' },
  { type: 'grabbed', hint: '_grabbedFileHint', label: 'Grabbed Files' },
  { type: 'detections', hint: '_domainDetectHint', label: 'Detections', shortcutKey: '9', transformable: true },
  { type: 'tokens', hint: '_accountTokenHint', label: 'Account Tokens', transformable: true },
  { type: 'services', hint: '_serviceArtifactHint', label: 'Services', transformable: true },
  { type: 'wallets', hint: '_cryptoWalletHint', label: 'Wallets', transformable: true },
  { type: 'software', hint: '_softwareFileHint', label: 'Software', supportsPaste: true },
  { type: 'processes', hint: '_processListHint', label: 'Processes', supportsPaste: true },
  { type: 'screenshot', hint: '_screenshotHint', label: 'Screenshot', supportsPaste: false },
]);
const ADDITIONAL_HINT_KEYS = Object.freeze([
  '_browserPluginHint',
  '_messengerHint',
  '_creditsFileHint',
]);

const FILE_TYPE_BY_TYPE = new Map(FILE_TYPE_DEFINITIONS.map((definition) => [definition.type, definition]));
const FILE_TYPE_TO_HINT = Object.freeze(
  Object.fromEntries(FILE_TYPE_DEFINITIONS.map(({ type, hint }) => [type, hint]))
);
const HINT_KEYS = Object.freeze([
  ...FILE_TYPE_DEFINITIONS.map(({ hint }) => hint),
  ...ADDITIONAL_HINT_KEYS,
]);

function getFileTypeDefinition(type) {
  return FILE_TYPE_BY_TYPE.get(type) || null;
}

function getNodeFileType(node) {
  if (!node) return null;
  for (const definition of FILE_TYPE_DEFINITIONS) {
    if (node[definition.hint]) return definition.type;
  }
  return null;
}

function getFileTypeLabel(type) {
  return getFileTypeDefinition(type)?.label || 'Set Type';
}

function isTransformableFileType(type) {
  return Boolean(getFileTypeDefinition(type)?.transformable);
}

function supportsColumnMapping(type) {
  return Boolean(getFileTypeDefinition(type)?.columnMappable);
}

function buildOptionMarkup(option, activeType) {
  const classes = ['filetype-option'];
  if (option.type === activeType) classes.push('active');
  if (option.type === 'none') classes.push('filetype-option-remove');

  const keyAttr = option.shortcutKey ? ` data-key="${escapeHtml(option.shortcutKey)}"` : '';
  const description = option.description
    ? `<span class="filetype-desc">${escapeHtml(option.description)}</span>`
    : '';

  return `
    <button class="${classes.join(' ')}" data-type="${escapeHtml(option.type)}"${keyAttr}>
      <span class="filetype-icon">${escapeHtml(option.label)}</span>
      ${description}
    </button>
  `;
}

function getPickerOptions({ includeOther = false, includeRemove = false, supportsPasteOnly = false } = {}) {
  const options = FILE_TYPE_DEFINITIONS
    .filter((definition) => !supportsPasteOnly || definition.supportsPaste !== false)
    .map((definition) => ({
      type: definition.type,
      label: definition.label,
      shortcutKey: definition.shortcutKey || '',
    }));

  if (includeOther) {
    options.push({
      type: 'other',
      label: 'Other',
      description: 'View file content only',
    });
  }

  if (includeRemove) {
    options.push({
      type: 'none',
      label: 'Remove Label',
    });
  }

  return options;
}

function buildFileTypeOptionsHtml(options = {}) {
  const activeType = options.activeType || null;
  return getPickerOptions(options).map((option) => buildOptionMarkup(option, activeType)).join('');
}

function renderFileTypeOptions(container, options = {}) {
  if (!container) return;
  container.innerHTML = buildFileTypeOptionsHtml(options);
}

export {
  FILE_TYPE_TO_HINT,
  HINT_KEYS,
  getFileTypeLabel,
  getNodeFileType,
  isTransformableFileType,
  supportsColumnMapping,
  buildFileTypeOptionsHtml,
  renderFileTypeOptions,
};
