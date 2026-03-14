import { getFileExtension, isTextFile, looksLikeText } from '../core/utils.js';
import { getNodeFileType, isTransformableFileType, supportsColumnMapping } from './fileTypeRegistry.js';
import {
  parsePasswordFile,
  parseCookieFile,
  parseAutofillFile,
} from '../transforms/credentials.js';
import {
  parseSystemInfoFile,
  parseHistoryFile,
  parseBookmarkFile,
  parseBrowserMetadataFile,
  parseDownloadFile,
  parseDomainDetectFile,
  parseClipboardFile,
  parseAccountTokenFile,
  parseServiceArtifactFile,
} from '../transforms/structured.js';
import { parseCreditCardFile } from '../transforms/cards.js';
import { parseWalletArtifact } from '../analysis/walletArtifacts.js';

const TEXT_DECODER = new TextDecoder('utf-8');

function walletArtifactToTable(entry) {
  if (!entry) return null;
  return {
    headers: ['Service', 'Category', 'Artifact Type', 'Store Type', 'Browser', 'Profile', 'Highlights', 'Email Count', 'Address Count', 'Token Count', 'Seed Hints', 'Source'],
    rows: [[
      entry.service || '',
      entry.category || '',
      entry.artifactType || '',
      entry.storeType || '',
      entry.browser || '',
      entry.profile || '',
      entry.highlights || '',
      String(entry.emailCount || 0),
      String(entry.addressCount || 0),
      String(entry.tokenCount || 0),
      String(entry.seedHints || 0),
      entry.source || '',
    ]],
  };
}

function shouldAttemptFallbackTransform(fileName, content) {
  if (!fileName) return false;
  if (isTextFile(fileName)) return true;
  return content instanceof Uint8Array && looksLikeText(content);
}

function parseStructuredFile({
  node = null,
  content = null,
  text = null,
  fileName = '',
  sourcePath = '',
  allowUntypedFallback = false,
  overrideConfig = null,
} = {}) {
  const fileType = getNodeFileType(node);
  const config = overrideConfig ?? node?._parseConfig ?? null;
  const resolvedName = fileName || node?.name || '';
  const resolvedSourcePath = sourcePath || resolvedName;
  let decodedText = text;

  const getText = () => {
    if (decodedText != null) return decodedText;
    if (!(content instanceof Uint8Array)) return '';
    decodedText = TEXT_DECODER.decode(content);
    return decodedText;
  };

  switch (fileType) {
    case 'credentials':
      return parsePasswordFile(getText(), config);
    case 'cookies':
      return parseCookieFile(getText(), config);
    case 'autofill':
      return parseAutofillFile(getText(), config);
    case 'sysinfo':
      return parseSystemInfoFile(getText(), resolvedName);
    case 'history':
      return parseHistoryFile(getText(), config);
    case 'bookmarks':
      return parseBookmarkFile(getText());
    case 'browsermeta':
      return parseBrowserMetadataFile(getText());
    case 'downloads':
      return parseDownloadFile(getText());
    case 'cards':
      return parseCreditCardFile(getText(), config);
    case 'clipboard':
      return parseClipboardFile(getText());
    case 'detections':
      return parseDomainDetectFile(getText());
    case 'tokens':
      return parseAccountTokenFile(getText(), resolvedName);
    case 'services':
      return parseServiceArtifactFile(getText());
    case 'wallets':
      return walletArtifactToTable(parseWalletArtifact(content, resolvedName, resolvedSourcePath));
    default:
      break;
  }

  if (!allowUntypedFallback || !shouldAttemptFallbackTransform(resolvedName, content)) {
    return null;
  }

  const fallbackText = getText();
  return parseCookieFile(fallbackText, null)
    || parseHistoryFile(fallbackText, null)
    || parseAutofillFile(fallbackText, null)
    || parsePasswordFile(fallbackText, null);
}

function canTransformStructuredFile(node) {
  return isTransformableFileType(getNodeFileType(node));
}

function canOfferTransformAction(node, fileName = '', content = null) {
  if (canTransformStructuredFile(node)) return true;
  const ext = getFileExtension(fileName);
  if (ext === 'txt' || ext === 'tsv') return true;
  return content instanceof Uint8Array && looksLikeText(content);
}

function getColumnMappingFileType(node) {
  const fileType = getNodeFileType(node);
  return supportsColumnMapping(fileType) ? fileType : null;
}

export {
  parseStructuredFile,
  canTransformStructuredFile,
  canOfferTransformAction,
  getColumnMappingFileType,
};
