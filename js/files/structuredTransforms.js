import { isTextFile, looksLikeText } from '../core/utils.js';
import { decodeNodeCached } from '../core/shared.js';
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
import { detectFormat } from '../transforms/delimited.js';

function walletArtifactToTable(entry) {
  if (!entry) return null;
  return {
    headers: ['Service', 'Category', 'Artifact Type', 'Store Type', 'Browser', 'Profile', 'Highlights', 'Email Count', 'Address Count', 'Token Count', 'Seed Keywords', 'Source'],
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
    decodedText = decodeNodeCached(node, content);
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
      return parseCreditCardFile(getText());
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

// Only offer "Try Transform" when the file has detectable structured data.
function canOfferTransformAction(node, fileName = '', content = null) {
  if (canTransformStructuredFile(node)) return true;
  if (!shouldAttemptFallbackTransform(fileName, content)) return false;
  if (!(content instanceof Uint8Array)) return false;
  try {
    const text = decodeNodeCached(node, content);
    return detectFormat(text) != null;
  } catch {
    return false;
  }
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
