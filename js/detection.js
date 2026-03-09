// File classification

import { FILE_TYPE_PATTERNS, TEXT_EXTENSIONS } from './definitions.js';

function normalizePath(fullPath) {
  return String(fullPath || '').replace(/\\/g, '/');
}

// Credits/copyright files

function isLikelyCreditsFile(name) {
  return FILE_TYPE_PATTERNS.credits.filePatterns.some(rx => rx.test(name));
}

// Installed software files

function isLikelySoftwareFile(name) {
  return FILE_TYPE_PATTERNS.software.filePatterns.some(rx => rx.test(name));
}

// Process list files

function isLikelyProcessListFile(name) {
  return FILE_TYPE_PATTERNS.processList.filePatterns.some(rx => rx.test(name));
}

// Password files

function isLikelyPasswordFilename(name, parentDir) {
  if (FILE_TYPE_PATTERNS.password.exclusions.some(rx => rx.test(name))) return false;
  if (parentDir && FILE_TYPE_PATTERNS.password.parentDirMatch.test(parentDir)) return true;
  return FILE_TYPE_PATTERNS.password.patterns.some(rx => rx.test(name));
}

// Cookie files

function isLikelyCookieFile(name, parentDir) {
  const c = FILE_TYPE_PATTERNS.cookie;
  if (c.exclusions && c.exclusions.some(rx => rx.test(name))) return false;
  if (parentDir && c.excludeFolders.test(parentDir)) return false;
  if (parentDir && c.parentDirMatch.test(parentDir) && c.textExtensions.test(name)) return true;
  if (c.patterns.some(rx => rx.test(name))) return true;
  if (parentDir && c.parentDirMatch.test(parentDir) && c.browserProfiles.some(rx => rx.test(name))) return true;
  return false;
}

// System info files

function isLikelySystemInfoFile(name, parentDir) {
  if (FILE_TYPE_PATTERNS.sysinfo.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && FILE_TYPE_PATTERNS.sysinfo.dirPatterns.some(rx => rx.test(parentDir)) && /\.(?:txt|json)$/i.test(name)) return true;
  return false;
}

// Autofill files

function isLikelyAutofillFile(name, parentDir) {
  const a = FILE_TYPE_PATTERNS.autofill;
  if (parentDir && a.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return a.filePatterns.some(rx => rx.test(name));
}

// History files

function isLikelyHistoryFile(name, parentDir) {
  const h = FILE_TYPE_PATTERNS.history;
  if (parentDir && h.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return h.filePatterns.some(rx => rx.test(name));
}

// Bookmark files

function isLikelyBookmarkFile(name, parentDir, fullPath) {
  const b = FILE_TYPE_PATTERNS.bookmark;
  const normalizedPath = normalizePath(fullPath);
  if (parentDir && b.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  if (normalizedPath && /(^|\/)bookmarks?\//i.test(normalizedPath) && TEXT_EXTENSIONS.test(name)) return true;
  return b.filePatterns.some(rx => rx.test(name));
}

// Browser metadata / debug files

function isLikelyBrowserMetadataFile(name, parentDir, fullPath) {
  const bm = FILE_TYPE_PATTERNS.browserMetadata;
  const normalizedPath = normalizePath(fullPath);
  if (/^debug\.txt$/i.test(name)) {
    if (/(^|\/)(chrome|edge|firefox|opera|brave|vivaldi|chromium)\//i.test(normalizedPath)) return true;
  } else if (bm.filePatterns.some(rx => rx.test(name))) {
    return true;
  }
  if (parentDir && bm.folderPatterns.some(rx => rx.test(parentDir)) && TEXT_EXTENSIONS.test(name)) return true;
  return bm.pathPatterns.some(rx => rx.test(normalizedPath));
}

// Screenshots

function isLikelyScreenshot(name) {
  return FILE_TYPE_PATTERNS.screenshot.namePattern.test(name) && FILE_TYPE_PATTERNS.screenshot.extensions.test(name);
}

// Credit card files

function isLikelyCreditCardFile(name, parentDir) {
  const cc = FILE_TYPE_PATTERNS.creditCard;
  if (cc.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && cc.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return false;
}

// Download history files

function isLikelyDownloadFile(name, parentDir) {
  const d = FILE_TYPE_PATTERNS.downloadHistory;
  if (d.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && d.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return false;
}

// Browser plugin/extension files

function isLikelyBrowserPluginFile(name, parentDir) {
  if (!parentDir) return false;
  return FILE_TYPE_PATTERNS.browserPlugin.folderPatterns.some(rx => rx.test(parentDir));
}

// Domain detect files

function isLikelyDomainDetectFile(name) {
  return FILE_TYPE_PATTERNS.domainDetect.filePatterns.some(rx => rx.test(name));
}

// Crypto wallet data

function isLikelyCryptoWalletFile(name, parentDir) {
  const cw = FILE_TYPE_PATTERNS.cryptoWallet;
  if (cw.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && cw.folderPatterns.some(rx => rx.test(parentDir))) return true;
  return false;
}

// Account token files

function isLikelyAccountTokenFile(name, parentDir, fullPath) {
  const at = FILE_TYPE_PATTERNS.accountToken;
  const normalizedPath = normalizePath(fullPath);
  if (at.pathPatterns.some(rx => rx.test(normalizedPath))) return true;
  if (parentDir && at.folderPatterns.some(rx => rx.test(parentDir)) && TEXT_EXTENSIONS.test(name)) return true;
  return at.filePatterns.some(rx => rx.test(name)) && (
    /googleaccounts|fbfastcheck|discord|steam/i.test(normalizedPath) ||
    /^(?:restore_|discordtokens?|discord\.txt|token_eaab\.txt|ids?\.txt|tokens?\.txt)/i.test(name)
  );
}

// Service / messenger configuration artifacts

function isLikelyServiceArtifactFile(name, parentDir, fullPath) {
  const sa = FILE_TYPE_PATTERNS.serviceArtifact;
  const normalizedPath = normalizePath(fullPath);
  if (sa.pathPatterns.some(rx => rx.test(normalizedPath))) return true;

  if (/^(?:system|service|user)\.conf$/i.test(name) && /anydesk/i.test(normalizedPath)) return true;
  if (/^accounts\.txt$/i.test(name) && /(outlook|email clients?)/i.test(normalizedPath)) return true;
  if (/^usersettings\.json$/i.test(name) && /outlook/i.test(normalizedPath)) return true;
  if (/^token\.txt$/i.test(name) && /telegram/i.test(normalizedPath)) return true;
  if (/^\d+\.(?:log|ldb)$/i.test(name) && /discord\/.*leveldb/i.test(normalizedPath)) return true;

  return sa.filePatterns.some(rx => rx.test(name)) && /(telegram|outlook|anydesk|discord)/i.test(normalizedPath);
}

// Legacy messenger / token files

function isLikelyMessengerFile(name, parentDir, fullPath) {
  const m = FILE_TYPE_PATTERNS.messenger;
  if (isLikelyAccountTokenFile(name, parentDir, fullPath) || isLikelyServiceArtifactFile(name, parentDir, fullPath)) {
    return false;
  }
  return m.filePatterns.some(rx => rx.test(name));
}

// Clipboard files

function isLikelyClipboardFile(name) {
  return FILE_TYPE_PATTERNS.clipboard.filePatterns.some(rx => rx.test(name));
}

// Apply all hints to a node. Returns true if anything was detected.
function applyDetectionHints(node, name, parentDir, fullPath = '') {
  let detected = false;
  if (isLikelyPasswordFilename(name, parentDir)) { node._passwordFileHint = true; detected = true; }
  if (isLikelyCookieFile(name, parentDir))        { node._cookieFileHint = true;   detected = true; }
  if (isLikelySystemInfoFile(name, parentDir))     { node._sysInfoHint = true;      detected = true; }
  if (isLikelyAutofillFile(name, parentDir))       { node._autofillHint = true;     detected = true; }
  if (isLikelyHistoryFile(name, parentDir))        { node._historyHint = true;      detected = true; }
  if (isLikelyBookmarkFile(name, parentDir, fullPath)) { node._bookmarkHint = true; detected = true; }
  if (isLikelyBrowserMetadataFile(name, parentDir, fullPath)) { node._browserMetadataHint = true; detected = true; }
  if (isLikelyScreenshot(name))                    { node._screenshotHint = true;   detected = true; }
  if (isLikelyCreditCardFile(name, parentDir))     { node._creditCardHint = true;   detected = true; }
  if (isLikelyDownloadFile(name, parentDir))       { node._downloadHint = true;     detected = true; }
  if (isLikelyCryptoWalletFile(name, parentDir))   { node._cryptoWalletHint = true; detected = true; }
  if (isLikelyAccountTokenFile(name, parentDir, fullPath)) { node._accountTokenHint = true; detected = true; }
  if (isLikelyServiceArtifactFile(name, parentDir, fullPath)) { node._serviceArtifactHint = true; detected = true; }
  if (isLikelyMessengerFile(name, parentDir, fullPath))      { node._messengerHint = true;    detected = true; }
  if (isLikelyCreditsFile(name))                   { node._creditsFileHint = true;  detected = true; }
  if (isLikelySoftwareFile(name))                  { node._softwareFileHint = true; detected = true; }
  if (isLikelyProcessListFile(name))               { node._processListHint = true;  detected = true; }
  if (isLikelyDomainDetectFile(name))              { node._domainDetectHint = true; detected = true; }
  if (isLikelyBrowserPluginFile(name, parentDir))  { node._browserPluginHint = true; detected = true; }
  if (isLikelyClipboardFile(name))                 { node._clipboardHint = true;    detected = true; }
  return detected;
}

export {
  isLikelyPasswordFilename,
  isLikelyCookieFile,
  isLikelySystemInfoFile,
  isLikelyAutofillFile,
  isLikelyHistoryFile,
  isLikelyBookmarkFile,
  isLikelyBrowserMetadataFile,
  isLikelyScreenshot,
  isLikelyCreditCardFile,
  isLikelyDownloadFile,
  isLikelyDomainDetectFile,
  isLikelyBrowserPluginFile,
  isLikelyCryptoWalletFile,
  isLikelyAccountTokenFile,
  isLikelyServiceArtifactFile,
  isLikelyMessengerFile,
  isLikelyClipboardFile,
  isLikelyCreditsFile,
  isLikelySoftwareFile,
  isLikelyProcessListFile,
  applyDetectionHints,
};
