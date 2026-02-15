// File classification

import { FILE_TYPE_PATTERNS, TEXT_EXTENSIONS } from './definitions.js';

// Password files

function isLikelyPasswordFilename(name, parentDir) {
  if (FILE_TYPE_PATTERNS.password.exclusions.some(rx => rx.test(name))) return false;
  if (parentDir && FILE_TYPE_PATTERNS.password.parentDirMatch.test(parentDir)) return true;
  return FILE_TYPE_PATTERNS.password.patterns.some(rx => rx.test(name));
}

// Cookie files

function isLikelyCookieFile(name, parentDir) {
  const c = FILE_TYPE_PATTERNS.cookie;
  if (parentDir && c.excludeFolders.test(parentDir)) return false;
  if (parentDir && c.parentDirMatch.test(parentDir) && c.textExtensions.test(name)) return true;
  if (c.patterns.some(rx => rx.test(name))) return true;
  if (parentDir && c.parentDirMatch.test(parentDir) && c.browserProfiles.some(rx => rx.test(name))) return true;
  return false;
}

// System info files

function isLikelySystemInfoFile(name, parentDir) {
  if (FILE_TYPE_PATTERNS.sysinfo.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && FILE_TYPE_PATTERNS.sysinfo.dirPatterns.some(rx => rx.test(parentDir)) && /\.txt$/i.test(name)) return true;
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

// Crypto wallet data

function isLikelyCryptoWalletFile(name, parentDir) {
  const cw = FILE_TYPE_PATTERNS.cryptoWallet;
  if (cw.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && cw.folderPatterns.some(rx => rx.test(parentDir))) return true;
  return false;
}

// Messenger / token files

function isLikelyMessengerFile(name, parentDir) {
  const m = FILE_TYPE_PATTERNS.messenger;
  if (m.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && m.folderPatterns.some(rx => rx.test(parentDir))) return true;
  return false;
}

// Apply all hints to a node. Returns true if anything was detected.
function applyDetectionHints(node, name, parentDir) {
  let detected = false;
  if (isLikelyPasswordFilename(name, parentDir)) { node._passwordFileHint = true; detected = true; }
  if (isLikelyCookieFile(name, parentDir))        { node._cookieFileHint = true;   detected = true; }
  if (isLikelySystemInfoFile(name, parentDir))     { node._sysInfoHint = true;      detected = true; }
  if (isLikelyAutofillFile(name, parentDir))       { node._autofillHint = true;     detected = true; }
  if (isLikelyHistoryFile(name, parentDir))        { node._historyHint = true;      detected = true; }
  if (isLikelyScreenshot(name))                    { node._screenshotHint = true;   detected = true; }
  if (isLikelyCreditCardFile(name, parentDir))     { node._creditCardHint = true;   detected = true; }
  if (isLikelyCryptoWalletFile(name, parentDir))   { node._cryptoWalletHint = true; detected = true; }
  if (isLikelyMessengerFile(name, parentDir))      { node._messengerHint = true;    detected = true; }
  return detected;
}

export {
  isLikelyPasswordFilename,
  isLikelyCookieFile,
  isLikelySystemInfoFile,
  isLikelyAutofillFile,
  isLikelyHistoryFile,
  isLikelyScreenshot,
  isLikelyCreditCardFile,
  isLikelyCryptoWalletFile,
  isLikelyMessengerFile,
  applyDetectionHints,
};
