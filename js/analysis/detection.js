import { FILE_TYPE_PATTERNS, TEXT_EXTENSIONS } from '../core/definitions/fileTypes.js';
import { normalisePath } from '../core/shared.js';

function isLikelyCreditsFile(name) {
  return FILE_TYPE_PATTERNS.credits.filePatterns.some(rx => rx.test(name));
}

function isLikelySoftwareFile(name) {
  return FILE_TYPE_PATTERNS.software.filePatterns.some(rx => rx.test(name));
}

function isLikelyProcessListFile(name) {
  return FILE_TYPE_PATTERNS.processList.filePatterns.some(rx => rx.test(name));
}

function isLikelyPasswordFilename(name, parentDir, fullPath = '') {
  const trimmedName = String(name || '').trim();
  const normalisedPath = normalisePath(fullPath);
  if (FILE_TYPE_PATTERNS.password.exclusions.some(rx => rx.test(trimmedName))) return false;
  if (isLikelyAggregatePasswordFile(trimmedName)) return false;
  if (/(^|\/)(?:mails?|email clients?)\/outlook\/credentials\.txt$/i.test(normalisedPath)) return false;
  if (parentDir && FILE_TYPE_PATTERNS.password.parentDirMatch.test(parentDir)) return true;
  return FILE_TYPE_PATTERNS.password.patterns.some(rx => rx.test(trimmedName));
}

// `All Passwords.txt`-style aggregate files; promoted to a real password file by
// reconcileAggregatePasswordFiles, with dedup at the credential layer.
function isLikelyAggregatePasswordFile(name) {
  const trimmedName = String(name || '').trim();
  const patterns = FILE_TYPE_PATTERNS.password.aggregatePatterns || [];
  return patterns.some(rx => rx.test(trimmedName));
}

function isLikelyCookieFile(name, parentDir, fullPath) {
  const c = FILE_TYPE_PATTERNS.cookie;
  const bareName = name.replace(c.servicePrefix, '');
  if (c.exclusions && c.exclusions.some(rx => rx.test(bareName))) return false;
  if (parentDir && c.excludeFolders.test(parentDir)) return false;
  if (parentDir && c.parentDirMatch.test(parentDir) && c.textExtensions.test(name)) return true;
  if (c.patterns.some(rx => rx.test(bareName))) return true;
  if (parentDir && c.parentDirMatch.test(parentDir) && c.browserProfiles.some(rx => rx.test(bareName))) return true;
  return c.pathPatterns.some(rx => rx.test(normalisePath(fullPath)))
    && c.browserProfiles.some(rx => rx.test(bareName));
}

function isLikelySystemInfoFile(name, parentDir) {
  if (FILE_TYPE_PATTERNS.sysinfo.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && FILE_TYPE_PATTERNS.sysinfo.dirPatterns.some(rx => rx.test(parentDir)) && /\.(?:txt|json)$/i.test(name)) return true;
  return false;
}

function isLikelyAutofillFile(name, parentDir) {
  const a = FILE_TYPE_PATTERNS.autofill;
  if (parentDir && a.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return a.filePatterns.some(rx => rx.test(name));
}

function isLikelyHistoryFile(name, parentDir) {
  const h = FILE_TYPE_PATTERNS.history;
  if (parentDir && h.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return h.filePatterns.some(rx => rx.test(name));
}

function isLikelyBookmarkFile(name, parentDir, fullPath) {
  const b = FILE_TYPE_PATTERNS.bookmark;
  const normalisedPath = normalisePath(fullPath);
  if (parentDir && b.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  if (normalisedPath && /(^|\/)bookmarks?\//i.test(normalisedPath) && TEXT_EXTENSIONS.test(name)) return true;
  return b.filePatterns.some(rx => rx.test(name));
}

function isLikelyBrowserMetadataFile(name, parentDir, fullPath) {
  const bm = FILE_TYPE_PATTERNS.browserMetadata;
  const normalisedPath = normalisePath(fullPath);
  if (bm.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && bm.folderPatterns.some(rx => rx.test(parentDir)) && TEXT_EXTENSIONS.test(name)) return true;
  return bm.pathPatterns.some(rx => rx.test(normalisedPath));
}

function isLikelyStealerDebugFile(name, fullPath) {
  const debug = FILE_TYPE_PATTERNS.stealerDebug;
  if (!debug.filePatterns.some(rx => rx.test(name))) return false;
  return debug.pathPatterns.some(rx => rx.test(normalisePath(fullPath)));
}

function isLikelyScreenshot(name) {
  return FILE_TYPE_PATTERNS.screenshot.namePattern.test(name) && FILE_TYPE_PATTERNS.screenshot.extensions.test(name);
}

function isLikelyCreditCardFile(name, parentDir) {
  const cc = FILE_TYPE_PATTERNS.creditCard;
  if (parentDir && cc.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  if (cc.exclusions.some(rx => rx.test(name))) return false;
  return cc.filePatterns.some(rx => rx.test(name));
}

function isLikelyDownloadFile(name, parentDir) {
  const d = FILE_TYPE_PATTERNS.downloadHistory;
  if (d.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && d.folderPattern.test(parentDir) && TEXT_EXTENSIONS.test(name)) return true;
  return false;
}

function isLikelyBrowserPluginFile(name, parentDir) {
  if (!parentDir) return false;
  return FILE_TYPE_PATTERNS.browserPlugin.folderPatterns.some(rx => rx.test(parentDir));
}

function isLikelyDomainDetectFile(name) {
  return FILE_TYPE_PATTERNS.domainDetect.filePatterns.some(rx => rx.test(name));
}

function isLikelyCryptoWalletFile(name, parentDir, fullPath) {
  const cw = FILE_TYPE_PATTERNS.cryptoWallet;
  const normalisedPath = normalisePath(fullPath);
  if (cw.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && cw.folderPatterns.some(rx => rx.test(parentDir))) return true;
  if (cw.pathPatterns.some(rx => rx.test(normalisedPath))) return true;
  return cw.pathScopedFilePatterns.some(rx => rx.test(name)) && cw.scopePattern.test(normalisedPath);
}

function isLikelyAccountTokenFile(name, parentDir, fullPath) {
  const at = FILE_TYPE_PATTERNS.accountToken;
  const normalisedPath = normalisePath(fullPath);
  if (at.pathPatterns.some(rx => rx.test(normalisedPath))) return true;
  if (parentDir && at.folderPatterns.some(rx => rx.test(parentDir)) && TEXT_EXTENSIONS.test(name)) return true;
  return at.filePatterns.some(rx => rx.test(name)) && (
    /googleaccounts|fbfastcheck|discord|steam/i.test(normalisedPath) ||
    /^(?:restore_|googletokens?|discordtokens?|discord\.txt|token_eaab\.txt|ids?\.txt|tokens?\.txt)/i.test(name)
  );
}

function isLikelyServiceArtifactFile(name, parentDir, fullPath) {
  const sa = FILE_TYPE_PATTERNS.serviceArtifact;
  const normalisedPath = normalisePath(fullPath);
  if (sa.pathPatterns.some(rx => rx.test(normalisedPath))) return true;

  if (/^(?:system|service|user)\.conf$/i.test(name) && /anydesk/i.test(normalisedPath)) return true;
  if (/^accounts\.txt$/i.test(name) && /(outlook|email clients?)/i.test(normalisedPath)) return true;
  if (/^usersettings\.json$/i.test(name) && /outlook/i.test(normalisedPath)) return true;
  if (/^token\.txt$/i.test(name) && /telegram/i.test(normalisedPath)) return true;
  if (/^\d+\.(?:log|ldb)$/i.test(name) && /discord\/.*leveldb/i.test(normalisedPath)) return true;

  return sa.filePatterns.some(rx => rx.test(name)) && /(telegram|outlook|anydesk|discord)/i.test(normalisedPath);
}

function isLikelyFtpCredentialFile(name, parentDir, fullPath) {
  const ftp = FILE_TYPE_PATTERNS.ftpCredential;
  const normalisedPath = normalisePath(fullPath);
  if (ftp.filePatterns.some(rx => rx.test(name))) return true;
  return ftp.pathPatterns.some(rx => rx.test(normalisedPath));
}

function isLikelyMessengerFile(name, parentDir, fullPath) {
  const m = FILE_TYPE_PATTERNS.messenger;
  if (isLikelyAccountTokenFile(name, parentDir, fullPath) || isLikelyServiceArtifactFile(name, parentDir, fullPath)) {
    return false;
  }
  if (m.filePatterns.some(rx => rx.test(name))) return true;
  return m.pathScopedFilePatterns.some(rx => rx.test(name))
    && m.pathPatterns.some(rx => rx.test(normalisePath(fullPath)));
}

function isLikelyClipboardFile(name) {
  return FILE_TYPE_PATTERNS.clipboard.filePatterns.some(rx => rx.test(name));
}

function isLikelyNoteFile(name, parentDir, fullPath) {
  const notes = FILE_TYPE_PATTERNS.notes;
  const normalisedPath = normalisePath(fullPath);
  if (notes.filePatterns.some(rx => rx.test(name))) return true;
  if (parentDir && notes.folderPatterns.some(rx => rx.test(parentDir)) && TEXT_EXTENSIONS.test(name)) return true;
  return notes.pathPatterns.some(rx => rx.test(normalisedPath)) && TEXT_EXTENSIONS.test(name);
}

function isLikelyKeylogFile(_name, _parentDir, fullPath) {
  const normalisedPath = normalisePath(fullPath);
  return FILE_TYPE_PATTERNS.keylog.pathPatterns.some(rx => rx.test(normalisedPath));
}

function isLikelyGrabbedFile(_name, parentDir, fullPath) {
  const grabbed = FILE_TYPE_PATTERNS.grabbedFiles;
  const normalisedPath = normalisePath(fullPath);
  if (parentDir && grabbed.folderPatterns.some(rx => rx.test(parentDir))) return true;
  return grabbed.pathPatterns.some(rx => rx.test(normalisedPath));
}

function applyDetectionHints(node, rawName, parentDir, fullPath = '') {
  const name = String(rawName).replace(/\s*\[Part \d+ of \d+\]\s*$/i, '');
  let detected = false;
  if (isLikelyPasswordFilename(name, parentDir, fullPath)) { node._passwordFileHint = true; detected = true; }
  else if (isLikelyAggregatePasswordFile(name)) { node._passwordFileAggregateHint = true; detected = true; }
  if (isLikelyCookieFile(name, parentDir, fullPath)) { node._cookieFileHint = true; detected = true; }
  if (isLikelySystemInfoFile(name, parentDir, fullPath)) { node._sysInfoHint = true; detected = true; }
  if (isLikelyAutofillFile(name, parentDir))       { node._autofillHint = true;     detected = true; }
  if (isLikelyHistoryFile(name, parentDir))        { node._historyHint = true;      detected = true; }
  if (isLikelyBookmarkFile(name, parentDir, fullPath)) { node._bookmarkHint = true; detected = true; }
  if (isLikelyBrowserMetadataFile(name, parentDir, fullPath)) { node._browserMetadataHint = true; detected = true; }
  if (isLikelyStealerDebugFile(name, fullPath))    { node._stealerDebugHint = true; detected = true; }
  if (isLikelyScreenshot(name))                    { node._screenshotHint = true;   detected = true; }
  if (isLikelyCreditCardFile(name, parentDir))     { node._creditCardHint = true;   detected = true; }
  if (isLikelyDownloadFile(name, parentDir))       { node._downloadHint = true;     detected = true; }
  if (isLikelyCryptoWalletFile(name, parentDir, fullPath))   { node._cryptoWalletHint = true; detected = true; }
  if (isLikelyAccountTokenFile(name, parentDir, fullPath)) { node._accountTokenHint = true; detected = true; }
  if (isLikelyServiceArtifactFile(name, parentDir, fullPath)) { node._serviceArtifactHint = true; detected = true; }
  if (isLikelyFtpCredentialFile(name, parentDir, fullPath)) { node._ftpCredentialHint = true; detected = true; }
  if (isLikelyMessengerFile(name, parentDir, fullPath))      { node._messengerHint = true;    detected = true; }
  if (isLikelyCreditsFile(name))                   { node._creditsFileHint = true;  detected = true; }
  if (isLikelySoftwareFile(name))                  { node._softwareFileHint = true; detected = true; }
  if (isLikelyProcessListFile(name))               { node._processListHint = true;  detected = true; }
  if (isLikelyDomainDetectFile(name))              { node._domainDetectHint = true; detected = true; }
  if (isLikelyBrowserPluginFile(name, parentDir))  { node._browserPluginHint = true; detected = true; }
  if (isLikelyClipboardFile(name))                 { node._clipboardHint = true;    detected = true; }
  if (isLikelyNoteFile(name, parentDir, fullPath)) { node._notesHint = true;       detected = true; }
  if (isLikelyGrabbedFile(name, parentDir, fullPath)) { node._grabbedFileHint = true; detected = true; }
  if (isLikelyKeylogFile(name, parentDir, fullPath)) { node._keylogHint = true; detected = true; }
  return detected;
}

// Sampled rather than split whole: these dumps run to six figures of lines.
function isLikelyPasswordPool(text) {
  const pool = FILE_TYPE_PATTERNS.passwordPool;
  const source = String(text || '');
  let cursor = 0;
  let sampled = 0;
  let hits = 0;
  while (cursor < source.length && sampled < pool.sampleLines) {
    let end = source.indexOf('\n', cursor);
    if (end === -1) end = source.length;
    const line = source.slice(cursor, end).trim();
    cursor = end + 1;
    if (!line) continue;
    sampled += 1;
    if (pool.linePattern.test(line)) hits += 1;
  }
  if (sampled < pool.minLines) return false;
  return hits / sampled >= pool.minRatio;
}

// Content fallback for files no filename rule claimed. Combolist/ULP pools carry
// no usable name, so they can only be recognised once their text is loaded.
function applyContentDetectionHints(node, text) {
  if (!node) return false;
  if (Object.entries(node).some(([key, value]) => value && key.endsWith('Hint'))) return false;
  if (!isLikelyPasswordPool(text)) return false;
  node._passwordFileHint = true;
  return true;
}

// Promote every aggregate-password file to a real password file. Aggregates may
// be supersets of the per-profile files, so suppressing them risks dropping
// rows; exact (url,user,pass) duplicates are removed at the credential layer.
function reconcileAggregatePasswordFiles(tree) {
  if (!tree) return;
  const aggregates = [];
  walk(tree);

  for (const node of aggregates) {
    node._passwordFileHint = true;
    delete node._passwordFileAggregateHint;
  }

  function walk(node) {
    if (!node) return;
    if (node._passwordFileAggregateHint) aggregates.push(node);
    if (node.children) {
      for (const child of Object.values(node.children)) walk(child);
    }
  }
}

export { applyDetectionHints, applyContentDetectionHints, reconcileAggregatePasswordFiles };
