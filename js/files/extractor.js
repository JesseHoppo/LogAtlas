// Archive extraction

import { state, on, emit, setLoading, addError, setRememberedPassword } from '../core/state.js';
import {
  isZipFile,
  isArchiveFile,
  isJunkFile,
  isMacOSMetadata,
  looksLikeText,
} from '../core/utils.js';
import { promptForPassword, isRememberChecked } from './password.js';
import {
  applyDetectionHints,
  applyContentDetectionHints,
  reconcileAggregatePasswordFiles,
} from '../analysis/detection.js';
import { HINT_KEYS, FILE_TYPE_TO_HINT } from './fileTypeRegistry.js';
import { LIMITS } from '../core/definitions/patterns.js';
import { collapseSingleWrapper } from '../core/shared.js';

const MAX_DEPTH = 10;

// Enough leading text for the password-pool sampler. Entries past the cap are
// left unclassified rather than treated as a pool.
const CONTENT_SNIFF_BYTES = 64 * 1024;
const SNIFF_MAX_ENTRY_BYTES = 8 * 1024 * 1024;

// Decompressed bytes are cached so the pages that re-parse on every render, and
// on reanalyze, don't inflate twice. Wallet stores, screenshots and unclassified
// blobs are read once per pass and dominate a large log, so past this size they
// are handed back without being retained.
const RETAINED_CONTENT_MAX_BYTES = 2 * 1024 * 1024;
const ONE_SHOT_HINTS = ['_cryptoWalletHint', '_screenshotHint', '_grabbedFileHint'];

// A run walking a 900 MB archive is still going when the analyst clears the case
// and drops the next one. Every run carries the generation it began in, and a
// reset retires it: the abandoned walk stops where it is instead of spending the
// new case's budget and publishing its tree over the live one.
let _generation = 0;
on('reset', () => { _generation += 1; });

// Byte and entry accumulators for one case. `extractFile` opens a case, and so
// does the first `addFilesToTree` of a container; the add-more and paste drops
// that follow keep filling the same budget, so the cap spans every drop that
// builds one container rather than a single call. `reported` is a latch, cleared
// per drop so each one can surface an overflow error once.
function createBudget() {
  return { bytes: 0, entries: 0, reported: false, generation: _generation };
}

let _caseBudget = createBudget();

function abandoned(budget) {
  return budget.generation !== _generation;
}

function withinBudget(budget, extraBytes) {
  if (budget.entries >= LIMITS.maxEntries) return false;
  if (budget.bytes + (extraBytes || 0) > LIMITS.maxDecompressedBytes) return false;
  return true;
}

function reportBudgetExceeded(budget, path) {
  if (budget.reported) return;
  budget.reported = true;
  addError(`Extraction limit reached (${Math.round(LIMITS.maxDecompressedBytes / (1024 * 1024))} MB / ${LIMITS.maxEntries} entries); remaining contents left unexpanded near: ${path}`);
}

function reportArchiveRefused(budget, path, bytes, entries) {
  if (budget.reported) return;
  budget.reported = true;
  addError(`Archive declares ${Math.round(bytes / (1024 * 1024))} MB across ${entries} entries, past the extraction limit (${Math.round(LIMITS.maxDecompressedBytes / (1024 * 1024))} MB / ${LIMITS.maxEntries}); left unexpanded: ${path}`);
}

// libarchive lists an encrypted 7z or RAR but cannot decrypt either one, so a
// passphrase is only worth asking for when the bytes are something it can open.
// The name is no help — a `.7z` that is really a zip decrypts fine — so the
// magic decides.
const SEVEN_ZIP_MAGIC = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const RAR_MAGIC = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07];

async function supportsDecryption(file) {
  try {
    const head = new Uint8Array(await file.slice(0, 6).arrayBuffer());
    const matches = (magic) => magic.every((byte, i) => head[i] === byte);
    return !matches(SEVEN_ZIP_MAGIC) && !matches(RAR_MAGIC);
  } catch (_) {
    return true;
  }
}

// Lazy-load libarchive so it doesn't break the ZIP path if it fails
let _Archive = null;
async function getArchive() {
  if (!_Archive) {
    const mod = await import('../../lib/libarchive/libarchive.js');
    _Archive = mod.Archive;
    _Archive.init({
      workerUrl: new URL('../../lib/libarchive/worker-bundle.js', import.meta.url).href,
    });
  }
  return _Archive;
}

// Tree node factory. `_password` is retained on encrypted-zip-entry nodes so
// later reads (e.g. preview) don't re-prompt; it's cleared on resetState().

function createNode(name, opts = {}) {
  return {
    name,
    type: opts.type || 'file',
    size: opts.size || 0,
    depth: opts.depth || 0,
    isArchive: opts.isArchive || false,
    isNestedArchive: opts.isNestedArchive || false,
    encrypted: opts.encrypted || false,
    _zipEntry: opts.zipEntry || null,
    _password: opts.password || null,
    _blobContent: opts.blobContent || null,
    lastModified: opts.lastModified || null,
    // Null-prototype: an archive entry named `__proto__` or `constructor` is
    // a path segment, and writing it into a plain object mutates every object
    // in the page and loses the entry.
    children: opts.type === 'directory' ? Object.create(null) : undefined,
  };
}

// Insert path into tree, creating intermediate dirs. Archives may name a file
// and a directory identically: an existing file on the way down is promoted to a
// container (it keeps its payload), and a leaf landing on an occupied name is
// stored beside it rather than replacing it.
//
// An entry named `a/` thirty thousand times over builds a tree deep enough to
// overflow the stack in every walker that runs afterwards, which loses the whole
// case to one 1 KB member. The deepest path in a real log runs to a dozen or so
// segments, so anything past the cap is dropped here, where every caller is
// covered at once; callers get null and skip the entry.
function insertPath(root, pathSegments, nodeData) {
  if (pathSegments.length > LIMITS.flattenMaxDepth) {
    addError(`Skipped entry nested ${pathSegments.length} levels deep: ${abbreviatePath(pathSegments)}`);
    return null;
  }

  let current = root;
  for (let i = 0; i < pathSegments.length - 1; i++) {
    const seg = pathSegments[i];
    let child = current.children[seg];
    if (!child) {
      child = createNode(seg, { type: 'directory', depth: nodeData.depth });
      current.children[seg] = child;
    } else if (!child.children) {
      child.type = 'directory';
      child.children = Object.create(null);
    }
    current = child;
  }
  let leafName = pathSegments[pathSegments.length - 1];
  if (leafName) {
    if (nodeData.type === 'directory') {
      const existing = current.children[leafName];
      if (!existing) {
        current.children[leafName] = createNode(leafName, nodeData);
      } else {
        existing.type = 'directory';
        if (!existing.children) existing.children = Object.create(null);
      }
    } else {
      leafName = getUniqueChildName(current, leafName);
      current.children[leafName] = createNode(leafName, nodeData);
    }
  }
  return current.children ? current.children[leafName] : current;
}

function abbreviatePath(pathSegments) {
  return pathSegments.slice(0, 2).concat('...', pathSegments[pathSegments.length - 1]).join('/');
}

export function getUniqueChildName(parent, desiredName) {
  if (!parent?.children?.[desiredName]) return desiredName;

  const extIndex = desiredName.lastIndexOf('.');
  const hasExtension = extIndex > 0;
  const baseName = hasExtension ? desiredName.slice(0, extIndex) : desiredName;
  const extension = hasExtension ? desiredName.slice(extIndex) : '';

  let suffix = 2;
  let uniqueName = `${baseName} ${suffix}${extension}`;
  while (parent.children[uniqueName]) {
    suffix += 1;
    uniqueName = `${baseName} ${suffix}${extension}`;
  }

  return uniqueName;
}

function isInvalidPasswordError(error) {
  const message = String(error?.message || '').toLowerCase();
  return message.includes('password') || message.includes('invalid');
}

async function readZipEntryData(entry, label, initialPassword = null) {
  if (!entry.encrypted) {
    return {
      data: await entry.getData(new zip.Uint8ArrayWriter()),
      password: null,
    };
  }

  let password = initialPassword || state.rememberedPassword;
  let invalidPassword = false;

  while (true) {
    if (!password) {
      password = await promptForPassword(label, { invalid: invalidPassword });
      if (password === null) return null;
    }

    try {
      const data = await entry.getData(new zip.Uint8ArrayWriter(), { password });
      if (isRememberChecked()) {
        setRememberedPassword(password);
      }
      return { data, password };
    } catch (error) {
      if (!isInvalidPasswordError(error)) {
        throw error;
      }
      invalidPassword = true;
      password = null;
      setRememberedPassword(null);
    }
  }
}

// zip.js writer that keeps the leading `limit` bytes of an entry and drops the
// rest. Nothing here refuses a write, however far past the window it lands: a
// writer that fails strands the codec task holding it, and the getData after it
// never settles, so one oversized entry costs the whole archive. The entry is
// inflated in full either way; SNIFF_MAX_ENTRY_BYTES is what keeps that cheap.
function headSink(limit) {
  const chunks = [];
  let length = 0;

  return {
    writable: new WritableStream({
      write(chunk) {
        const room = limit - length;
        if (room <= 0) return;
        const part = chunk.length > room ? chunk.subarray(0, room) : chunk;
        chunks.push(part);
        length += part.length;
      },
    }),
    collect() {
      if (chunks.length === 1) return chunks[0];
      const head = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        head.set(chunk, offset);
        offset += chunk.length;
      }
      return head;
    },
  };
}

// Read without the password prompt loop: used for the content sniff, which must
// never interrupt extraction to ask about a file nothing has claimed yet. A short
// entry and an unreadable one both land here, and whatever arrived is what gets
// sampled.
async function readZipEntryHead(entry, password, limit) {
  const sink = headSink(limit);

  try {
    await entry.getData(sink, password ? { password } : undefined);
  } catch (_) { /* ignore */ }

  return sink.collect();
}

// Filename rules claim nothing on combolist/ULP pools, so their line shape is the
// only signal. The sampler needs the head of the file, nothing more.
const _sniffDecoder = new TextDecoder('utf-8', { fatal: false });

function sniffContentType(node, bytes) {
  if (!bytes || !looksLikeText(bytes)) return false;
  return applyContentDetectionHints(node, _sniffDecoder.decode(bytes.subarray(0, CONTENT_SNIFF_BYTES)));
}

// No extension test gates the sniff. It would pass over the very entries the
// sniff exists for — extensionless pools, and the `name.txt [Part N of M]`
// splits whose extension parses as `txt [part 1 of 2]` — and it decides nothing
// that the byte check inside sniffContentType does not already decide.
function wantsContentSniff(detected, name) {
  return !detected && !isArchiveFile(name);
}

async function sniffBlobContent(node, blob) {
  try {
    const head = blob.size > CONTENT_SNIFF_BYTES ? blob.slice(0, CONTENT_SNIFF_BYTES) : blob;
    return sniffContentType(node, new Uint8Array(await head.arrayBuffer()));
  } catch (_) {
    return false;
  }
}

function retainsContent(node, byteLength) {
  if (byteLength <= RETAINED_CONTENT_MAX_BYTES) return true;
  if (ONE_SHOT_HINTS.some(key => node[key])) return false;
  return HINT_KEYS.some(key => node[key]);
}

// Recursive: descends into nested archives.
async function extractIntoTree(root, zipData, basePath, depth, budget) {
  if (depth > MAX_DEPTH) {
    addError(`Max depth exceeded at: ${basePath}`);
    return;
  }

  let reader;
  try {
    const blob = new Blob([zipData]);
    reader = new zip.ZipReader(new zip.BlobReader(blob));
    const entries = await reader.getEntries();

    setLoading(`Extracting: ${basePath} (${entries.length.toLocaleString()} item${entries.length === 1 ? '' : 's'})`);

    for (const entry of entries) {
      if (abandoned(budget)) return;
      if (isMacOSMetadata(entry.filename)) continue;
      const leafName = entry.filename.split('/').filter(Boolean).pop();
      if (!leafName) continue;
      if (isJunkFile(leafName)) continue;

      const segments = entry.filename.split('/').filter(Boolean);

      if (entry.directory) {
        insertPath(root, segments, { type: 'directory', depth });
        continue;
      }

      const entryBytes = entry.uncompressedSize || 0;
      if (!withinBudget(budget, entryBytes)) {
        reportBudgetExceeded(budget, basePath + '/' + entry.filename);
        break;
      }
      budget.bytes += entryBytes;
      budget.entries += 1;

      const isZip = isZipFile(leafName);
      const isArchive = isArchiveFile(leafName);

      const nodeData = {
        type: 'file',
        size: entry.uncompressedSize || 0,
        depth,
        isArchive,
        isNestedArchive: isArchive,
        encrypted: entry.encrypted,
        lastModified: entry.lastModDate ? entry.lastModDate.getTime() : null,
        zipEntry: entry,
        password: entry.encrypted ? state.rememberedPassword : null,
      };

      const fileNode = insertPath(root, segments, nodeData);
      if (!fileNode) continue;
      const parentDir = segments.length >= 2 ? segments[segments.length - 2] : '';
      const detected = applyDetectionHints(fileNode, leafName, parentDir, entry.filename);

      // insertPath renames a leaf that collides with a sibling, so the tree path
      // is the only one that leads back to this node.
      const fullPath = basePath + '/' + segments.slice(0, -1).concat(fileNode.name).join('/');

      // The size cap is this path's alone: sampling an entry costs a whole
      // inflate here, where the libarchive and loose paths already hold their
      // bytes. It sits well above the largest pool a log carries, so it stops
      // grabbed media and nothing that the sniff would have claimed.
      if (wantsContentSniff(detected, leafName) && entryBytes <= SNIFF_MAX_ENTRY_BYTES) {
        const head = await readZipEntryHead(entry, fileNode._password || state.rememberedPassword, CONTENT_SNIFF_BYTES);
        sniffContentType(fileNode, head);
      }

      if (isArchive) {
        try {
          const nestedEntry = await readZipEntryData(entry, fullPath, fileNode._password);
          if (!nestedEntry) {
            addError(`Skipped encrypted file: ${fullPath}`);
            continue;
          }

          const { data: nestedData, password } = nestedEntry;
          const node = fileNode;
          node._password = password;
          node.type = 'directory';
          node.isArchive = true;
          node.isNestedArchive = true;
          if (!node.children) node.children = Object.create(null);

          if (isZip) {
            await extractIntoTree(node, nestedData.buffer, fullPath, depth + 1, budget);
          } else {
            const nestedFile = new File([nestedData], leafName);
            await extractArchiveIntoTree(node, nestedFile, fullPath, depth + 1, budget, password);
          }
        } catch (err) {
          addError(`Failed to extract nested archive: ${fullPath} - ${err.message}`);
        }
      }
    }

    await reader.close();
  } catch (err) {
    addError(`Failed to read ZIP: ${basePath} - ${err.message}`);
    if (reader) {
      try { await reader.close(); } catch (_) { /* ignore */ }
    }
  }
}

// Non-ZIP extraction (libarchive)

// getFilesObject() seeds the tree with lazy entry handles; extractFiles() swaps in
// a File for every entry it could read. A handle still in place came back without
// data, and must not be walked as if it were a directory.
function isEntryLeaf(value) {
  return value instanceof File || typeof value?.extract === 'function';
}

function declaredTotals(obj, totals) {
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (isMacOSMetadata(key)) continue;
    if (isJunkFile(key.toLowerCase())) continue;
    totals.entries += 1;
    if (isEntryLeaf(value)) totals.bytes += value.size || 0;
    else if (value && typeof value === 'object') declaredTotals(value, totals);
  }
  return totals;
}

async function walkExtractedFiles(obj, depth, root, parentPath, counts, budget) {
  for (const key of Object.keys(obj)) {
    if (abandoned(budget)) return counts;
    const value = obj[key];
    if (isMacOSMetadata(key) || isJunkFile(key.toLowerCase())) { counts.filtered += 1; continue; }

    const segments = parentPath.concat(key);

    if (isEntryLeaf(value)) {
      if (!withinBudget(budget, value.size || 0)) { reportBudgetExceeded(budget, segments.join('/')); counts.unexpanded += 1; continue; }
      budget.bytes += value.size || 0;
      budget.entries += 1;

      const isArchive = isArchiveFile(key);
      const nodeData = {
        type: 'file',
        size: value.size || 0,
        depth,
        isArchive,
        isNestedArchive: isArchive,
        encrypted: false,
        // The wasm build exposes only archive_entry_mtime_nsec, the sub-second
        // fraction, so entry times are unrecoverable here. A File built without
        // one reports the moment it was extracted, which the capture-date
        // fallbacks would read as the log having been taken today.
        lastModified: null,
        blobContent: value instanceof File ? value : null,
      };

      const fileNode = insertPath(root, segments, nodeData);
      if (!fileNode) { counts.filtered += 1; continue; }
      const parentDir = segments.length >= 2 ? segments[segments.length - 2] : '';
      const detected = applyDetectionHints(fileNode, key, parentDir, segments.join('/'));
      if (wantsContentSniff(detected, key) && fileNode._blobContent) {
        await sniffBlobContent(fileNode, fileNode._blobContent);
      }
      counts.files += 1;
    } else if (value && typeof value === 'object') {
      if (!withinBudget(budget, 0)) { reportBudgetExceeded(budget, segments.join('/')); counts.unexpanded += 1; continue; }
      budget.entries += 1;
      if (!insertPath(root, segments, { type: 'directory', depth })) { counts.filtered += 1; continue; }
      await walkExtractedFiles(value, depth + 1, root, segments, counts, budget);
    }
  }

  return counts;
}

async function extractArchiveIntoTree(root, file, basePath, depth, budget, parentPassword = null) {
  if (depth > MAX_DEPTH) {
    addError(`Max depth exceeded at: ${basePath}`);
    return;
  }

  // The wasm build is fetched on first use and can fail on its own; letting that
  // out of here would abandon the whole drop over one member.
  let Archive;
  try {
    Archive = await getArchive();
  } catch (err) {
    addError(`Archive support failed to load: ${basePath} - ${err.message}`);
    return;
  }

  let invalidPassword = false;
  let encrypted = false;
  let decryptable = true;
  let attempts = 0;

  // Password retry loop: re-open on each iteration since the archive object
  // isn't reusable after a failed extract. Bounded, so a file that fails the
  // same way every time ends with an error rather than a spinning tab.
  while (attempts < PASSWORD_ATTEMPT_LIMIT) {
    if (abandoned(budget)) return;
    attempts += 1;
    let archive = null;
    try {
      archive = await Archive.open(file);
      const hasEncrypted = await archive.hasEncryptedData();
      encrypted = hasEncrypted;

      if (hasEncrypted) decryptable = await supportsDecryption(file);

      // Whatever sits outside the encrypted members is still worth having, so
      // an archive nothing can decrypt is read rather than skipped.
      if (hasEncrypted && decryptable) {
        // Carry the parent archive's password into the first attempt so a nested
        // archive inside an encrypted zip opens without re-prompting.
        let password = invalidPassword ? null : (parentPassword || state.rememberedPassword);
        if (!password) {
          password = await promptForPassword(basePath, { invalid: invalidPassword });
          if (password === null) {
            addError(`Skipped encrypted archive: ${basePath}`);
            try { await archive.close?.(); } catch (_) { /* ignore */ }
            return;
          }
          if (isRememberChecked()) setRememberedPassword(password);
        }
        await archive.usePassword(password);
      }

      setLoading(`Extracting: ${basePath}`);

      // libarchive expands the whole archive into memory in one call, so the
      // budget has to be settled against the declared sizes first; a bomb is
      // refused here instead of being caught after it has already been inflated.
      const declared = declaredTotals(await archive.getFilesObject(), { bytes: 0, entries: 0 });
      if (!withinBudget(budget, declared.bytes) || budget.entries + declared.entries > LIMITS.maxEntries) {
        reportArchiveRefused(budget, basePath, declared.bytes, declared.entries);
        try { await archive.close?.(); } catch (_) { /* ignore */ }
        return;
      }

      const extracted = await archive.extractFiles();
      const counts = await walkExtractedFiles(extracted, depth, root, [], { files: 0, filtered: 0, unexpanded: 0 }, budget);
      // An archive holding nothing but OS metadata is empty, not broken, and the
      // budget stop has already reported itself.
      if (counts.files === 0 && counts.unexpanded === 0) {
        if (hasEncrypted && !decryptable) {
          addError(`Encrypted archive left unopened: ${basePath} - 7z and RAR encryption cannot be decrypted here; unpack it outside the browser`);
        } else if (hasEncrypted) {
          addError(`No files could be decrypted from: ${basePath} - wrong password or unsupported encryption`);
        } else if (counts.filtered === 0) {
          addError(`Archive contained no readable files: ${basePath}`);
        }
      }
      await extractNestedArchives(root, basePath, depth, budget);
      return;
    } catch (err) {
      try { await archive?.close?.(); } catch (_) { /* ignore */ }
      // Only an archive that actually carries encrypted data can have the wrong
      // password; anything else is a broken file.
      if (encrypted && decryptable && isInvalidPasswordError(err)) {
        invalidPassword = true;
        setRememberedPassword(null);
        continue;
      }
      addError(`Failed to read archive: ${basePath} - ${err.message}`);
      return;
    }
  }

  addError(`Could not decrypt: ${basePath} - wrong password`);
}

// Recurse into nested archives
async function extractNestedArchives(root, basePath, depth, budget) {
  if (!root.children) return;

  for (const child of Object.values(root.children)) {
    if (abandoned(budget)) return;
    if (child.type === 'directory') {
      await extractNestedArchives(child, basePath + '/' + child.name, depth, budget);
      continue;
    }

    if (!child._blobContent || !isArchiveFile(child.name)) continue;

    try {
      const nestedFile = child._blobContent instanceof File
        ? child._blobContent
        : new File([child._blobContent], child.name);

      child.type = 'directory';
      child.isArchive = true;
      child.isNestedArchive = true;
      if (!child.children) child.children = Object.create(null);

      const nestedPath = basePath + '/' + child.name;

      if (isZipFile(child.name)) {
        const arrayBuffer = await nestedFile.arrayBuffer();
        await extractIntoTree(child, arrayBuffer, nestedPath, depth + 1, budget);
      } else {
        await extractArchiveIntoTree(child, nestedFile, nestedPath, depth + 1, budget);
      }
    } catch (err) {
      addError(`Failed to extract nested archive: ${child.name} - ${err.message}`);
    }
  }
}

// Decompress a single file on demand

async function loadFileContent(node) {
  if (!node || node.type === 'directory') return null;
  if (node._cachedContent) return node._cachedContent;

  // libarchive path
  if (node._blobContent) {
    try {
      const buf = await node._blobContent.arrayBuffer();
      const result = new Uint8Array(buf);
      if (retainsContent(node, result.length)) node._cachedContent = result;
      return result;
    } catch (err) {
      console.warn(`Failed to read file content: ${node.name} - ${err.message}`);
      return null;
    }
  }

  // zip.js path
  const entry = node._zipEntry;
  if (!entry) return null;

  try {
    const result = await readZipEntryData(entry, node.name, node._password);
    if (!result) return null;

    node._password = result.password;
    if (retainsContent(node, result.data.length)) node._cachedContent = result.data;
    return result.data;
  } catch (err) {
    console.warn(`Failed to read file content: ${node.name} - ${err.message}`);
    return null;
  }
}

// Public API

async function extractFile(file) {
  if (!isArchiveFile(file.name)) {
    throw new Error('extractFile expects an archive input');
  }

  state.rootZipName = file.name;
  state.sourceFile = file;
  setLoading('Reading archive...');
  _caseBudget = createBudget();
  const budget = _caseBudget;

  const root = createNode(file.name, { type: 'directory', depth: 0 });

  if (isZipFile(file.name)) {
    const arrayBuffer = await file.arrayBuffer();
    await extractIntoTree(root, arrayBuffer, file.name, 0, budget);
  } else {
    await extractArchiveIntoTree(root, file, file.name, 0, budget);
  }

  if (abandoned(budget)) return;

  reconcileAggregatePasswordFiles(root);
  const collapsed = collapseSingleWrapper(root);
  state.fileTree = collapsed;
  state.rootZipName = collapsed.name;
  state.flatFiles = flattenTree(collapsed, collapsed.name);
  setLoading(null);
  emit('extracted');
}

function getNodeAtPath(pathSegments) {
  let node = state.fileTree;
  if (!node) return null;
  for (const seg of pathSegments) {
    if (!node.children || !node.children[seg]) return null;
    node = node.children[seg];
  }
  return node;
}

function getChildrenList(node) {
  if (!node || !node.children) return [];
  return Object.values(node.children).sort((a, b) => {
    const aIsDir = a.type === 'directory';
    const bIsDir = b.type === 'directory';
    if (aIsDir && !bIsDir) return -1;
    if (!aIsDir && bIsDir) return 1;
    return a.name.localeCompare(b.name);
  });
}

function countChildren(node) {
  if (!node || !node.children) return 0;
  return Object.keys(node.children).length;
}

function flattenTree(root, basePath = '') {
  const result = [];
  if (!root || !root.children) return result;

  for (const child of Object.values(root.children)) {
    const path = basePath ? basePath + '/' + child.name : child.name;
    result.push({
      name: child.name,
      path,
      type: child.type,
      size: child.size || 0,
      depth: child.depth || 0,
      isNestedArchive: child.isNestedArchive || false,
      encrypted: child.encrypted || false,
      ...Object.fromEntries(HINT_KEYS.map(k => [k, child[k] || false])),
    });
    if (child.type === 'directory' && child.children) {
      result.push(...flattenTree(child, path));
    }
  }
  return result;
}

function applyManualType(node, fileType) {
  for (const key of Object.keys(node)) {
    if (key.endsWith('Hint')) delete node[key];
  }
  delete node._parseConfig;
  delete node._parsedRows;

  const hint = FILE_TYPE_TO_HINT[fileType];
  if (hint) node[hint] = true;
}

async function addFilesToTree(files) {
  // Reset the budget only when starting a fresh container; it must accumulate
  // across repeated drops so the decompressed-size cap is per-session, not per-call.
  resetBudgetReport();
  if (!state.fileTree) {
    resetExtractionBudget();
    state.fileTree = createNode(state.virtualContainerName || 'Uploaded Files', {
      type: 'directory',
      depth: 0,
    });
    state.rootZipName = state.fileTree.name;
  }

  const root = state.fileTree;
  const needsTypeSelection = [];

  for (const file of files) {
    setLoading(`Processing: ${file.name}`);
    const storedName = getUniqueChildName(root, file.name);

    if (isArchiveFile(file.name)) {
      const archiveRoot = createNode(storedName, { type: 'directory', depth: 1 });
      root.children[storedName] = archiveRoot;

      if (isZipFile(file.name)) {
        const arrayBuffer = await file.arrayBuffer();
        await extractIntoTree(archiveRoot, arrayBuffer, storedName, 1);
      } else {
        await extractArchiveIntoTree(archiveRoot, file, storedName, 1);
      }
    } else {
      const fileNode = createNode(storedName, {
        type: 'file',
        size: file.size,
        depth: 1,
        previewable: isPreviewable(file.name),
        blobContent: file,
      });
      root.children[storedName] = fileNode;

      const detected = applyDetectionHints(fileNode, file.name, '', storedName);
      if (!detected && !await sniffBlobContent(fileNode, file)) {
        needsTypeSelection.push({ name: storedName, node: fileNode });
      }
    }
  }

  reconcileAggregatePasswordFiles(root);
  const childNames = Object.keys(root.children);
  if (childNames.length === 1 && root.children[childNames[0]].type === 'directory') {
    const collapsed = collapseSingleWrapper(root);
    state.fileTree = collapsed;
    state.rootZipName = collapsed.name;
    state.flatFiles = flattenTree(collapsed, collapsed.name);
  } else {
    state.flatFiles = flattenTree(root, state.rootZipName);
  }
  setLoading(null);

  return needsTypeSelection;
}

export { extractFile, getNodeAtPath, getChildrenList, countChildren, loadFileContent, flattenTree, applyManualType, addFilesToTree };
