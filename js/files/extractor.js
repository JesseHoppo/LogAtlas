// Archive extraction

import { state, emit, setLoading, addError, setRememberedPassword } from '../core/state.js';
import {
  isZipFile,
  isArchiveFile,
  isPreviewable,
  isJunkFile,
  isMacOSMetadata,
} from '../core/utils.js';
import { promptForPassword, isRememberChecked } from './password.js';
import { applyDetectionHints } from '../analysis/detection.js';
import { HINT_KEYS, FILE_TYPE_TO_HINT } from './fileTypeRegistry.js';

const MAX_DEPTH = 10;

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
    previewable: opts.previewable || false,
    _zipEntry: opts.zipEntry || null,
    _password: opts.password || null,
    _blobContent: opts.blobContent || null,
    lastModified: opts.lastModified || null,
    children: opts.type === 'directory' ? {} : undefined,
  };
}

// Insert path into tree, creating intermediate dirs
function insertPath(root, pathSegments, nodeData) {
  let current = root;
  for (let i = 0; i < pathSegments.length - 1; i++) {
    const seg = pathSegments[i];
    if (!current.children[seg]) {
      current.children[seg] = createNode(seg, {
        type: 'directory',
        depth: nodeData.depth,
      });
    }
    current = current.children[seg];
  }
  const leafName = pathSegments[pathSegments.length - 1];
  if (leafName) {
    if (nodeData.type === 'directory') {
      if (!current.children[leafName]) {
        current.children[leafName] = createNode(leafName, nodeData);
      } else {
        current.children[leafName].type = 'directory';
        if (!current.children[leafName].children) {
          current.children[leafName].children = {};
        }
      }
    } else {
      current.children[leafName] = createNode(leafName, nodeData);
    }
  }
  return current.children ? current.children[leafName] : current;
}

function getUniqueChildName(parent, desiredName) {
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

// Extract ZIP into tree (recursive for nested archives)
async function extractIntoTree(root, zipData, basePath, depth) {
  if (depth > MAX_DEPTH) {
    addError(`Max depth exceeded at: ${basePath}`);
    return;
  }

  let reader;
  try {
    const blob = new Blob([zipData]);
    reader = new zip.ZipReader(new zip.BlobReader(blob));
    const entries = await reader.getEntries();

    setLoading(`Extracting: ${basePath} (${entries.length} items)`);

    for (const entry of entries) {
      if (isMacOSMetadata(entry.filename)) continue;
      const leafName = entry.filename.split('/').filter(Boolean).pop();
      if (!leafName) continue;
      if (isJunkFile(leafName)) continue;

      const segments = entry.filename.split('/').filter(Boolean);

      if (entry.directory) {
        insertPath(root, segments, { type: 'directory', depth });
        continue;
      }

      const isZip = isZipFile(leafName);
      const isArchive = isArchiveFile(leafName);

      const nodeData = {
        type: 'file',
        size: entry.uncompressedSize || 0,
        depth,
        isArchive,
        isNestedArchive: isArchive,
        encrypted: entry.encrypted,
        previewable: isPreviewable(leafName),
        lastModified: entry.lastModDate ? entry.lastModDate.getTime() : null,
        zipEntry: entry,
        password: entry.encrypted ? state.rememberedPassword : null,
      };

      const fileNode = insertPath(root, segments, nodeData);
      const parentDir = segments.length >= 2 ? segments[segments.length - 2] : '';
      applyDetectionHints(fileNode, leafName, parentDir, entry.filename);

      const fullPath = basePath + '/' + entry.filename;

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
          if (!node.children) node.children = {};

          if (isZip) {
            await extractIntoTree(node, nestedData.buffer, fullPath, depth + 1);
          } else {
            const nestedFile = new File([nestedData], leafName);
            await extractArchiveIntoTree(node, nestedFile, fullPath, depth + 1);
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

function walkExtractedFiles(obj, depth, root, parentPath) {
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (isMacOSMetadata(key)) continue;
    if (isJunkFile(key.toLowerCase())) continue;

    const segments = parentPath.concat(key);

    if (value instanceof File) {
      const isArchive = isArchiveFile(key);
      const nodeData = {
        type: 'file',
        size: value.size || 0,
        depth,
        isArchive,
        isNestedArchive: isArchive,
        encrypted: false,
        previewable: isPreviewable(key),
        lastModified: value.lastModified || null,
        blobContent: value,
      };

      const fileNode = insertPath(root, segments, nodeData);
      const parentDir = segments.length >= 2 ? segments[segments.length - 2] : '';
      applyDetectionHints(fileNode, key, parentDir, segments.join('/'));
    } else if (value && typeof value === 'object') {
      insertPath(root, segments, { type: 'directory', depth });
      walkExtractedFiles(value, depth + 1, root, segments);
    }
  }
}

async function extractArchiveIntoTree(root, file, basePath, depth) {
  if (depth > MAX_DEPTH) {
    addError(`Max depth exceeded at: ${basePath}`);
    return;
  }

  const Archive = await getArchive();
  let invalidPassword = false;

  // Password retry loop: re-open on each iteration since the archive object
  // isn't reusable after a failed extract.
  while (true) {
    let archive = null;
    try {
      archive = await Archive.open(file);
      const hasEncrypted = await archive.hasEncryptedData();

      if (hasEncrypted) {
        let password = invalidPassword ? null : state.rememberedPassword;
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
      const extracted = await archive.extractFiles();
      walkExtractedFiles(extracted, depth, root, []);
      await extractNestedArchives(root, basePath, depth);
      return;
    } catch (err) {
      try { await archive?.close?.(); } catch (_) { /* ignore */ }
      if (isInvalidPasswordError(err)) {
        invalidPassword = true;
        setRememberedPassword(null);
        continue;
      }
      addError(`Failed to read archive: ${basePath} - ${err.message}`);
      return;
    }
  }
}

// Recurse into nested archives
async function extractNestedArchives(root, basePath, depth) {
  if (!root.children) return;

  for (const child of Object.values(root.children)) {
    if (child.type === 'directory') {
      await extractNestedArchives(child, basePath + '/' + child.name, depth);
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
      if (!child.children) child.children = {};

      const nestedPath = basePath + '/' + child.name;

      if (isZipFile(child.name)) {
        const arrayBuffer = await nestedFile.arrayBuffer();
        await extractIntoTree(child, arrayBuffer, nestedPath, depth + 1);
      } else {
        await extractArchiveIntoTree(child, nestedFile, nestedPath, depth + 1);
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
      node._cachedContent = result;
      return result;
    } catch {
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
    node._cachedContent = result.data;
    return result.data;
  } catch {
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

  const root = createNode(file.name, { type: 'directory', depth: 0 });

  if (isZipFile(file.name)) {
    const arrayBuffer = await file.arrayBuffer();
    await extractIntoTree(root, arrayBuffer, file.name, 0);
  } else {
    await extractArchiveIntoTree(root, file, file.name, 0);
  }

  state.fileTree = root;
  state.flatFiles = flattenTree(root, file.name);
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
  for (const key of HINT_KEYS) delete node[key];
  delete node._parseConfig;

  const hint = FILE_TYPE_TO_HINT[fileType];
  if (hint) node[hint] = true;
}

async function addFilesToTree(files) {
  if (!state.fileTree) {
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
      if (!detected) {
        needsTypeSelection.push({ name: storedName, node: fileNode });
      }
    }
  }

  state.flatFiles = flattenTree(root, state.rootZipName);
  setLoading(null);

  return needsTypeSelection;
}

export { extractFile, getNodeAtPath, getChildrenList, countChildren, loadFileContent, flattenTree, applyManualType, addFilesToTree };
