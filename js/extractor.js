// Archive extraction

import { state, emit, setLoading, addError, setRememberedPassword } from './state.js';
import {
  isZipFile,
  isArchiveFile,
  isNonZipArchive,
  isPreviewable,
  isJunkFile,
  isMacOSMetadata,
} from './utils.js';
import { promptForPassword, showPasswordError, isRememberChecked } from './password.js';
import { applyDetectionHints } from './detection.js';

const MAX_DEPTH = 10;

// Lazy-load libarchive so it doesn't break the ZIP path if it fails
let _Archive = null;
async function getArchive() {
  if (!_Archive) {
    const mod = await import('../lib/libarchive/libarchive.js');
    _Archive = mod.Archive;
    _Archive.init({
      workerUrl: new URL('../lib/libarchive/worker-bundle.js', import.meta.url).href,
    });
  }
  return _Archive;
}

// Tree node factory

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
    _zipData: opts.zipData || null,
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
        zipData,
        password: entry.encrypted ? state.rememberedPassword : null,
      };

      const fileNode = insertPath(root, segments, nodeData);
      const parentDir = segments.length >= 2 ? segments[segments.length - 2] : '';
      applyDetectionHints(fileNode, leafName, parentDir);

      const fullPath = basePath + '/' + entry.filename;

      if (isArchive) {
        try {
          let nestedData;

          if (entry.encrypted) {
            let password = state.rememberedPassword;
            let success = false;

            while (!success) {
              if (!password) {
                password = await promptForPassword(fullPath);
                if (password === null) {
                  addError(`Skipped encrypted file: ${fullPath}`);
                  break;
                }
              }
              try {
                nestedData = await entry.getData(new zip.Uint8ArrayWriter(), { password });
                success = true;
                if (isRememberChecked()) {
                  setRememberedPassword(password);
                }
              } catch (err) {
                if (err.message.includes('password') || err.message.includes('Invalid')) {
                  showPasswordError();
                  password = null;
                  setRememberedPassword(null);
                } else {
                  throw err;
                }
              }
            }
            if (!success) continue;
          } else {
            nestedData = await entry.getData(new zip.Uint8ArrayWriter());
          }

          // Find the node we inserted so we can attach children
          let node = root;
          for (const seg of segments) {
            if (!node.children[seg]) break;
            node = node.children[seg];
          }
          node.type = 'directory';
          node.isArchive = true;
          node.isNestedArchive = true;
          if (!node.children) node.children = {};

          if (isZip) {
            await extractIntoTree(node, nestedData.buffer, fullPath, depth + 1);
          } else {
            const nestedBlob = new Blob([nestedData]);
            const nestedFile = new File([nestedBlob], leafName);
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

function walkExtractedFiles(obj, basePath, depth, root, parentPath) {
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (isMacOSMetadata(key)) continue;
    if (isJunkFile(key.toLowerCase())) continue;

    const fullPath = basePath + '/' + key;
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
      applyDetectionHints(fileNode, key, parentDir);
    } else if (value && typeof value === 'object') {
      insertPath(root, segments, { type: 'directory', depth });
      walkExtractedFiles(value, fullPath, depth + 1, root, segments);
    }
  }
}

async function extractArchiveIntoTree(root, file, basePath, depth) {
  if (depth > MAX_DEPTH) {
    addError(`Max depth exceeded at: ${basePath}`);
    return;
  }

  let archive;
  try {
    const Archive = await getArchive();
    archive = await Archive.open(file);

    const hasEncrypted = await archive.hasEncryptedData();
    if (hasEncrypted) {
      let password = state.rememberedPassword;
      if (!password) {
        password = await promptForPassword(basePath);
        if (password && isRememberChecked()) {
          setRememberedPassword(password);
        }
      }
      if (password) {
        await archive.usePassword(password);
      }
    }

    setLoading(`Extracting: ${basePath}`);

    const extracted = await archive.extractFiles();
    walkExtractedFiles(extracted, basePath, depth, root, []);
    await extractNestedArchives(root, basePath, depth);
  } catch (err) {
    addError(`Failed to read archive: ${basePath} - ${err.message}`);
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
  const zipData = node._zipData;
  if (!entry || !zipData) return null;

  try {
    let data;
    if (entry.encrypted) {
      const password = node._password || state.rememberedPassword;
      if (!password) return null;
      data = await entry.getData(new zip.Uint8ArrayWriter(), { password });
    } else {
      data = await entry.getData(new zip.Uint8ArrayWriter());
    }
    node._cachedContent = data;
    return data;
  } catch {
    return null;
  }
}

// Public API

async function extractFile(file) {
  state.rootZipName = file.name;
  state.sourceFile = file;
  setLoading('Reading archive...');

  const root = createNode(file.name, { type: 'directory', depth: 0 });

  if (isZipFile(file.name)) {
    const arrayBuffer = await file.arrayBuffer();
    await extractIntoTree(root, arrayBuffer, file.name, 0);
  } else if (isArchiveFile(file.name)) {
    await extractArchiveIntoTree(root, file, file.name, 0);
  } else {
    // Plain file
    const fileNode = createNode(file.name, {
      type: 'file',
      size: file.size,
      depth: 0,
      previewable: isPreviewable(file.name),
      blobContent: file,
    });
    root.children[file.name] = fileNode;
    applyDetectionHints(fileNode, file.name, '');
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
      _passwordFileHint: child._passwordFileHint || false,
      _cookieFileHint: child._cookieFileHint || false,
      _sysInfoHint: child._sysInfoHint || false,
      _autofillHint: child._autofillHint || false,
      _historyHint: child._historyHint || false,
      _screenshotHint: child._screenshotHint || false,
    });
    if (child.type === 'directory' && child.children) {
      result.push(...flattenTree(child, path));
    }
  }
  return result;
}

function applyManualType(node, fileType) {
  delete node._passwordFileHint;
  delete node._cookieFileHint;
  delete node._autofillHint;
  delete node._historyHint;
  delete node._sysInfoHint;
  delete node._parseConfig;

  switch (fileType) {
    case 'credentials':
      node._passwordFileHint = true;
      break;
    case 'cookies':
      node._cookieFileHint = true;
      break;
    case 'autofill':
      node._autofillHint = true;
      break;
    case 'history':
      node._historyHint = true;
      break;
    case 'sysinfo':
      node._sysInfoHint = true;
      break;
  }
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

    if (isArchiveFile(file.name)) {
      const archiveRoot = createNode(file.name, { type: 'directory', depth: 1 });
      root.children[file.name] = archiveRoot;

      if (isZipFile(file.name)) {
        const arrayBuffer = await file.arrayBuffer();
        await extractIntoTree(archiveRoot, arrayBuffer, file.name, 1);
      } else {
        await extractArchiveIntoTree(archiveRoot, file, file.name, 1);
      }
    } else {
      const fileNode = createNode(file.name, {
        type: 'file',
        size: file.size,
        depth: 1,
        previewable: isPreviewable(file.name),
        blobContent: file,
      });
      root.children[file.name] = fileNode;

      const detected = applyDetectionHints(fileNode, file.name, '');
      if (!detected) {
        needsTypeSelection.push({ file, node: fileNode });
      }
    }
  }

  state.flatFiles = flattenTree(root, state.rootZipName);
  setLoading(null);

  return needsTypeSelection;
}

export { extractFile, getNodeAtPath, getChildrenList, countChildren, loadFileContent, flattenTree, applyManualType, addFilesToTree };
