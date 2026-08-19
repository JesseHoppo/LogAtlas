import { state, on, emit, resetState, setMultiFileMode } from '../core/state.js';
import { extractFile, flattenTree, addFilesToTree, applyManualType, getUniqueChildName } from '../files/extractor.js';
import { formatBytes, isArchiveFile } from '../core/utils.js';
import { showNotification } from '../core/shared.js';
import { promptForFileType } from '../files/fileTypeModal.js';
import { openPasteModal } from '../files/pasteText.js';
import { countLabel } from '../pages/shared.js';

// What the analyst handed over, kept apart from the tree: state.flatFiles is
// post-extraction, so counting it reports nested-archive members and their
// decompressed sizes instead of the dropped files.
const sources = [];

// A drop still walking a large archive when the analyst clears the case belongs
// to a case that no longer exists. The extractor already refuses to publish that
// run's tree; this counter is what stops the handlers here from re-rendering and
// re-analysing the live case on the abandoned run's behalf.
let generation = 0;

// Past this many, prompting one file at a time is a wall of modals rather than a
// question. The files land untyped and the Files browser types them in bulk.
const TYPE_PROMPT_LIMIT = 20;

// Deep enough for any real case folder, shallow enough that a symlink loop in a
// dropped directory cannot spin forever.
const MAX_DROP_DEPTH = 24;

// Where an artifact brought in after the case opened is filed. A case unpacked
// from an archive is evidence as the archive carried it: dropping the analyst's
// own files in among its members would make every path in the tree, the exports
// and the reports ambiguous about which is which. Loose-file cases are entirely
// analyst-supplied already, so they keep the flat shape they have always had.
const ADDED_FOLDER = 'Added files';

// Resolved once per case, because the name is only free the first time.
let addedFolder = null;

function recordSources(files) {
  for (const file of files) sources.push({ name: file.name, size: file.size || 0 });
}

// A dropped folder is not in dataTransfer.files at all: it appears there as one
// zero-content entry that reads back empty, so the only way to see inside it is
// webkitGetAsEntry. The item list is neutered as soon as the drop handler yields,
// so the entries are taken before anything awaits.
function snapshotDropEntries(dataTransfer) {
  const items = dataTransfer.items ? Array.from(dataTransfer.items) : [];
  const entries = items
    .filter((item) => item.kind === 'file')
    .map((item) => (item.webkitGetAsEntry ? item.webkitGetAsEntry() : null))
    .filter(Boolean);
  return entries.length > 0 ? entries : null;
}

// webkitRelativePath is a prototype getter that reports '' for any File the
// directory picker did not produce. Shadowing it with an own property is what
// lets a dragged folder carry the same path a directory pick would.
function setRelativePath(file, relativePath) {
  Object.defineProperty(file, 'webkitRelativePath', {
    value: relativePath,
    enumerable: true,
    configurable: true,
  });
  return file;
}

function withRelativePath(file, relativePath) {
  if (file.webkitRelativePath) return file;
  return setRelativePath(file, relativePath);
}

function entryFile(entry) {
  return new Promise((resolve) => entry.file(resolve, () => resolve(null)));
}

function readEntryBatch(reader) {
  return new Promise((resolve) => reader.readEntries(resolve, () => resolve([])));
}

// A directory reader hands back its children in batches and signals the end with
// an empty one, so every reader has to be drained in a loop.
async function collectEntry(entry, prefix, depth, out) {
  if (entry.isFile) {
    const file = await entryFile(entry);
    if (file) out.push(withRelativePath(file, prefix + file.name));
    return;
  }
  if (!entry.isDirectory || depth >= MAX_DROP_DEPTH) return;

  const reader = entry.createReader();
  const childPrefix = `${prefix}${entry.name}/`;
  for (;;) {
    const batch = await readEntryBatch(reader);
    if (batch.length === 0) return;
    for (const child of batch) await collectEntry(child, childPrefix, depth + 1, out);
  }
}

// Returns null when the drop carried no files at all (a dragged link or
// selection), and an empty array when it carried only unreadable ones.
async function filesFromDrop(dataTransfer) {
  if (!dataTransfer) return null;

  const entries = snapshotDropEntries(dataTransfer);
  const plain = Array.from(dataTransfer.files || []);
  if (!entries) return plain.length > 0 ? plain : null;

  const collected = [];
  for (const entry of entries) await collectEntry(entry, '', 0, collected);
  return collected;
}

function dropCarriesFiles(dataTransfer) {
  return !!dataTransfer && Array.from(dataTransfer.types || []).includes('Files');
}

// An archive still names the case after something has been added to it: folding
// it into a bare count would hide which archive is open.
function caseLabel() {
  if (sources.length === 1) return sources[0].name;
  if (!state.isMultiFileMode && sources.length > 1) {
    return `${sources[0].name} + ${countLabel(sources.length - 1, 'file')}`;
  }
  return countLabel(sources.length, 'file');
}

function updateCaseSummary() {
  const totalSize = sources.reduce((sum, source) => sum + source.size, 0);
  document.getElementById('currentFileName').textContent = caseLabel();
  document.getElementById('currentFileSize').textContent = formatBytes(totalSize);
}

function startFreshUI({ name, sizeBytes, multiFile }) {
  resetState();
  setMultiFileMode(multiFile);

  document.getElementById('dropZone').style.display = 'none';
  document.getElementById('uploadInfo').style.display = 'none';
  document.getElementById('resetZone').classList.add('visible');

  document.getElementById('currentFileName').textContent = name;
  document.getElementById('currentFileSize').textContent = formatBytes(sizeBytes);

  document.getElementById('addMoreBtn').classList.remove('hidden');
  document.getElementById('pasteMoreBtn').classList.remove('hidden');

  document.getElementById('results').classList.remove('visible');
  document.getElementById('errorList').classList.remove('visible');
  document.getElementById('loading').classList.add('visible');
}

async function handleFiles(files, { resetUI }) {
  const loading = document.getElementById('loading');

  const fileArray = Array.from(files);
  if (fileArray.length === 0) return;

  // Anything arriving over an open case joins it, whether that case came out of
  // an archive or out of a folder drop.
  if (state.fileTree) {
    await handleAddMoreFiles(fileArray);
    return;
  }

  const isMultiFile = fileArray.length > 1 ||
    (fileArray.length === 1 && !isArchiveFile(fileArray[0].name));

  const name = isMultiFile
    ? (fileArray.length === 1 ? fileArray[0].name : countLabel(fileArray.length, 'file'))
    : fileArray[0].name;
  const sizeBytes = isMultiFile
    ? fileArray.reduce((sum, f) => sum + f.size, 0)
    : fileArray[0].size;
  startFreshUI({ name, sizeBytes, multiFile: isMultiFile });
  recordSources(fileArray);

  const gen = generation;

  try {
    if (isMultiFile) {
      const { needsTypeSelection } = await addFilesToTree(fileArray);
      await processTypeSelectionQueue(needsTypeSelection);
      if (gen !== generation) return;
      emit('extracted');
    } else {
      await extractFile(fileArray[0]);
    }
  } catch (err) {
    if (gen !== generation) return;
    loading.classList.remove('visible');
    showNotification(`Failed to process files: ${err.message}`, 'error');
    resetUI();
  }
}

function addedFolderName() {
  if (!state.fileTree || state.isMultiFileMode) return null;
  if (!addedFolder) addedFolder = getUniqueChildName(state.fileTree, ADDED_FOLDER);
  return addedFolder;
}

function addedFolderParent(folder) {
  return folder ? state.fileTree?.children?.[folder] : state.fileTree;
}

// The tree path is rebuilt from webkitRelativePath, so pushing the folder onto
// the front of it files a whole dragged directory under the label instead of
// scattering its files beside it.
function rebase(files, folder) {
  if (!folder) return files;
  return files.map((file) => setRelativePath(file, `${folder}/${file.webkitRelativePath || file.name}`));
}

function destinationSuffix(folder) {
  return folder ? ` under "${folder}"` : '';
}

async function handleAddMoreFiles(files) {
  const loading = document.getElementById('loading');

  const fileArray = Array.from(files);
  if (fileArray.length === 0 || !state.fileTree) return;

  const folder = addedFolderName();
  loading.classList.add('visible');

  const gen = generation;

  let failure = null;
  let added = 0;
  let failed = 0;
  try {
    // An archive dates its own capture; a file the analyst brought in later
    // carries the mtime of their disk, and letting that speak for the capture
    // would redate the case to the moment it was added.
    const result = await addFilesToTree(rebase(fileArray, folder), { trustMtime: !folder });
    added = result.added;
    failed = result.failed;
    await processTypeSelectionQueue(result.needsTypeSelection);
  } catch (err) {
    failure = err;
  }

  if (gen !== generation) return;

  // A file that throws part-way leaves everything before it in the tree, so
  // flatFiles is rebuilt either way. The file browser reads the tree and every
  // dataset page reads flatFiles; when the two disagree the case looks like it
  // is missing credentials rather than like an add that failed.
  if (state.fileTree) state.flatFiles = flattenTree(state.fileTree, state.rootZipName);

  recordSources(fileArray);
  updateCaseSummary();

  loading.classList.remove('visible');
  emit('reanalyze');

  const where = destinationSuffix(folder);

  // One unreadable member of a dropped folder does not make the add a failure,
  // so the count that landed leads and the shortfall is named after it.
  if (failure) showNotification(`Failed to add files: ${failure.message}`, 'error');
  else if (added === 0) showNotification(`Nothing readable in those ${countLabel(failed, 'file')}.`, 'error');
  else if (failed > 0) showNotification(`Added ${countLabel(added, 'file')}${where}; ${countLabel(failed, 'file')} could not be read.`, 'info');
  else showNotification(`Added ${countLabel(added, 'file')}${where}.`, 'info');
}

// Returns false when the case was cleared while this was still running. The
// File is built around the textarea contents, so its mtime is the paste moment
// and says nothing about the capture.
async function ingestPastedFile(file, fileName, type, folder) {
  const gen = generation;
  await addFilesToTree(rebase([file], folder), { trustMtime: false });
  if (gen !== generation) return false;

  const node = addedFolderParent(folder)?.children?.[fileName];
  if (node) {
    applyManualType(node, type);
  }

  if (state.fileTree) state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
  return true;
}

async function handlePasteText({ resetUI }) {
  const loading = document.getElementById('loading');

  const result = await openPasteModal({
    destination: state.fileTree ? addedFolderName() || '' : null,
  });
  if (!result) return;

  // Recomputed after the modal, which is open long enough for the case behind it
  // to have been cleared or loaded.
  const folder = addedFolderName();
  const { text, name, type } = result;
  const baseFileName = /\.[^./\\]+$/.test(name) ? name : `${name}.txt`;
  const fileName = getUniqueChildName(addedFolderParent(folder), baseFileName);

  const file = new File([text], fileName, { type: 'text/plain' });

  if (state.fileTree) {
    // Add to existing analysis
    loading.classList.add('visible');
    const gen = generation;
    try {
      if (!await ingestPastedFile(file, fileName, type, folder)) return;

      recordSources([file]);
      updateCaseSummary();

      loading.classList.remove('visible');
      emit('reanalyze');
      showNotification(`Added "${folder ? `${folder}/` : ''}${fileName}".`, 'info');
    } catch (err) {
      if (gen !== generation) return;

      // Whatever landed before the throw is in the tree already, so the derived
      // views are brought back into step with it rather than left behind.
      if (state.fileTree) state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
      loading.classList.remove('visible');
      emit('reanalyze');
      showNotification(`Failed to add pasted text: ${err.message}`, 'error');
    }
  } else {
    // Start new analysis
    startFreshUI({ name: fileName, sizeBytes: file.size, multiFile: true });
    recordSources([file]);

    const gen = generation;
    try {
      if (!await ingestPastedFile(file, fileName, type, null)) return;
      emit('extracted');
    } catch (err) {
      if (gen !== generation) return;
      loading.classList.remove('visible');
      showNotification(`Failed to process pasted text: ${err.message}`, 'error');
      resetUI();
    }
  }
}

async function processTypeSelectionQueue(files) {
  for (let i = 0; i < files.length; i++) {
    const { name, node } = files[i];
    const remaining = files.length - i - 1;

    const selectedType = await promptForFileType(name, remaining);
    applyManualType(node, selectedType);
  }

  if (files.length > 0 && state.fileTree) {
    state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
  }
}

export function initFileHandling({ resetUI }) {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const folderInput = document.getElementById('folderInput');

  on('reset', () => {
    sources.length = 0;
    addedFolder = null;
    generation += 1;
  });

  const boundHandleFiles = (files) => handleFiles(files, { resetUI });
  const boundHandlePasteText = () => handlePasteText({ resetUI });

  // Drag & drop / file input. Anywhere in the zone opens the file picker, so
  // only the folder button has to stop the click reaching it.
  dropZone.addEventListener('click', () => fileInput.click());

  document.getElementById('browseFolderBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    folderInput.click();
  });

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', (e) => {
    if (!dropZone.contains(e.relatedTarget)) {
      dropZone.classList.remove('drag-over');
    }
  });

  async function ingestDrop(dataTransfer) {
    const files = await filesFromDrop(dataTransfer);
    if (!files) return;
    if (files.length === 0) {
      showNotification('Nothing readable in that drop.', 'error');
      return;
    }
    boundHandleFiles(files);
  }

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    ingestDrop(e.dataTransfer);
  });

  // With a case loaded the drop zone is display:none, so every drop lands on
  // ordinary page chrome. Left to the browser, a file dropped there navigates
  // the tab to it and the case in memory goes with no prompt. Text dragged into
  // a field is the field's business and is left alone.
  function guardsDrop(e) {
    const target = e.target instanceof Element ? e.target : null;
    if (target && dropZone.contains(target)) return false;
    if (dropCarriesFiles(e.dataTransfer)) return true;
    return !target?.closest('input:not([type="file"]), textarea, [contenteditable="true"]');
  }

  window.addEventListener('dragover', (e) => {
    if (!guardsDrop(e)) return;
    e.preventDefault();
    if (!e.dataTransfer) return;
    e.dataTransfer.dropEffect = dropCarriesFiles(e.dataTransfer) ? 'copy' : 'none';
  });

  window.addEventListener('drop', (e) => {
    if (!guardsDrop(e)) return;
    e.preventDefault();
    if (!dropCarriesFiles(e.dataTransfer)) return;
    ingestDrop(e.dataTransfer);
  });

  for (const input of [fileInput, folderInput]) {
    input.addEventListener('change', (e) => {
      const files = e.target.files;
      if (files.length > 0) boundHandleFiles(files);
      e.target.value = '';
    });
  }

  document.getElementById('addMoreBtn').addEventListener('click', () => {
    document.getElementById('addMoreInput').click();
  });

  document.getElementById('addMoreInput').addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      handleAddMoreFiles(files);
      e.target.value = '';
    }
  });

  document.getElementById('pasteTextBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    boundHandlePasteText();
  });

  document.getElementById('pasteMoreBtn').addEventListener('click', () => {
    boundHandlePasteText();
  });

  // Return handleFiles for use by auto-load
  return { handleFiles: boundHandleFiles };
}
