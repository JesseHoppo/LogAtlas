import { state, emit, resetState, setMultiFileMode } from '../core/state.js';
import { extractFile, flattenTree, addFilesToTree, applyManualType, getUniqueChildName } from '../files/extractor.js';
import { formatBytes, isArchiveFile } from '../core/utils.js';
import { showNotification } from '../core/shared.js';
import { promptForFileType } from '../files/fileTypeModal.js';
import { openPasteModal } from '../files/pasteText.js';

function updateMultiFileSummary() {
  const totalFiles = state.flatFiles.filter((file) => file.type === 'file').length;
  const totalSize = state.flatFiles.reduce(
    (sum, file) => sum + (file.type === 'file' ? (file.size || 0) : 0),
    0
  );
  document.getElementById('currentFileName').textContent = totalFiles === 1 ? '1 file' : `${totalFiles} files`;
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

  const addMoreBtn = document.getElementById('addMoreBtn');
  const pasteMoreBtn = document.getElementById('pasteMoreBtn');
  if (multiFile) {
    addMoreBtn.classList.remove('hidden');
    pasteMoreBtn.classList.remove('hidden');
  } else {
    addMoreBtn.classList.add('hidden');
    pasteMoreBtn.classList.add('hidden');
  }

  document.getElementById('results').classList.remove('visible');
  document.getElementById('errorList').classList.remove('visible');
  document.getElementById('loading').classList.add('visible');
}

async function handleFiles(files, { resetUI }) {
  const loading = document.getElementById('loading');

  const fileArray = Array.from(files);
  if (fileArray.length === 0) return;

  const isMultiFile = fileArray.length > 1 ||
    (fileArray.length === 1 && !isArchiveFile(fileArray[0].name));

  if (state.fileTree && state.isMultiFileMode) {
    await handleAddMoreFiles(fileArray);
    return;
  }

  const name = isMultiFile
    ? (fileArray.length === 1 ? fileArray[0].name : `${fileArray.length} files`)
    : fileArray[0].name;
  const sizeBytes = isMultiFile
    ? fileArray.reduce((sum, f) => sum + f.size, 0)
    : fileArray[0].size;
  startFreshUI({ name, sizeBytes, multiFile: isMultiFile });

  try {
    if (isMultiFile) {
      const needsTypeSelection = await addFilesToTree(fileArray);
      await processTypeSelectionQueue(needsTypeSelection);
      emit('extracted');
    } else {
      await extractFile(fileArray[0]);
    }
  } catch (err) {
    loading.classList.remove('visible');
    showNotification(`Failed to process files: ${err.message}`, 'error');
    resetUI();
  }
}

async function handleAddMoreFiles(files) {
  const loading = document.getElementById('loading');

  const fileArray = Array.from(files);
  if (fileArray.length === 0) return;

  loading.classList.add('visible');

  try {
    const needsTypeSelection = await addFilesToTree(fileArray);
    await processTypeSelectionQueue(needsTypeSelection);

    updateMultiFileSummary();

    loading.classList.remove('visible');
    emit('reanalyze');
    showNotification(`Added ${fileArray.length} file(s).`, 'info');
  } catch (err) {
    loading.classList.remove('visible');
    showNotification(`Failed to add files: ${err.message}`, 'error');
  }
}

async function ingestPastedFile(file, fileName, type) {
  await addFilesToTree([file]);

  const node = state.fileTree.children[fileName];
  if (node) {
    applyManualType(node, type);
  }

  state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
}

async function handlePasteText({ resetUI }) {
  const loading = document.getElementById('loading');

  const result = await openPasteModal();
  if (!result) return;

  const { text, name, type } = result;
  const baseFileName = /\.[^./\\]+$/.test(name) ? name : `${name}.txt`;
  const fileName = getUniqueChildName(state.fileTree, baseFileName);

  const file = new File([text], fileName, { type: 'text/plain' });

  if (state.fileTree && state.isMultiFileMode) {
    // Add to existing analysis
    loading.classList.add('visible');
    try {
      await ingestPastedFile(file, fileName, type);

      updateMultiFileSummary();

      loading.classList.remove('visible');
      emit('reanalyze');
      showNotification(`Added "${fileName}".`, 'info');
    } catch (err) {
      loading.classList.remove('visible');
      showNotification(`Failed to add pasted text: ${err.message}`, 'error');
    }
  } else {
    // Start new analysis
    startFreshUI({ name: fileName, sizeBytes: file.size, multiFile: true });

    try {
      await ingestPastedFile(file, fileName, type);
      emit('extracted');
    } catch (err) {
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

  const boundHandleFiles = (files) => handleFiles(files, { resetUI });
  const boundHandlePasteText = () => handlePasteText({ resetUI });

  // Drag & drop / file input
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('keydown', (e) => {
    if (e.target !== dropZone) return;
    if (e.key !== 'Enter' && e.key !== ' ') return;
    e.preventDefault();
    fileInput.click();
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

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) boundHandleFiles(files);
  });

  fileInput.addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length > 0) boundHandleFiles(files);
    e.target.value = '';
  });

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
