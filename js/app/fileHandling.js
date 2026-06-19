import { state, emit, resetState, setMultiFileMode } from '../core/state.js';
import { extractFile, flattenTree, addFilesToTree, applyManualType } from '../files/extractor.js';
import { formatBytes, isArchiveFile } from '../core/utils.js';
import { showNotification } from '../core/shared.js';
import { promptForFileType } from '../files/fileTypeModal.js';
import { openPasteModal } from '../files/pasteText.js';

function getUniqueRootName(fileName) {
  if (!state.fileTree?.children || !state.fileTree.children[fileName]) {
    return fileName;
  }

  const extIndex = fileName.lastIndexOf('.');
  const hasExtension = extIndex > 0;
  const baseName = hasExtension ? fileName.slice(0, extIndex) : fileName;
  const extension = hasExtension ? fileName.slice(extIndex) : '';

  let suffix = 2;
  let uniqueName = `${baseName} ${suffix}${extension}`;
  while (state.fileTree.children[uniqueName]) {
    suffix += 1;
    uniqueName = `${baseName} ${suffix}${extension}`;
  }

  return uniqueName;
}

function updateMultiFileSummary() {
  const totalFiles = state.flatFiles.filter((file) => file.type === 'file').length;
  const totalSize = state.flatFiles.reduce(
    (sum, file) => sum + (file.type === 'file' ? (file.size || 0) : 0),
    0
  );
  document.getElementById('currentFileName').textContent = totalFiles === 1 ? '1 file' : `${totalFiles} files`;
  document.getElementById('currentFileSize').textContent = formatBytes(totalSize);
}

async function handleFiles(files, { resetUI }) {
  const dropZone = document.getElementById('dropZone');
  const uploadInfo = document.getElementById('uploadInfo');
  const resetZone = document.getElementById('resetZone');
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');

  const fileArray = Array.from(files);
  if (fileArray.length === 0) return;

  const isMultiFile = fileArray.length > 1 ||
    (fileArray.length === 1 && !isArchiveFile(fileArray[0].name));

  if (state.fileTree && state.isMultiFileMode) {
    await handleAddMoreFiles(fileArray);
    return;
  }

  resetState();
  setMultiFileMode(isMultiFile);

  dropZone.style.display = 'none';
  uploadInfo.style.display = 'none';
  resetZone.classList.add('visible');

  const addMoreBtn = document.getElementById('addMoreBtn');
  if (isMultiFile) {
    const totalSize = fileArray.reduce((sum, f) => sum + f.size, 0);
    document.getElementById('currentFileName').textContent =
      fileArray.length === 1 ? fileArray[0].name : `${fileArray.length} files`;
    document.getElementById('currentFileSize').textContent = formatBytes(totalSize);
    addMoreBtn.classList.remove('hidden');
    document.getElementById('pasteMoreBtn').classList.remove('hidden');
  } else {
    document.getElementById('currentFileName').textContent = fileArray[0].name;
    document.getElementById('currentFileSize').textContent = formatBytes(fileArray[0].size);
    addMoreBtn.classList.add('hidden');
    document.getElementById('pasteMoreBtn').classList.add('hidden');
  }

  results.classList.remove('visible');
  document.getElementById('errorList').classList.remove('visible');
  loading.classList.add('visible');

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
    showNotification(`Added ${fileArray.length} file(s). Analysis updated.`, 'info');
  } catch (err) {
    loading.classList.remove('visible');
    showNotification(`Failed to add files: ${err.message}`, 'error');
  }
}

async function handlePasteText({ resetUI }) {
  const dropZone = document.getElementById('dropZone');
  const uploadInfo = document.getElementById('uploadInfo');
  const resetZone = document.getElementById('resetZone');
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');

  const result = await openPasteModal();
  if (!result) return;

  const { text, name, type } = result;
  const baseFileName = /\.[^./\\]+$/.test(name) ? name : `${name}.txt`;
  const fileName = getUniqueRootName(baseFileName);

  const file = new File([text], fileName, { type: 'text/plain' });

  if (state.fileTree && state.isMultiFileMode) {
    // Add to existing analysis
    loading.classList.add('visible');
    try {
      await addFilesToTree([file]);

      const node = state.fileTree.children[fileName];
      if (node) {
        applyManualType(node, type);
      }

      state.flatFiles = flattenTree(state.fileTree, state.rootZipName);

      updateMultiFileSummary();

      loading.classList.remove('visible');
      emit('reanalyze');
      showNotification(`Added "${fileName}". Analysis updated.`, 'info');
    } catch (err) {
      loading.classList.remove('visible');
      showNotification(`Failed to add pasted text: ${err.message}`, 'error');
    }
  } else {
    // Start new analysis
    resetState();
    setMultiFileMode(true);

    dropZone.style.display = 'none';
    uploadInfo.style.display = 'none';
    resetZone.classList.add('visible');

    document.getElementById('currentFileName').textContent = fileName;
    document.getElementById('currentFileSize').textContent = formatBytes(file.size);
    document.getElementById('addMoreBtn').classList.remove('hidden');
    document.getElementById('pasteMoreBtn').classList.remove('hidden');

    results.classList.remove('visible');
    document.getElementById('errorList').classList.remove('visible');
    loading.classList.add('visible');

    try {
      await addFilesToTree([file]);

      const node = state.fileTree.children[fileName];
      if (node) {
        applyManualType(node, type);
      }

      state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
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
