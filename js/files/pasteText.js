// Paste text modal -- lets user paste raw text and pick a file type.

import { renderFileTypeOptions } from './fileTypeRegistry.js';

let pasteResolver = null;
let pasteCounter = 0;
let selectedType = 'credentials';

let elModal;
let elTextArea;
let elNameInput;
let elTypeOptions;

function openPasteModal() {
  return new Promise((resolve) => {
    pasteResolver = resolve;
    elNameInput.value = 'Pasted Text ' + (pasteCounter + 1);
    elTextArea.value = '';
    selectedType = 'credentials';

    for (const btn of elTypeOptions.querySelectorAll('.filetype-option')) {
      btn.classList.toggle('active', btn.dataset.type === selectedType);
    }

    elModal.classList.add('visible');
    elTextArea.focus();
  });
}

function closePasteModal(result) {
  elModal.classList.remove('visible');
  if (pasteResolver) {
    pasteResolver(result);
    pasteResolver = null;
  }
}

function initPasteText() {
  elModal = document.getElementById('pasteTextModal');
  elTextArea = document.getElementById('pasteTextArea');
  elNameInput = document.getElementById('pasteTextName');
  elTypeOptions = document.getElementById('pasteTypeOptions');
  const submitButton = document.getElementById('pasteTextSubmit');
  const cancelButton = document.getElementById('pasteTextCancel');
  renderFileTypeOptions(elTypeOptions, {
    includeOther: true,
    supportsPasteOnly: true,
    activeType: selectedType,
  });

  elTypeOptions.addEventListener('click', (e) => {
    const btn = e.target.closest('.filetype-option');
    if (!btn) return;
    selectedType = btn.dataset.type;
    for (const b of elTypeOptions.querySelectorAll('.filetype-option')) {
      b.classList.toggle('active', b === btn);
    }
  });

  submitButton.addEventListener('click', () => {
    const text = elTextArea.value.trim();
    if (!text) return;
    pasteCounter += 1;
    const name = elNameInput.value.trim() || ('Pasted Text ' + pasteCounter);
    closePasteModal({ text, name, type: selectedType });
  });

  cancelButton.addEventListener('click', () => closePasteModal(null));

  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) closePasteModal(null);
  });

  document.addEventListener('keydown', (e) => {
    if (!elModal.classList.contains('visible')) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      closePasteModal(null);
    }
  });
}

export { openPasteModal, initPasteText };
