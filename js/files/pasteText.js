// Paste text modal -- lets user paste raw text and pick a file type.

import { renderFileTypeOptions } from './fileTypeRegistry.js';
import { openModal, closeModal } from '../core/modal.js';

let pasteResolver = null;
let pasteCounter = 0;
let selectedType = 'credentials';

let elModal;
let elTextArea;
let elNameInput;
let elTypeOptions;
let elDestination;

// `destination` is null with no case open, the folder the text will be filed
// under when one is, and '' when it lands beside the files already there.
function destinationText(destination) {
  if (destination === null || destination === undefined) return '';
  if (!destination) return 'Added to the open case.';
  return `Added to the open case under "${destination}".`;
}

function openPasteModal({ destination = null } = {}) {
  return new Promise((resolve) => {
    // Reopening while an earlier open is unanswered cancels it; overwriting the
    // resolver instead would leave that promise hanging forever.
    if (pasteResolver) closePasteModal(null);
    pasteResolver = resolve;
    elNameInput.value = 'Pasted Text ' + (pasteCounter + 1);
    elTextArea.value = '';
    selectedType = 'credentials';
    if (elDestination) elDestination.textContent = destinationText(destination);

    for (const btn of elTypeOptions.querySelectorAll('.filetype-option')) {
      btn.classList.toggle('active', btn.dataset.type === selectedType);
    }

    openModal(elModal, { onDismiss: () => closePasteModal(null), initialFocus: elTextArea });
  });
}

function closePasteModal(result) {
  closeModal(elModal);
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
  elDestination = elModal.querySelector('.modal > p');
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
}

export { openPasteModal, initPasteText };
