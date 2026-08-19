import { renderFileTypeOptions } from './fileTypeRegistry.js';
import { openModal, closeModal, topModal } from '../core/modal.js';

// Null is the answer to "no type at all", and the caller reads it as a decision
// about the whole queue rather than about this one file. Picking Other is a
// choice and stays distinct from it.
let typeResolver = null;

let elModal;
let elFileLabel;
let elOptions;
let elPending;
let elPendingCount;

function promptForFileType(fileName, pendingCount) {
  return new Promise((resolve) => {
    // Nothing prompts twice over at present, but a second caller arriving
    // before the first is answered would otherwise leave that promise hanging.
    if (typeResolver) closeFileTypeModal(null);
    typeResolver = resolve;

    elFileLabel.textContent = fileName;

    if (pendingCount > 0) {
      elPending.classList.remove('hidden');
      elPendingCount.textContent = pendingCount;
    } else {
      elPending.classList.add('hidden');
    }

    openModal(elModal, {
      onDismiss: () => closeFileTypeModal(null),
      initialFocus: '.filetype-option',
    });
  });
}

function closeFileTypeModal(selectedType) {
  closeModal(elModal);
  if (typeResolver) {
    typeResolver(selectedType);
    typeResolver = null;
  }
}

function initFileTypeModal() {
  elModal = document.getElementById('fileTypeModal');
  elFileLabel = document.getElementById('fileTypeFileName');
  elOptions = document.getElementById('fileTypeOptions');
  elPending = document.getElementById('fileTypePending');
  elPendingCount = document.getElementById('fileTypePendingCount');
  renderFileTypeOptions(elOptions, { includeOther: true });

  elOptions.addEventListener('click', (e) => {
    const btn = e.target.closest('.filetype-option');
    if (!btn) return;
    closeFileTypeModal(btn.dataset.type);
  });

  document.getElementById('fileTypeSkipRest').addEventListener('click', () => closeFileTypeModal(null));

  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) {
      closeFileTypeModal(null);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (topModal() !== elModal) return;

    // Number shortcuts 1-9 map to the visible option keys.
    const num = parseInt(e.key, 10);
    if (num >= 1 && num <= 9) {
      e.preventDefault();
      const button = [...elOptions.querySelectorAll('.filetype-option')]
        .find((option) => option.dataset.key === String(num));
      if (button) closeFileTypeModal(button.dataset.type);
    }
  });
}

export { promptForFileType, initFileTypeModal };
