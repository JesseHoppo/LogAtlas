import { renderFileTypeOptions } from './fileTypeRegistry.js';

let typeResolver = null;

let elModal;
let elFileLabel;
let elOptions;
let elPending;
let elPendingCount;

function promptForFileType(fileName, pendingCount) {
  return new Promise((resolve) => {
    typeResolver = resolve;

    elFileLabel.textContent = fileName;
    elModal.classList.add('visible');

    if (pendingCount > 0) {
      elPending.classList.remove('hidden');
      elPendingCount.textContent = pendingCount;
    } else {
      elPending.classList.add('hidden');
    }

    const firstBtn = elOptions.querySelector('.filetype-option');
    if (firstBtn) firstBtn.focus();
  });
}

function closeFileTypeModal(selectedType) {
  elModal.classList.remove('visible');
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

  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) {
      closeFileTypeModal('other');
    }
  });

  document.addEventListener('keydown', (e) => {
    if (!elModal.classList.contains('visible')) return;

    if (e.key === 'Escape') {
      e.preventDefault();
      closeFileTypeModal('other');
      return;
    }

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
