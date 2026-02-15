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

    // Number shortcuts 1-5
    const num = parseInt(e.key);
    if (num >= 1 && num <= 5) {
      e.preventDefault();
      const types = ['credentials', 'cookies', 'autofill', 'history', 'other'];
      closeFileTypeModal(types[num - 1]);
    }
  });
}

export { promptForFileType, closeFileTypeModal, initFileTypeModal };
