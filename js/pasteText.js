// Paste text modal -- lets user paste raw text and pick a file type.

let pasteResolver = null;
let pasteCounter = 0;
let selectedType = 'credentials';

let elModal, elTextArea, elNameInput, elTypeOptions, elSubmit, elCancel;

function openPasteModal() {
  return new Promise((resolve) => {
    pasteResolver = resolve;
    pasteCounter++;

    elNameInput.value = 'Pasted Text ' + pasteCounter;
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
  elSubmit = document.getElementById('pasteTextSubmit');
  elCancel = document.getElementById('pasteTextCancel');

  elTypeOptions.addEventListener('click', (e) => {
    const btn = e.target.closest('.filetype-option');
    if (!btn) return;
    selectedType = btn.dataset.type;
    for (const b of elTypeOptions.querySelectorAll('.filetype-option')) {
      b.classList.toggle('active', b === btn);
    }
  });

  elSubmit.addEventListener('click', () => {
    const text = elTextArea.value.trim();
    if (!text) return;
    const name = elNameInput.value.trim() || ('Pasted Text ' + pasteCounter);
    closePasteModal({ text, name, type: selectedType });
  });

  elCancel.addEventListener('click', () => closePasteModal(null));

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
