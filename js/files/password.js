import { on } from '../core/state.js';
import { openModal, closeModal } from '../core/modal.js';

// Analysis reads many entries at once, so several of them can want the archive
// password at the same moment. One shared prompt answers all of them: a single
// resolver would be overwritten by the next caller and every earlier promise
// would hang, which stalled the case forever with no error shown.
let pendingResolvers = [];

// Entries are read in waves, so one prompt only ever answers the waiters that
// have arrived. Reuse has to cover the skip as well as the password, or an
// archive of encrypted files asks again for every wave that follows.
let skipRest = false;

let elModal;
let elInput;
let elErrorEl;
let elFileLabel;
let elToggleBtn;
let elRemember;
let waitingLabel = '';
let waitingCount = 0;

function renderWaitingLabel() {
  elFileLabel.textContent = waitingCount > 1
    ? `${waitingLabel} and ${(waitingCount - 1).toLocaleString()} more`
    : waitingLabel;
}

function resetInput() {
  elInput.value = '';
  elInput.type = 'password';
  elToggleBtn.textContent = 'Show';
  elToggleBtn.setAttribute('aria-label', 'Show password');
  elToggleBtn.title = 'Show password';
}

function promptForPassword(filePath, { invalid = false } = {}) {
  if (skipRest) return Promise.resolve(null);

  return new Promise((resolve) => {
    const alreadyOpen = pendingResolvers.length > 0;
    pendingResolvers.push(resolve);
    waitingCount = pendingResolvers.length;

    if (alreadyOpen) {
      renderWaitingLabel();
      return;
    }

    waitingLabel = filePath;
    renderWaitingLabel();
    resetInput();
    elErrorEl.classList.toggle('visible', invalid);
    openModal(elModal, { onDismiss: () => closePasswordModal(null), initialFocus: elInput });
  });
}

function closePasswordModal(password) {
  closeModal(elModal);
  resetInput();
  const resolvers = pendingResolvers;
  pendingResolvers = [];
  waitingCount = 0;
  if (password === null && resolvers.length > 0 && isRememberChecked()) skipRest = true;
  for (const resolve of resolvers) resolve(password);
}

function initPasswordModal() {
  elModal = document.getElementById('passwordModal');
  elInput = document.getElementById('passwordInput');
  elErrorEl = document.getElementById('passwordError');
  elFileLabel = document.getElementById('encryptedFileName');
  elToggleBtn = document.getElementById('togglePassword');
  elRemember = document.getElementById('rememberPassword');

  const submitBtn = document.getElementById('submitPassword');
  const skipBtn = document.getElementById('skipPassword');

  on('reset', () => {
    skipRest = false;
    elRemember.checked = true;
  });

  submitBtn.addEventListener('click', () => {
    if (elInput.value) closePasswordModal(elInput.value);
  });

  skipBtn.addEventListener('click', () => {
    closePasswordModal(null);
  });

  elInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && elInput.value) {
      closePasswordModal(elInput.value);
    }
  });

  elToggleBtn.addEventListener('click', () => {
    if (elInput.type === 'password') {
      elInput.type = 'text';
      elToggleBtn.textContent = 'Hide';
      elToggleBtn.setAttribute('aria-label', 'Hide password');
      elToggleBtn.title = 'Hide password';
    } else {
      elInput.type = 'password';
      elToggleBtn.textContent = 'Show';
      elToggleBtn.setAttribute('aria-label', 'Show password');
      elToggleBtn.title = 'Show password';
    }
  });

  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) closePasswordModal(null);
  });
}

function isRememberChecked() {
  return elRemember.checked;
}

export { promptForPassword, closePasswordModal, initPasswordModal, isRememberChecked };
