let passwordResolver = null;

let elModal;
let elInput;
let elErrorEl;
let elFileLabel;
let elToggleBtn;
let elRemember;

function promptForPassword(filePath, { invalid = false } = {}) {
  return new Promise((resolve) => {
    passwordResolver = resolve;
    elFileLabel.textContent = filePath;
    elInput.value = '';
    elInput.type = 'password';
    elToggleBtn.textContent = 'Show';
    elToggleBtn.setAttribute('aria-label', 'Show password');
    elToggleBtn.title = 'Show password';
    elErrorEl.classList.toggle('visible', invalid);
    elModal.classList.add('visible');
    elInput.focus();
  });
}

function closePasswordModal(password) {
  elModal.classList.remove('visible');
  elInput.value = '';
  elInput.type = 'password';
  elToggleBtn.textContent = 'Show';
  elToggleBtn.setAttribute('aria-label', 'Show password');
  elToggleBtn.title = 'Show password';
  if (passwordResolver) {
    passwordResolver(password);
    passwordResolver = null;
  }
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
