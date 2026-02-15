let passwordResolver = null;

let elModal;
let elInput;
let elErrorEl;
let elFileLabel;
let elToggleBtn;
let elRemember;

function promptForPassword(filePath) {
  return new Promise((resolve) => {
    passwordResolver = resolve;
    elFileLabel.textContent = filePath;
    elInput.value = '';
    elErrorEl.classList.remove('visible');
    elModal.classList.add('visible');
    elInput.focus();
  });
}

function closePasswordModal(password) {
  elModal.classList.remove('visible');
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

  elInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && elInput.value) {
      closePasswordModal(elInput.value);
    }
  });

  elToggleBtn.addEventListener('click', () => {
    if (elInput.type === 'password') {
      elInput.type = 'text';
      elToggleBtn.textContent = 'Hide';
    } else {
      elInput.type = 'password';
      elToggleBtn.textContent = 'Show';
    }
  });

  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) closePasswordModal(null);
  });
}

function showPasswordError() {
  elErrorEl.classList.add('visible');
}

function isRememberChecked() {
  return elRemember.checked;
}

export { promptForPassword, closePasswordModal, initPasswordModal, showPasswordError, isRememberChecked };
