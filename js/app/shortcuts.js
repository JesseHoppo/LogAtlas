import { state } from '../core/state.js';

function isTypingTarget() {
  const active = document.activeElement;
  if (!active) return false;
  return ['INPUT', 'TEXTAREA'].includes(active.tagName) || active.isContentEditable;
}

export function initKeyboardShortcuts({ closePreview, closePasswordModal, navigateTo }) {
  const shortcutsModal = document.getElementById('shortcutsModal');
  const closeButton = document.getElementById('shortcutsClose');

  closeButton?.addEventListener('click', () => {
    shortcutsModal?.classList.remove('visible');
  });

  shortcutsModal?.addEventListener('click', (event) => {
    if (event.target === shortcutsModal) {
      shortcutsModal.classList.remove('visible');
    }
  });

  document.addEventListener('keydown', (event) => {
    const previewOverlay = document.getElementById('previewOverlay');
    const passwordModal = document.getElementById('passwordModal');
    const previewOpen = previewOverlay?.classList.contains('visible');
    const passwordOpen = passwordModal?.classList.contains('visible');
    const shortcutsOpen = shortcutsModal?.classList.contains('visible');

    if (event.key === 'Escape') {
      if (shortcutsOpen) {
        shortcutsModal.classList.remove('visible');
        return;
      }
      if (previewOpen) {
        closePreview();
        return;
      }
      if (passwordOpen) {
        closePasswordModal(null);
      }
      return;
    }

    if (event.key === '?' && !isTypingTarget()) {
      event.preventDefault();
      shortcutsModal?.classList.toggle('visible');
      return;
    }

    if (event.key === 'Backspace' && !isTypingTarget()) {
      if (!previewOpen && !passwordOpen && !shortcutsOpen && state.currentPath.length > 0) {
        event.preventDefault();
        navigateTo(state.currentPath.slice(0, -1));
      }
    }
  });
}
