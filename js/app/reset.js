import { state, on, resetState } from '../core/state.js';
import { clearDomainCaches } from '../core/shared.js';
import { openTransientModal } from '../core/modal.js';
import { escapeHtml } from '../core/utils.js';
import { countLabel } from '../pages/shared.js';

const NAV_IDS_TO_DISABLE = [
  'navSysInfo',
  'navSearch',
  'navBrowser',
  'navExports',
  'navTimeline',
  'navDomains',
];

// Nothing about a case survives it being cleared: the tree, the parsed rows and
// the analysis are all in memory, and there is no copy anywhere to reload from.
function confirmClear() {
  return new Promise((resolve) => {
    const fileCount = state.flatFiles.filter((file) => file.type === 'file').length;
    const modal = openTransientModal(`
      <div class="modal">
        <h3>Clear case?</h3>
        <p>Discards <span class="modal-file">${escapeHtml(state.rootZipName || 'this case')}</span>
          and everything read from it &mdash; ${countLabel(fileCount, 'file')}.
          Nothing is stored outside this tab, so it cannot be recovered.</p>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="clearCaseKeep">Keep case</button>
          <button class="modal-btn modal-btn-submit" id="clearCaseConfirm">Clear case</button>
        </div>
      </div>
    `, { onDismiss: () => resolve(false) });
    if (!modal) { resolve(false); return; }

    const answer = (result) => {
      modal.close();
      resolve(result);
    };
    const keepButton = modal.overlay.querySelector('#clearCaseKeep');
    keepButton.addEventListener('click', () => answer(false));
    modal.overlay.querySelector('#clearCaseConfirm').addEventListener('click', () => answer(true));

    // Focus keeps the case. The dialog exists to put something between a stray
    // activation and an unrecoverable discard, and focusing the discard would
    // hand the whole case to whatever key arrives next — including the Enter
    // that opened the dialog, which repeats onto the control now under it.
    keepButton.focus();
  });
}

export function createResetUI({
  navigateToPage,
  refreshSidebarAvailability,
  resetOverviewState,
}) {
  // Loading a case resets state without going through the button, so the domain
  // caches hang off the event rather than off resetUI.
  on('reset', clearDomainCaches);

  function clearCase() {
    resetOverviewState();
    resetState();

    document.getElementById('dropZone').style.display = '';
    document.getElementById('uploadInfo').style.display = '';
    document.getElementById('resetZone').classList.remove('visible');
    document.getElementById('results').classList.remove('visible');
    document.getElementById('loading').classList.remove('visible');
    document.getElementById('fileInput').value = '';
    document.getElementById('folderInput').value = '';
    document.getElementById('addMoreInput').value = '';
    document.getElementById('globalSearchInput').value = '';
    document.getElementById('addMoreBtn').classList.add('hidden');
    document.getElementById('pasteMoreBtn').classList.add('hidden');

    for (const id of NAV_IDS_TO_DISABLE) {
      const element = document.getElementById(id);
      if (element) element.disabled = true;
    }

    const sidebarAvailableToggle = document.getElementById('sidebarAvailableToggle');
    if (sidebarAvailableToggle) sidebarAvailableToggle.checked = true;

    navigateToPage('overview');
    refreshSidebarAvailability();
  }

  // The Clear case button hands its click event straight through. A reset that
  // follows a load failure arrives without one, and must not stop to ask about
  // a case that never opened.
  return async function resetUI(trigger) {
    if (trigger instanceof Event && state.fileTree && !await confirmClear()) return;
    clearCase();
  };
}
