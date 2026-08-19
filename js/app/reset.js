import { on, resetState } from '../core/state.js';
import { clearDomainCaches } from '../core/shared.js';

const NAV_IDS_TO_DISABLE = [
  'navSysInfo',
  'navSearch',
  'navBrowser',
  'navExports',
  'navTimeline',
  'navDomains',
];

export function createResetUI({
  navigateToPage,
  refreshSidebarAvailability,
  searchRefs,
  resetOverviewState,
}) {
  // Also covers dropping a new archive over a loaded case, which resets state
  // without going through the button.
  on('reset', clearDomainCaches);

  return function resetUI() {
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

    if (searchRefs) {
      searchRefs.globalSearchInput.value = '';
      searchRefs.searchResults.innerHTML = '';
      searchRefs.searchStatus.textContent = '';
      searchRefs.searchStatus.className = 'search-page-status';
    }

    navigateToPage('overview');
    refreshSidebarAvailability();
  };
}
