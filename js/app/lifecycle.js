import { state, on } from '../core/state.js';
import { escapeHtml } from '../core/utils.js';
import { runAnalysis } from '../analysis/analysis.js';

function updateErrorList() {
  const errorList = document.getElementById('errorList');
  const errorItems = document.getElementById('errorListItems');

  if (state.errors.length === 0) {
    errorList?.classList.remove('visible');
    if (errorItems) errorItems.innerHTML = '';
    return;
  }

  errorItems.innerHTML = state.errors.map((message) => `<li>${escapeHtml(message)}</li>`).join('');
  errorList?.classList.add('visible');
}

export function initLifecycle({ navigateToPage, refreshSidebarAvailability, updateDashboardVisibility }) {
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const navSearch = document.getElementById('navSearch');
  const navBrowser = document.getElementById('navBrowser');

  on('extracted', () => {
    updateDashboardVisibility();
    navSearch.disabled = false;
    navBrowser.disabled = false;
    updateErrorList();
    loading.classList.remove('visible');
    results.classList.add('visible');
    refreshSidebarAvailability();
    navigateToPage('overview');
    runAnalysis(state.fileTree, state.rootZipName);
  });

  on('reanalyze', () => {
    if (!state.fileTree) return;
    updateDashboardVisibility();
    updateErrorList();
    refreshSidebarAvailability();
    runAnalysis(state.fileTree, state.rootZipName);
  });
}
