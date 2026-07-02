import { resetState } from '../core/state.js';

const SYSINFO_EMPTY_STATE = '<div class="no-data" id="sysInfoNoData">No system information files detected.</div>';

const HIDDEN_SECTIONS = [
  'dashCredIntel',
  'dashCookieIntel',
  'overviewNoData',
  'dashIOCs',
  'dashFingerprint',
  'dashCaseContext',
  'dashVerdictCards',
  'dashRiskSignals',
  'dashScreenshot',
  'dashAutofillIntel',
  'dashDownloadIntel',
  'dashDomainDetect',
  'dashExtraIntel',
];

const TEXT_RESETS = [
  { id: 'dashCredSummary', text: 'Analysing credential files...', loading: true },
  { id: 'dashCookieSummary', text: 'Analysing cookie files...', loading: true },
  { id: 'dashAutofillSummary', text: 'Analysing autofill files...', loading: true },
  { id: 'dashDownloadSummary', text: 'Analysing download files...' },
];

const HTML_RESETS = [
  { id: 'dashIOCBody', html: '' },
  { id: 'dashFingerprintBody', html: '' },
  { id: 'dashCaseContext', html: '' },
  { id: 'dashVerdictCards', html: '' },
  { id: 'dashRiskSignalsBody', html: '' },
  { id: 'dashScreenshotBody', html: '' },
  { id: 'dashDomainDetectBody', html: '' },
  { id: 'dashExtraBody', html: '' },
  { id: 'dashAutofillBody', html: '' },
  { id: 'dashDownloadBody', html: '' },
];

const NAV_IDS_TO_DISABLE = [
  'navSysInfo',
  'navSearch',
  'navBrowser',
  'navExports',
  'navTimeline',
  'navDomains',
];

function setTextReset({ id, text, loading }) {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = text;
  element.classList.toggle('dash-loading', Boolean(loading));
}

export function createResetUI({
  navigateToPage,
  refreshSidebarAvailability,
  searchRefs,
  resetOverviewState,
}) {
  return function resetUI() {
    resetOverviewState();
    resetState();

    document.getElementById('dropZone').style.display = '';
    document.getElementById('uploadInfo').style.display = '';
    document.getElementById('resetZone').classList.remove('visible');
    document.getElementById('results').classList.remove('visible');
    document.getElementById('loading').classList.remove('visible');
    document.getElementById('fileInput').value = '';
    document.getElementById('addMoreInput').value = '';
    document.getElementById('addMoreBtn').classList.add('hidden');
    document.getElementById('pasteMoreBtn').classList.add('hidden');

    for (const id of HIDDEN_SECTIONS) {
      document.getElementById(id)?.classList.add('hidden');
    }

    for (const config of TEXT_RESETS) {
      setTextReset(config);
    }

    for (const { id, html } of HTML_RESETS) {
      const element = document.getElementById(id);
      if (element) element.innerHTML = html;
    }

    const sysInfoBody = document.getElementById('dashSysInfoBody');
    if (sysInfoBody) sysInfoBody.innerHTML = SYSINFO_EMPTY_STATE;

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

    document.getElementById('sysInfoOpenBtn')?.classList.add('hidden');
    document.getElementById('sysInfoActions')?.classList.add('hidden');

    navigateToPage('overview');
    refreshSidebarAvailability();
  };
}
