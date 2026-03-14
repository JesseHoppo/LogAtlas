const DATA_PAGE_DEFINITIONS = Object.freeze([
  {
    name: 'passwords',
    pageId: 'pagePasswords',
    navId: 'navPasswords',
    sidebarSection: 'artifacts',
    title: 'Passwords',
    summaryId: 'passwordsSummary',
    summaryText: 'Loading...',
    searchId: 'passwordsSearch',
    searchPlaceholder: 'Search passwords...',
    searchLabel: 'Search passwords',
    filters: [
      { id: 'passwordsHidePasswords', label: 'Hide passwords', checked: true },
    ],
    exportId: 'exportPasswordsCsv',
    statsId: 'passwordsStats',
    contentId: 'passwordsContent',
    emptyText: 'No password data available.',
  },
  {
    name: 'cookies',
    pageId: 'pageCookies',
    navId: 'navCookies',
    sidebarSection: 'artifacts',
    title: 'Cookies',
    summaryId: 'cookiesSummary',
    summaryText: 'Loading...',
    searchId: 'cookiesSearch',
    searchPlaceholder: 'Search cookies...',
    searchLabel: 'Search cookies',
    filters: [
      { id: 'cookiesValidOnly', label: 'Valid only' },
      { id: 'cookiesSessionOnly', label: 'Session tokens' },
    ],
    exportId: 'exportCookiesCsv',
    statsId: 'cookiesStats',
    contentId: 'cookiesContent',
    emptyText: 'No cookie data available.',
  },
  {
    name: 'autofills',
    pageId: 'pageAutofills',
    navId: 'navAutofills',
    sidebarSection: 'artifacts',
    title: 'Autofills',
    summaryId: 'autofillsSummary',
    summaryText: 'Loading...',
    searchId: 'autofillsSearch',
    searchPlaceholder: 'Search autofills...',
    searchLabel: 'Search autofills',
    exportId: 'exportAutofillsCsv',
    statsId: 'autofillsStats',
    contentId: 'autofillsContent',
    emptyText: 'No autofill data available.',
  },
  {
    name: 'notes',
    pageId: 'pageNotes',
    navId: 'navNotes',
    sidebarSection: 'artifacts',
    title: 'Notes',
    summaryId: 'notesSummary',
    summaryText: 'Loading...',
    searchId: 'notesSearch',
    searchPlaceholder: 'Search notes...',
    searchLabel: 'Search notes',
    exportId: 'exportNotesCsv',
    statsId: 'notesStats',
    contentId: 'notesContent',
    emptyText: 'No note data available.',
  },
  {
    name: 'history',
    pageId: 'pageHistory',
    navId: 'navHistory',
    sidebarSection: 'artifacts',
    title: 'History',
    summaryId: 'historySummary',
    summaryText: 'Loading...',
    searchId: 'historySearch',
    searchPlaceholder: 'Search history...',
    searchLabel: 'Search history',
    exportId: 'exportHistoryCsv',
    statsId: 'historyStats',
    contentId: 'historyContent',
    emptyText: 'No history data available.',
  },
  {
    name: 'bookmarks',
    pageId: 'pageBookmarks',
    navId: 'navBookmarks',
    sidebarSection: 'artifacts',
    title: 'Bookmarks',
    summaryId: 'bookmarksSummary',
    summaryText: 'Loading...',
    searchId: 'bookmarksSearch',
    searchPlaceholder: 'Search bookmarks...',
    searchLabel: 'Search bookmarks',
    exportId: 'exportBookmarksCsv',
    statsId: 'bookmarksStats',
    contentId: 'bookmarksContent',
    emptyText: 'No bookmark data available.',
  },
  {
    name: 'browsermeta',
    pageId: 'pageBrowserMeta',
    navId: 'navBrowserMeta',
    sidebarSection: 'artifacts',
    navLabel: 'Browser Metadata',
    title: 'Browser Metadata',
    summaryId: 'browserMetaSummary',
    summaryText: 'Loading...',
    searchId: 'browserMetaSearch',
    searchPlaceholder: 'Search browser metadata...',
    searchLabel: 'Search browser metadata',
    exportId: 'exportBrowserMetaCsv',
    statsId: 'browserMetaStats',
    contentId: 'browserMetaContent',
    emptyText: 'No browser metadata available.',
  },
  {
    name: 'tokens',
    pageId: 'pageTokens',
    navId: 'navTokens',
    sidebarSection: 'artifacts',
    navLabel: 'Tokens',
    title: 'Account Tokens',
    summaryId: 'tokensSummary',
    summaryText: 'Loading...',
    searchId: 'tokensSearch',
    searchPlaceholder: 'Search account tokens...',
    searchLabel: 'Search account tokens',
    filters: [
      { id: 'tokensHideSensitive', label: 'Hide token values', checked: true },
    ],
    exportId: 'exportTokensCsv',
    statsId: 'tokensStats',
    contentId: 'tokensContent',
    emptyText: 'No account-token data available.',
  },
  {
    name: 'services',
    pageId: 'pageServices',
    navId: 'navServices',
    sidebarSection: 'artifacts',
    title: 'Services',
    summaryId: 'servicesSummary',
    summaryText: 'Loading...',
    searchId: 'servicesSearch',
    searchPlaceholder: 'Search service artifacts...',
    searchLabel: 'Search service artifacts',
    exportId: 'exportServicesCsv',
    statsId: 'servicesStats',
    contentId: 'servicesContent',
    emptyText: 'No service artifact data available.',
  },
  {
    name: 'wallets',
    pageId: 'pageWallets',
    navId: 'navWallets',
    sidebarSection: 'artifacts',
    navLabel: 'Wallets',
    title: 'Wallets & Stores',
    summaryId: 'walletsSummary',
    summaryText: 'Loading...',
    searchId: 'walletsSearch',
    searchPlaceholder: 'Search wallets and stores...',
    searchLabel: 'Search wallets and stores',
    exportId: 'exportWalletsCsv',
    statsId: 'walletsStats',
    contentId: 'walletsContent',
    emptyText: 'No wallet or raw-store artifacts available.',
  },
  {
    name: 'downloads',
    pageId: 'pageDownloads',
    navId: 'navDownloads',
    sidebarSection: 'artifacts',
    title: 'Downloads',
    summaryId: 'downloadsSummary',
    summaryText: 'Loading...',
    searchId: 'downloadsSearch',
    searchPlaceholder: 'Search downloads...',
    searchLabel: 'Search downloads',
    exportId: 'exportDownloadsCsv',
    statsId: 'downloadsStats',
    contentId: 'downloadsContent',
    emptyText: 'No download data available.',
  },
  {
    name: 'cards',
    pageId: 'pageCards',
    navId: 'navCards',
    sidebarSection: 'artifacts',
    navLabel: 'Cards',
    title: 'Credit Cards',
    summaryId: 'cardsSummary',
    summaryText: 'Loading...',
    searchId: 'cardsSearch',
    searchPlaceholder: 'Search cards...',
    searchLabel: 'Search credit cards',
    filters: [
      { id: 'cardsHideSensitive', label: 'Hide sensitive data', checked: true },
    ],
    exportId: 'exportCardsCsv',
    statsId: 'cardsStats',
    contentId: 'cardsContent',
    emptyText: 'No credit-card data available.',
  },
  {
    name: 'clipboard',
    pageId: 'pageClipboard',
    navId: 'navClipboard',
    sidebarSection: 'artifacts',
    title: 'Clipboard',
    summaryId: 'clipboardSummary',
    summaryText: 'Loading...',
    searchId: 'clipboardSearch',
    searchPlaceholder: 'Search clipboard...',
    searchLabel: 'Search clipboard',
    exportId: 'exportClipboardCsv',
    statsId: 'clipboardStats',
    contentId: 'clipboardContent',
    emptyText: 'No clipboard data available.',
  },
  {
    name: 'grabbed',
    pageId: 'pageGrabbed',
    navId: 'navGrabbed',
    sidebarSection: 'artifacts',
    navLabel: 'Grabbed Files',
    title: 'Grabbed Files',
    summaryId: 'grabbedSummary',
    summaryText: 'Loading...',
    searchId: 'grabbedSearch',
    searchPlaceholder: 'Search grabbed files...',
    searchLabel: 'Search grabbed files',
    exportId: 'exportGrabbedCsv',
    statsId: 'grabbedStats',
    contentId: 'grabbedContent',
    emptyText: 'No grabbed-file data available.',
  },
  {
    name: 'detections',
    pageId: 'pageDetections',
    navId: 'navDetections',
    sidebarSection: 'artifacts',
    title: 'Detections',
    summaryId: 'detectionsSummary',
    summaryText: 'Loading...',
    searchId: 'detectionsSearch',
    searchPlaceholder: 'Search detections...',
    searchLabel: 'Search detections',
    exportId: 'exportDetectionsCsv',
    statsId: 'detectionsStats',
    contentId: 'detectionsContent',
    emptyText: 'No domain-detection data available.',
  },
  {
    name: 'screenshots',
    pageId: 'pageScreenshots',
    navId: 'navScreenshots',
    sidebarSection: 'artifacts',
    title: 'Screenshots',
    summaryId: 'screenshotsSummary',
    summaryText: 'Loading...',
    searchId: 'screenshotsSearch',
    searchPlaceholder: 'Search screenshots...',
    searchLabel: 'Search screenshots',
    exportId: 'exportScreenshotsCsv',
    statsId: 'screenshotsStats',
    contentId: 'screenshotsContent',
    emptyText: 'No screenshots available.',
  },
  {
    name: 'domains',
    pageId: 'pageDomains',
    navId: 'navDomains',
    sidebarSection: 'analysis',
    navLabel: 'Domains',
    title: 'Domain Explorer',
    summaryId: 'domainsSummary',
    summaryText: 'Loading...',
    searchId: 'domainsSearch',
    searchPlaceholder: 'Search domains...',
    searchLabel: 'Search domains',
    exportId: 'exportDomainsCsv',
    statsId: 'domainsStats',
    contentId: 'domainsContent',
    emptyText: 'No domain data available.',
  },
  {
    name: 'software',
    pageId: 'pageSoftware',
    navId: 'navSoftware',
    sidebarSection: 'analysis',
    navLabel: 'Software',
    title: 'Installed Software',
    summaryId: 'softwareSummary',
    summaryText: 'Loading...',
    searchId: 'softwareSearch',
    searchPlaceholder: 'Search software...',
    searchLabel: 'Search software',
    exportId: 'exportSoftwareCsv',
    statsId: 'softwareStats',
    contentId: 'softwareContent',
    emptyText: 'No software data available.',
  },
  {
    name: 'processes',
    pageId: 'pageProcesses',
    navId: 'navProcesses',
    sidebarSection: 'analysis',
    navLabel: 'Processes',
    title: 'Running Processes',
    summaryId: 'processesSummary',
    summaryText: 'Loading...',
    searchId: 'processesSearch',
    searchPlaceholder: 'Search processes...',
    searchLabel: 'Search processes',
    exportId: 'exportProcessesCsv',
    statsId: 'processesStats',
    contentId: 'processesContent',
    emptyText: 'No process data available.',
  },
  {
    name: 'timeline',
    pageId: 'pageTimeline',
    navId: 'navTimeline',
    sidebarSection: 'analysis',
    navLabel: 'Timeline',
    title: 'Timeline',
    summaryId: 'timelineSummary',
    summaryText: 'No timeline data.',
    searchId: 'timelineSearch',
    searchPlaceholder: 'Search timeline...',
    searchLabel: 'Search timeline',
    exportId: 'exportTimelineCsv',
    statsId: 'timelineStats',
    beforeContentHtml: '<div id="timelineFilters"></div><div id="timelineVisual"></div>',
    contentId: 'timelineContent',
    emptyText: 'No timeline data available.',
  },
  {
    name: 'identity',
    pageId: 'pageIdentity',
    navId: 'navIdentity',
    sidebarSection: 'analysis',
    navLabel: 'Identity',
    title: 'Identity Profile',
    summaryId: 'identitySummary',
    summaryText: 'No identity data.',
    searchId: 'identitySearch',
    searchPlaceholder: 'Search accounts...',
    searchLabel: 'Search accounts',
    exportId: 'exportIdentityCsv',
    statsId: 'identityStats',
    beforeContentHtml: '<div id="identityPrimary"></div>',
    contentId: 'identityContent',
    emptyText: 'No identity data available.',
    afterContentHtml: '<div id="identityEmailMap"></div>',
  },
]);

const PAGE_IDS = Object.freeze({
  overview: 'pageOverview',
  sysinfo: 'pageSysInfo',
  browser: 'pageBrowser',
  search: 'pageSearch',
  exports: 'pageExports',
  ...Object.fromEntries(DATA_PAGE_DEFINITIONS.map(({ name, pageId }) => [name, pageId])),
});
const DATA_PAGE_NAMES = new Set(DATA_PAGE_DEFINITIONS.map(({ name }) => name));
const DATA_PAGE_CONTENT_IDS_BY_NAME = Object.freeze(
  Object.fromEntries(
    DATA_PAGE_DEFINITIONS
      .filter(({ contentId }) => Boolean(contentId))
      .map(({ name, contentId }) => [name, contentId])
  )
);
const DATA_PAGE_NAV_IDS_BY_NAME = Object.freeze(
  Object.fromEntries(
    DATA_PAGE_DEFINITIONS
      .filter(({ navId }) => Boolean(navId))
      .map(({ name, navId }) => [name, navId])
  )
);

function renderFilter(filter) {
  const checkedAttr = filter.checked ? ' checked' : '';
  return `
    <label class="data-page-filter">
      <input type="checkbox" id="${filter.id}"${checkedAttr}> ${filter.label}
    </label>
  `;
}

function renderPageShell(page) {
  const filtersHtml = (page.filters || []).map(renderFilter).join('');
  const beforeContentHtml = page.beforeContentHtml || '';
  const afterContentHtml = page.afterContentHtml || '';

  return `
    <div class="page" id="${page.pageId}">
      <h2 class="page-title">${page.title}</h2>
      <div class="data-page-header">
        <div class="data-page-summary" id="${page.summaryId}">${page.summaryText}</div>
        <div class="data-page-actions">
          <input type="text" class="data-page-search" id="${page.searchId}" placeholder="${page.searchPlaceholder}" autocomplete="off" aria-label="${page.searchLabel}">
          ${filtersHtml}
          <button class="export-btn export-btn-primary" id="${page.exportId}">Download CSV</button>
        </div>
      </div>
      <div class="data-page-stats" id="${page.statsId}"></div>
      ${beforeContentHtml}
      <div class="data-page-content" id="${page.contentId}">
        <div class="no-data">${page.emptyText}</div>
      </div>
      ${afterContentHtml}
    </div>
  `;
}

function renderSidebarButtons(sectionName) {
  return DATA_PAGE_DEFINITIONS
    .filter((page) => page.sidebarSection === sectionName)
    .map((page) => `
      <button class="sidebar-nav-item" data-page="${page.name}" id="${page.navId}" disabled>${page.navLabel || page.title}</button>
    `)
    .join('');
}

function renderSidebarDataNav() {
  const artifactsMount = document.getElementById('generatedArtifactNav');
  if (artifactsMount) {
    artifactsMount.innerHTML = renderSidebarButtons('artifacts');
  }

  const analysisMount = document.getElementById('generatedAnalysisNav');
  if (analysisMount) {
    analysisMount.innerHTML = renderSidebarButtons('analysis');
  }
}

function renderDataPageShells() {
  const mount = document.getElementById('generatedDataPages');
  if (!mount) return;
  mount.innerHTML = DATA_PAGE_DEFINITIONS.map(renderPageShell).join('');
}

export {
  PAGE_IDS,
  DATA_PAGE_NAMES,
  DATA_PAGE_CONTENT_IDS_BY_NAME,
  DATA_PAGE_NAV_IDS_BY_NAME,
  renderSidebarDataNav,
  renderDataPageShells,
};
