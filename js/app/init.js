import { initBrowser, navigateTo } from '../files/browser.js';
import { initPreview, closePreview } from '../files/preview.js';
import { initPasswordModal, closePasswordModal } from '../files/password.js';
import { initFileTypeModal } from '../files/fileTypeModal.js';
import { initDataPages } from '../pages/dataPages.js';
import { initExports } from '../views/exports.js';
import { initTimeline } from '../views/timeline.js';
import { initIdentityGraph, initIdentityPage } from '../views/identityGraph.js';
import { initColumnMapper } from '../files/columnMapper.js';
import { initPasteText } from '../files/pasteText.js';
import { initDomainExplorer } from '../views/domainExplorer.js';
import {
  initDashboard,
  updateDashboardVisibility,
  getSysInfoSourcePath,
  resetOverviewState,
} from './dashboard.js';
import { initSearch } from './search.js';
import { initFileHandling } from './fileHandling.js';
import { initNavigation } from './navigation.js';
import { initLifecycle } from './lifecycle.js';
import { createResetUI } from './reset.js';
import { initFileExportActions } from './fileExports.js';
import { initSystemInfoActions } from './systemInfo.js';
import { initKeyboardShortcuts } from './shortcuts.js';
import { initThemeToggle } from './theme.js';
import { autoLoadFromQuery } from './autoLoad.js';
import { renderDataPageShells, renderSidebarDataNav } from '../pages/registry.js';

renderSidebarDataNav();
renderDataPageShells();
const { navigateToPage, refreshSidebarAvailability } = initNavigation();

const moduleInitializers = [
  ['Password modal', initPasswordModal],
  ['File type modal', initFileTypeModal],
  ['Column mapper', initColumnMapper],
  ['Paste text', initPasteText],
  ['Browser', initBrowser],
  ['Preview', initPreview],
  ['Data pages', initDataPages],
  ['Exports', initExports],
  ['Timeline', initTimeline],
  ['Identity graph', initIdentityGraph],
  ['Identity page', initIdentityPage],
  ['Domain explorer', initDomainExplorer],
  ['Dashboard', initDashboard],
];

for (const [name, init] of moduleInitializers) {
  try {
    init();
  } catch (error) {
    console.error(`${name} failed to initialize:`, error);
  }
}

const searchRefs = initSearch(navigateToPage);

const resetUI = createResetUI({
  navigateToPage,
  refreshSidebarAvailability,
  searchRefs,
  resetOverviewState,
});

const fileHandling = initFileHandling({ resetUI });

initLifecycle({
  navigateToPage,
  refreshSidebarAvailability,
  updateDashboardVisibility,
});

initFileExportActions();
initSystemInfoActions({
  getSysInfoSourcePath,
  navigateToPage,
  navigateTo,
});
initKeyboardShortcuts({
  closePreview,
  closePasswordModal,
  navigateTo,
});
initThemeToggle();

document.getElementById('resetBtn')?.addEventListener('click', resetUI);

void autoLoadFromQuery(fileHandling.handleFiles);
