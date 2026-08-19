import { state, emit, on } from '../core/state.js';
import { openModal } from '../core/modal.js';
import { PAGE_IDS, DATA_PAGE_NAMES } from '../pages/registry.js';
import { countLabel } from '../pages/shared.js';
import {
  getPasswordsData,
  getCookiesData,
  getAutofillsData,
  getNotesData,
} from '../pages/credentials.js';
import {
  getHistoryData,
  getBookmarksData,
} from '../pages/browser.js';
import {
  getAccountTokensData,
  getServiceArtifactsData,
  getWalletArtifactsData,
  getCreditCardsData,
} from '../pages/assets.js';
import {
  getDownloadsData,
  getDomainDetectionsData,
  getClipboardData,
  getGrabbedFilesData,
  getScreenshotsData,
} from '../pages/activity.js';

// Put on the sidebar by the modal layer while it is the drawer.
const DIALOG_ATTRS = ['role', 'aria-modal', 'aria-label', 'tabindex'];

const NAV_COLLAPSE_KEY = 'logAtlasNavCollapsed';

// Pages whose module holds the parsed rows. Anything else that wants a count
// beside its nav item reports one with `nav:count`.
const DATASET_SOURCES = Object.freeze({
  passwords: getPasswordsData,
  cookies: getCookiesData,
  autofills: getAutofillsData,
  notes: getNotesData,
  history: getHistoryData,
  bookmarks: getBookmarksData,
  tokens: getAccountTokensData,
  services: getServiceArtifactsData,
  wallets: getWalletArtifactsData,
  cards: getCreditCardsData,
  downloads: getDownloadsData,
  detections: getDomainDetectionsData,
  clipboard: getClipboardData,
  grabbed: getGrabbedFilesData,
  screenshots: getScreenshotsData,
});

function getPages() {
  return Object.fromEntries(
    Object.entries(PAGE_IDS).map(([name, id]) => [name, document.getElementById(id)])
  );
}

// Credential datasets are shaped as rows, the rest as entries; both are the
// whole dataset, not the page of it currently drawn.
function datasetSize(read) {
  try {
    const data = read();
    return (data?.rows || data?.entries)?.length ?? null;
  } catch {
    return null;
  }
}

function readCollapsedSections() {
  try {
    const stored = JSON.parse(localStorage.getItem(NAV_COLLAPSE_KEY));
    return new Set(Array.isArray(stored) ? stored : []);
  } catch {
    return new Set();
  }
}

function writeCollapsedSections(names) {
  try {
    localStorage.setItem(NAV_COLLAPSE_KEY, JSON.stringify([...names]));
  } catch {
    // Ignore storage failures; the sidebar just forgets between visits.
  }
}

export function initNavigation() {
  const pages = getPages();
  const sidebarNav = document.getElementById('sidebarNav');
  const sidebarAvailableToggle = document.getElementById('sidebarAvailableToggle');
  const sidebarAvailableToggleWrap = document.getElementById('sidebarAvailableToggleWrap');
  const sidebarSections = [...document.querySelectorAll('.sidebar-section')];
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const collapsedSections = readCollapsedSections();

  let drawer = null;

  // The toggle only exists below the drawer breakpoint, so its being rendered
  // is what says the sidebar is a drawer rather than the page's own nav.
  function isDrawerLayout() {
    return Boolean(sidebarToggle?.getClientRects().length);
  }

  // Open, the drawer sits over the page, so it goes on the modal stack: focus
  // is trapped inside it, Escape closes it and focus comes back to the toggle.
  // Closed, the sidebar is ordinary navigation again and keeps none of that.
  function setSidebarOpen(isOpen) {
    if (!sidebar) return;
    const open = Boolean(isOpen) && isDrawerLayout();

    if (open && !drawer) {
      sidebar.classList.add('open');
      drawer = openModal(sidebar, {
        label: 'Navigation',
        initialFocus: '.sidebar-nav-item.active',
        onDismiss: () => setSidebarOpen(false),
      });
    } else if (!open && drawer) {
      drawer.close();
      drawer = null;
      sidebar.classList.remove('open');
      for (const attr of DIALOG_ATTRS) sidebar.removeAttribute(attr);
      // Hiding the drawer strands whatever focus it held on the document.
      const active = document.activeElement;
      if (!active || active === document.body || sidebar.contains(active)) sidebarToggle?.focus();
    } else {
      sidebar.classList.toggle('open', open);
    }

    sidebarToggle?.setAttribute('aria-expanded', String(open));
  }

  function navigateToPage(pageName) {
    if (!pages[pageName]) return;

    const activeButton = sidebarNav.querySelector(`[data-page="${pageName}"]`);
    if (activeButton?.disabled) return;

    for (const [name, element] of Object.entries(pages)) {
      element?.classList.toggle('active', name === pageName);
    }

    for (const item of sidebarNav.querySelectorAll('.sidebar-nav-item')) {
      const isActive = item.dataset.page === pageName;
      item.classList.toggle('active', isActive);
      item.setAttribute('aria-current', isActive ? 'page' : 'false');
    }

    activeButton?.scrollIntoView({ block: 'nearest' });
    // Closed before the page renders: an open drawer is an aria-modal dialog,
    // and anything the page announces has to reach the tree outside it.
    setSidebarOpen(false);

    if (DATA_PAGE_NAMES.has(pageName)) {
      emit(`page:${pageName}`);
    }
  }

  function refreshSidebarAvailability() {
    const hasLoadedCase = Boolean(state.fileTree);
    sidebarAvailableToggleWrap?.classList.toggle('hidden', !hasLoadedCase);

    const hideDisabled = hasLoadedCase && Boolean(sidebarAvailableToggle?.checked);
    for (const section of sidebarSections) {
      let visibleCount = 0;
      for (const button of section.querySelectorAll('.sidebar-nav-item')) {
        const shouldHide = hideDisabled && button.disabled;
        button.classList.toggle('sidebar-nav-item-hidden', shouldHide);
        if (!shouldHide) visibleCount++;
      }
      section.classList.toggle('sidebar-section-hidden', hideDisabled && visibleCount === 0);
    }
  }

  sidebarNav.addEventListener('click', (event) => {
    const button = event.target.closest('.sidebar-nav-item');
    if (!button || button.disabled) return;
    navigateToPage(button.dataset.page);
  });

  sidebarAvailableToggle?.addEventListener('change', refreshSidebarAvailability);
  sidebarToggle?.addEventListener('click', () => {
    setSidebarOpen(!sidebar?.classList.contains('open'));
  });

  const observer = new MutationObserver(refreshSidebarAvailability);
  observer.observe(sidebarNav, {
    subtree: true,
    attributes: true,
    attributeFilter: ['disabled'],
  });

  setSidebarOpen(false);
  refreshSidebarAvailability();

  return {
    navigateToPage,
    refreshSidebarAvailability,
  };
}
