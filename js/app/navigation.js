import { state, emit } from '../core/state.js';
import { PAGE_IDS, DATA_PAGE_NAMES } from '../pages/registry.js';

function getPages() {
  return Object.fromEntries(
    Object.entries(PAGE_IDS).map(([name, id]) => [name, document.getElementById(id)])
  );
}

export function initNavigation() {
  const pages = getPages();
  const sidebarNav = document.getElementById('sidebarNav');
  const sidebarAvailableToggle = document.getElementById('sidebarAvailableToggle');
  const sidebarAvailableToggleWrap = document.getElementById('sidebarAvailableToggleWrap');
  const sidebarSections = [...document.querySelectorAll('.sidebar-section')];
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');

  function setSidebarOpen(isOpen) {
    sidebar?.classList.toggle('open', isOpen);
    sidebarToggle?.setAttribute('aria-expanded', String(isOpen));
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
    }

    if (DATA_PAGE_NAMES.has(pageName)) {
      emit(`page:${pageName}`);
    }

    activeButton?.scrollIntoView({ block: 'nearest' });
    setSidebarOpen(false);
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
