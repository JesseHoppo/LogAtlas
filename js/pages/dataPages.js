import { state, on, emit } from '../core/state.js';
import { PAGE_SIZE, buildRowsHtml } from './shared.js';
import {
  DATA_PAGE_CONTENT_IDS_BY_NAME,
  DATA_PAGE_NAV_IDS_BY_NAME,
} from './registry.js';

import {
  initCredentials,
} from './credentials.js';

import {
  initBrowserPages,
  loadAll as loadBrowser,
  handleShowMore as browserShowMore,
  updateShown as browserUpdateShown,
  updateNav as browserUpdateNav,
  reset as browserReset,
} from './browser.js';

import {
  initAssetPages,
  loadAll as loadAssets,
  handleShowMore as assetShowMore,
  updateShown as assetUpdateShown,
  updateNav as assetUpdateNav,
  reset as assetReset,
} from './assets.js';

import {
  initActivityPages,
  loadAll as loadActivity,
  handleShowMore as activityShowMore,
  updateShown as activityUpdateShown,
  updateNav as activityUpdateNav,
  reset as activityReset,
  setSoftwareData,
  setProcessListData,
} from './activity.js';

const COLLECTION_MODULES = [
  {
    key: 'browser',
    init: initBrowserPages,
    load: loadBrowser,
    handleShowMore: browserShowMore,
    updateShown: browserUpdateShown,
    updateNav: browserUpdateNav,
    reset: browserReset,
  },
  {
    key: 'assets',
    init: initAssetPages,
    load: loadAssets,
    handleShowMore: assetShowMore,
    updateShown: assetUpdateShown,
    updateNav: assetUpdateNav,
    reset: assetReset,
  },
  {
    key: 'activity',
    init: initActivityPages,
    load: loadActivity,
    handleShowMore: activityShowMore,
    updateShown: activityUpdateShown,
    updateNav: activityUpdateNav,
    reset: activityReset,
  },
];

let credentialsController = null;
let collectionControllers;

// Unified show-more handler

function handleShowMore(pageId, contentEl) {
  // Credentials module handles its own show-more internally
  if (credentialsController && credentialsController.showMore(pageId, contentEl)) return;

  let matchedModule = null;
  let showMoreState = null;
  for (const collectionModule of COLLECTION_MODULES) {
    const match = collectionModule.handleShowMore(pageId);
    if (!match) continue;
    matchedModule = collectionModule;
    showMoreState = match;
    break;
  }
  if (!matchedModule || !showMoreState) return;

  const { filtered, shown, builder } = showMoreState;
  const nextEnd = Math.min(shown + PAGE_SIZE, filtered.length);
  const newRowsHtml = buildRowsHtml(builder, filtered, shown, nextEnd);

  const tbody = contentEl.querySelector('tbody');
  const screenshotGrid = contentEl.querySelector('.screenshot-grid');
  if (tbody) {
    tbody.insertAdjacentHTML('beforeend', newRowsHtml);
  } else if (screenshotGrid && pageId === 'screenshots') {
    screenshotGrid.insertAdjacentHTML('beforeend', newRowsHtml);
  }

  matchedModule.updateShown(pageId, nextEnd);

  const btn = contentEl.querySelector('.data-show-more');
  const remaining = filtered.length - nextEnd;
  if (remaining > 0 && btn) {
    btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)`;
  } else if (btn) {
    btn.remove();
  }
}

// Data loading

async function reloadData() {
  if (!state.fileTree) return;

  const tree = state.fileTree;
  const root = state.rootZipName;
  const loadTasks = [
    ...credentialsController.load.map((load) => ({
      label: load.name || 'credentials',
      run: () => load(tree, root),
    })),
    ...COLLECTION_MODULES.map(({ key, load }) => ({
      label: key,
      run: () => load(tree, root),
    })),
  ];

  const loadResults = await Promise.allSettled(loadTasks.map(({ run }) => run()));
  loadResults.forEach((result, index) => {
    if (result.status === 'rejected') {
      console.error(`Data page load failed (${loadTasks[index].label}):`, result.reason);
    }
  });

  emit('data:loaded');

  // Update nav enabled/disabled states
  const { navIds } = credentialsController;
  for (const [pageName, isEmpty] of Object.entries(navIds)) {
    const navId = DATA_PAGE_NAV_IDS_BY_NAME[pageName];
    const navEl = navId ? document.getElementById(navId) : null;
    if (navEl) navEl.disabled = isEmpty();
  }

  for (const { updateNav } of COLLECTION_MODULES) {
    updateNav();
  }
}

export function initDataPages() {
  credentialsController = initCredentials();
  collectionControllers = Object.fromEntries(
    COLLECTION_MODULES.map(({ key, init }) => [key, init()])
  );

  const managedPageRenderers = {
    ...credentialsController.render,
    ...Object.assign(
      {},
      ...Object.values(collectionControllers).map(({ renders }) => renders)
    ),
  };
  const managedPageNames = Object.keys(managedPageRenderers);
  const managedContentIds = managedPageNames
    .map((pageName) => DATA_PAGE_CONTENT_IDS_BY_NAME[pageName])
    .filter(Boolean);
  const managedNavIds = managedPageNames
    .map((pageName) => DATA_PAGE_NAV_IDS_BY_NAME[pageName])
    .filter(Boolean);

  // Delegated show-more + screenshot click handlers
  for (const id of managedContentIds) {
    const el = document.getElementById(id);
    el?.addEventListener('click', (e) => {
      const screenshotBtn = e.target.closest('[data-screenshot-idx]');
      if (screenshotBtn && id === 'screenshotsContent') {
        const idx = parseInt(screenshotBtn.dataset.screenshotIdx, 10);
        const filtered = collectionControllers.activity.getScreenshotsFiltered();
        if (idx >= 0 && idx < filtered.length) {
          collectionControllers.activity.openScreenshotLightbox(filtered[idx]);
        }
        return;
      }
      const btn = e.target.closest('.data-show-more');
      if (!btn) return;
      handleShowMore(btn.dataset.page, el);
    });
  }

  on('extracted', reloadData);
  on('reanalyze', reloadData);

  for (const [pageName, render] of Object.entries(managedPageRenderers)) {
    on(`page:${pageName}`, render);
  }

  // Software and process list come from analysis events
  on('analysis:software', setSoftwareData);
  on('analysis:processList', setProcessListData);

  on('reset', () => {
    credentialsController.reset();
    for (const { reset } of COLLECTION_MODULES) {
      reset();
    }
    for (const { resetSearches } of Object.values(collectionControllers)) {
      resetSearches();
    }

    for (const id of managedNavIds) {
      const navEl = document.getElementById(id);
      if (navEl) navEl.disabled = true;
    }
  });
}
