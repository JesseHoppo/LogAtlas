// Asset pages: Tokens, Services, Wallets, Credit Cards

import { loadFileContent } from '../files/extractor.js';
import { escapeHtml } from '../core/utils.js';
import {
  parseAccountTokenFile,
  parseServiceArtifactFile,
} from '../transforms/structured.js';
import { parseCreditCardFile } from '../transforms/cards.js';
import { parseWalletArtifact } from '../analysis/walletArtifacts.js';
import {
  collectHintedNodes,
  inferBrowserFromPath,
  inferProfileFromPath,
  inferServiceFromPath,
  SHARED_TEXT_DECODER,
} from '../core/shared.js';
import {
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  bindDebouncedInput,
  trimRootPath,
  inferServiceArtifactType,
  maskTokenValue,
  maskCardNumber,
  extractCardLast4,
  downloadCsvRows,
  createPagedCollectionRegistry,
} from './shared.js';

let accountTokensData = { entries: [], fileCount: 0 };
let serviceArtifactsData = { entries: [], fileCount: 0 };
let walletArtifactsData = { entries: [], fileCount: 0 };
let creditCardsData = { entries: [], fileCount: 0 };

let accountTokensFiltered = [];
let accountTokensShown = 0;
let serviceArtifactsFiltered = [];
let serviceArtifactsShown = 0;
let walletArtifactsFiltered = [];
let walletArtifactsShown = 0;
let creditCardsFiltered = [];
let creditCardsShown = 0;

let hideCardNumbers = true;
let hideTokenValues = true;

const pageRegistry = createPagedCollectionRegistry({
  tokens: {
    navId: 'navTokens',
    rowBuilder: accountTokenRowBuilder,
    getFiltered: () => accountTokensFiltered,
    getShown: () => accountTokensShown,
    setShown: (value) => { accountTokensShown = value; },
    isEmpty: () => accountTokensData.entries.length === 0,
    reset: () => {
      accountTokensData = { entries: [], fileCount: 0 };
      accountTokensFiltered = [];
      accountTokensShown = 0;
      hideTokenValues = true;
    },
  },
  services: {
    navId: 'navServices',
    rowBuilder: serviceArtifactRowBuilder,
    getFiltered: () => serviceArtifactsFiltered,
    getShown: () => serviceArtifactsShown,
    setShown: (value) => { serviceArtifactsShown = value; },
    isEmpty: () => serviceArtifactsData.entries.length === 0,
    reset: () => {
      serviceArtifactsData = { entries: [], fileCount: 0 };
      serviceArtifactsFiltered = [];
      serviceArtifactsShown = 0;
    },
  },
  wallets: {
    navId: 'navWallets',
    rowBuilder: walletArtifactRowBuilder,
    getFiltered: () => walletArtifactsFiltered,
    getShown: () => walletArtifactsShown,
    setShown: (value) => { walletArtifactsShown = value; },
    isEmpty: () => walletArtifactsData.entries.length === 0,
    reset: () => {
      walletArtifactsData = { entries: [], fileCount: 0 };
      walletArtifactsFiltered = [];
      walletArtifactsShown = 0;
    },
  },
  cards: {
    navId: 'navCards',
    rowBuilder: creditCardRowBuilder,
    getFiltered: () => creditCardsFiltered,
    getShown: () => creditCardsShown,
    setShown: (value) => { creditCardsShown = value; },
    isEmpty: () => creditCardsData.entries.length === 0,
    reset: () => {
      creditCardsData = { entries: [], fileCount: 0 };
      creditCardsFiltered = [];
      creditCardsShown = 0;
      hideCardNumbers = true;
    },
  },
});

async function loadAccountTokensData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_accountTokenHint', rootName, nodes);
  if (nodes.length === 0) { accountTokensData = { entries: [], fileCount: 0 }; return; }
  const entries = [];
  let fileCount = 0;
  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = SHARED_TEXT_DECODER.decode(content);
      const parsed = parseAccountTokenFile(text, path || node.name);
      if (!parsed || parsed.rows.length === 0) continue;
      fileCount++;
      const service = inferServiceFromPath(path || node.name) || 'Unknown';
      const browser = inferBrowserFromPath(path || node.name);
      const profile = inferProfileFromPath(path || node.name);
      for (const row of parsed.rows) {
        const type = (row[0] || '').trim();
        const value = (row[1] || '').trim();
        const accountId = (row[2] || '').trim();
        const note = (row[3] || '').trim();
        if (!value && !accountId) continue;
        entries.push({ service, type, value, accountId, browser, profile, note, source: path });
      }
    } catch { /* skip */ }
  }
  accountTokensData = { entries, fileCount };
}

async function loadServiceArtifactsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_serviceArtifactHint', rootName, nodes);
  if (nodes.length === 0) { serviceArtifactsData = { entries: [], fileCount: 0 }; return; }
  const entries = [];
  let fileCount = 0;
  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = SHARED_TEXT_DECODER.decode(content);
      const parsed = parseServiceArtifactFile(text);
      if (!parsed || parsed.rows.length === 0) continue;
      fileCount++;
      const service = inferServiceFromPath(path || node.name) || 'Unknown';
      const artifactType = inferServiceArtifactType(path || node.name);
      for (const row of parsed.rows) {
        const section = (row[0] || '').trim();
        const key = (row[1] || '').trim();
        const value = (row[2] || '').trim();
        if (!key && !value) continue;
        entries.push({ service, artifactType, section, key, value, source: path });
      }
    } catch { /* skip */ }
  }
  serviceArtifactsData = { entries, fileCount };
}

async function loadWalletArtifactsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_cryptoWalletHint', rootName, nodes);
  if (nodes.length === 0) { walletArtifactsData = { entries: [], fileCount: 0 }; return; }
  const entries = [];
  let fileCount = 0;
  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const parsed = parseWalletArtifact(content, node.name, path);
      if (!parsed) continue;
      fileCount++;
      entries.push(parsed);
    } catch { /* skip */ }
  }
  walletArtifactsData = { entries, fileCount };
}

async function loadCreditCardsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_creditCardHint', rootName, nodes);
  if (nodes.length === 0) { creditCardsData = { entries: [], fileCount: 0 }; return; }
  const entries = [];
  let fileCount = 0;
  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = SHARED_TEXT_DECODER.decode(content);
      const parsed = parseCreditCardFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;
      fileCount++;
      for (const row of parsed.rows) {
        const cardNumber = (row[0] || '').trim();
        const nameOnCard = (row[1] || '').trim();
        const cvc = (row[2] || '').trim();
        const expiration = (row[3] || '').trim();
        const filePath = (row[4] || '').trim();
        if (!cardNumber && !nameOnCard && !cvc && !expiration && !filePath) continue;
        entries.push({ cardNumber, last4: extractCardLast4(cardNumber), nameOnCard, cvc, expiration, filePath, browser: inferBrowserFromPath(filePath || path), source: path });
      }
    } catch { /* skip */ }
  }
  creditCardsData = { entries, fileCount };
}

function accountTokenRowBuilder({ service, type, value, accountId, browser, profile, note, source }) {
  const displayValue = hideTokenValues ? maskTokenValue(value) : value;
  return `<tr><td>${escapeHtml(service || '')}</td><td>${escapeHtml(type || '')}</td><td title="${escapeHtml(value)}">${escapeHtml(displayValue)}</td><td>${escapeHtml(accountId || '')}</td><td>${escapeHtml(browser || '')}</td><td>${escapeHtml(profile || '')}</td><td title="${escapeHtml(note || '')}">${escapeHtml(note || '')}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderTokensPage(searchQuery = '') {
  const summary = document.getElementById('tokensSummary');
  const stats = document.getElementById('tokensStats');
  const content = document.getElementById('tokensContent');
  if (accountTokensData.entries.length === 0) { summary.textContent = 'No account tokens found'; stats.innerHTML = ''; content.innerHTML = '<div class="no-data">No account-token data available.</div>'; return; }
  let filtered = accountTokensData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.type.toLowerCase().includes(q) || entry.value.toLowerCase().includes(q) || entry.accountId.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.note.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  accountTokensFiltered = filtered;
  accountTokensShown = Math.min(PAGE_SIZE, filtered.length);
  const services = new Set(accountTokensData.entries.map(e => e.service).filter(Boolean));
  const withValue = accountTokensData.entries.filter(e => e.value).length;
  const withAccountId = accountTokensData.entries.filter(e => e.accountId).length;
  const tokenTypes = new Set(accountTokensData.entries.map(e => e.type).filter(Boolean));
  summary.textContent = filtered.length !== accountTokensData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${accountTokensData.entries.length.toLocaleString()} token rows from ${accountTokensData.fileCount} file(s)` : `${accountTokensData.entries.length.toLocaleString()} token rows from ${accountTokensData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withValue.toLocaleString()}</div><div class="data-page-stat-label">With Token</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withAccountId.toLocaleString()}</div><div class="data-page-stat-label">With Account ID</div></div><div class="data-page-stat"><div class="data-page-stat-value">${tokenTypes.size.toLocaleString()}</div><div class="data-page-stat-label">Token Types</div></div>`;
  let html = '<div class="data-table-container"><table class="data-table"><thead><tr><th>Service</th><th>Type</th><th>Value</th><th>Account ID</th><th>Browser</th><th>Profile</th><th>Note</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(accountTokenRowBuilder, accountTokensFiltered, 0, accountTokensShown);
  html += '</tbody></table></div>';
  const remaining = accountTokensFiltered.length - accountTokensShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'tokens');
  content.innerHTML = html;
}

function serviceArtifactRowBuilder({ service, artifactType, section, key, value, source }) {
  return `<tr><td>${escapeHtml(service || '')}</td><td>${escapeHtml(artifactType || '')}</td><td>${escapeHtml(section || '')}</td><td title="${escapeHtml(key)}">${escapeHtml(key)}</td><td title="${escapeHtml(value)}">${escapeHtml(value)}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderServicesPage(searchQuery = '') {
  const summary = document.getElementById('servicesSummary');
  const stats = document.getElementById('servicesStats');
  const content = document.getElementById('servicesContent');
  if (serviceArtifactsData.entries.length === 0) { summary.textContent = 'No service artifacts found'; stats.innerHTML = ''; content.innerHTML = '<div class="no-data">No service artifact data available.</div>'; return; }
  let filtered = serviceArtifactsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.artifactType.toLowerCase().includes(q) || entry.section.toLowerCase().includes(q) || entry.key.toLowerCase().includes(q) || entry.value.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  serviceArtifactsFiltered = filtered;
  serviceArtifactsShown = Math.min(PAGE_SIZE, filtered.length);
  const services = new Set(serviceArtifactsData.entries.map(e => e.service).filter(Boolean));
  const artifactTypes = new Set(serviceArtifactsData.entries.map(e => e.artifactType).filter(Boolean));
  const sections = new Set(serviceArtifactsData.entries.map(e => e.section).filter(Boolean));
  const withValue = serviceArtifactsData.entries.filter(e => e.value).length;
  summary.textContent = filtered.length !== serviceArtifactsData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${serviceArtifactsData.entries.length.toLocaleString()} service rows from ${serviceArtifactsData.fileCount} file(s)` : `${serviceArtifactsData.entries.length.toLocaleString()} service rows from ${serviceArtifactsData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${artifactTypes.size.toLocaleString()}</div><div class="data-page-stat-label">Artifact Types</div></div><div class="data-page-stat"><div class="data-page-stat-value">${sections.size.toLocaleString()}</div><div class="data-page-stat-label">Sections</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withValue.toLocaleString()}</div><div class="data-page-stat-label">With Value</div></div>`;
  let html = '<div class="data-table-container"><table class="data-table"><thead><tr><th>Service</th><th>Artifact Type</th><th>Section</th><th>Key</th><th>Value</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(serviceArtifactRowBuilder, serviceArtifactsFiltered, 0, serviceArtifactsShown);
  html += '</tbody></table></div>';
  const remaining = serviceArtifactsFiltered.length - serviceArtifactsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'services');
  content.innerHTML = html;
}

function walletArtifactRowBuilder({ service, category, artifactType, storeType, browser, profile, emailCount, addressCount, tokenCount, seedHints, highlights, source }) {
  return `<tr><td>${escapeHtml(service || '')}</td><td>${escapeHtml(category || '')}</td><td>${escapeHtml(artifactType || '')}</td><td>${escapeHtml(storeType || '')}</td><td>${escapeHtml(browser || '')}</td><td>${escapeHtml(profile || '')}</td><td>${emailCount || 0}</td><td>${addressCount || 0}</td><td>${tokenCount || 0}</td><td>${seedHints || 0}</td><td title="${escapeHtml(highlights || '')}">${escapeHtml(highlights || '')}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderWalletsPage(searchQuery = '') {
  const summary = document.getElementById('walletsSummary');
  const stats = document.getElementById('walletsStats');
  const content = document.getElementById('walletsContent');
  if (walletArtifactsData.entries.length === 0) { summary.textContent = 'No wallet or store artifacts found'; stats.innerHTML = ''; content.innerHTML = '<div class="no-data">No wallet/store artifact data available.</div>'; return; }
  let filtered = walletArtifactsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.category.toLowerCase().includes(q) || entry.artifactType.toLowerCase().includes(q) || entry.storeType.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.highlights.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  walletArtifactsFiltered = filtered;
  walletArtifactsShown = Math.min(PAGE_SIZE, filtered.length);
  const services = new Set(walletArtifactsData.entries.map(e => e.service).filter(Boolean));
  const categories = new Set(walletArtifactsData.entries.map(e => e.category).filter(Boolean));
  const rawStores = walletArtifactsData.entries.filter(e => e.storeType === 'LevelDB' || e.storeType === 'SQLite').length;
  const signalHits = walletArtifactsData.entries.reduce((sum, e) => sum + e.emailCount + e.addressCount + e.tokenCount + e.seedHints, 0);
  summary.textContent = filtered.length !== walletArtifactsData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${walletArtifactsData.entries.length.toLocaleString()} wallet/store artifacts from ${walletArtifactsData.fileCount} file(s)` : `${walletArtifactsData.entries.length.toLocaleString()} wallet/store artifacts from ${walletArtifactsData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${categories.size.toLocaleString()}</div><div class="data-page-stat-label">Categories</div></div><div class="data-page-stat"><div class="data-page-stat-value">${rawStores.toLocaleString()}</div><div class="data-page-stat-label">Raw Stores</div></div><div class="data-page-stat"><div class="data-page-stat-value">${signalHits.toLocaleString()}</div><div class="data-page-stat-label">Signal Hits</div></div>`;
  let html = '<div class="data-table-container"><table class="data-table"><thead><tr><th>Service</th><th>Category</th><th>Artifact Type</th><th>Store Type</th><th>Browser</th><th>Profile</th><th>Emails</th><th>Addresses</th><th>Tokens</th><th>Seeds</th><th>Highlights</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(walletArtifactRowBuilder, walletArtifactsFiltered, 0, walletArtifactsShown);
  html += '</tbody></table></div>';
  const remaining = walletArtifactsFiltered.length - walletArtifactsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'wallets');
  content.innerHTML = html;
}

function creditCardRowBuilder({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) {
  const cardDisplay = hideCardNumbers ? maskCardNumber(cardNumber) : cardNumber;
  const cvcDisplay = hideCardNumbers && cvc ? '\u2022\u2022\u2022' : cvc;
  return `<tr><td title="${escapeHtml(cardNumber)}">${escapeHtml(cardDisplay)}</td><td>${escapeHtml(last4)}</td><td title="${escapeHtml(nameOnCard)}">${escapeHtml(nameOnCard)}</td><td>${escapeHtml(expiration)}</td><td>${escapeHtml(cvcDisplay)}</td><td>${escapeHtml(browser)}</td><td title="${escapeHtml(filePath || source)}">${escapeHtml(trimRootPath(filePath || source))}</td></tr>`;
}

function renderCardsPage(searchQuery = '') {
  const summary = document.getElementById('cardsSummary');
  const stats = document.getElementById('cardsStats');
  const content = document.getElementById('cardsContent');
  if (creditCardsData.entries.length === 0) { summary.textContent = 'No credit cards found'; stats.innerHTML = ''; content.innerHTML = '<div class="no-data">No credit-card data available.</div>'; return; }
  let filtered = creditCardsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.cardNumber.toLowerCase().includes(q) || entry.last4.toLowerCase().includes(q) || entry.nameOnCard.toLowerCase().includes(q) || entry.expiration.toLowerCase().includes(q) || entry.cvc.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.filePath.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  creditCardsFiltered = filtered;
  creditCardsShown = Math.min(PAGE_SIZE, filtered.length);
  const withHolder = creditCardsData.entries.filter(e => e.nameOnCard).length;
  const withCvc = creditCardsData.entries.filter(e => e.cvc).length;
  const withExpiry = creditCardsData.entries.filter(e => e.expiration && e.expiration !== '/').length;
  const uniqueLast4 = new Set(creditCardsData.entries.map(e => e.last4).filter(Boolean));
  summary.textContent = filtered.length !== creditCardsData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${creditCardsData.entries.length.toLocaleString()} cards from ${creditCardsData.fileCount} file(s)` : `${creditCardsData.entries.length.toLocaleString()} cards from ${creditCardsData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${uniqueLast4.size.toLocaleString()}</div><div class="data-page-stat-label">Unique Last4</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withHolder.toLocaleString()}</div><div class="data-page-stat-label">With Cardholder</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withCvc.toLocaleString()}</div><div class="data-page-stat-label">With CVC</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withExpiry.toLocaleString()}</div><div class="data-page-stat-label">With Expiry</div></div>`;
  let html = '<div class="data-table-container"><table class="data-table"><thead><tr><th>Card Number</th><th>Last4</th><th>Name On Card</th><th>Expiration</th><th>CVC</th><th>Browser</th><th>Recovered From</th></tr></thead><tbody>';
  html += buildRowsHtml(creditCardRowBuilder, creditCardsFiltered, 0, creditCardsShown);
  html += '</tbody></table></div>';
  const remaining = creditCardsFiltered.length - creditCardsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'cards');
  content.innerHTML = html;
}

function exportTokensCSV() {
  if (accountTokensData.entries.length === 0) return;
  downloadCsvRows('account_tokens.csv', ['Service', 'Type', 'Value', 'Account ID', 'Browser', 'Profile', 'Note', 'Source'], accountTokensData.entries.map(
    ({ service, type, value, accountId, browser, profile, note, source }) => [service, type, value, accountId, browser, profile, note, source]
  ));
}

function exportServicesCSV() {
  if (serviceArtifactsData.entries.length === 0) return;
  downloadCsvRows('service_artifacts.csv', ['Service', 'Artifact Type', 'Section', 'Key', 'Value', 'Source'], serviceArtifactsData.entries.map(
    ({ service, artifactType, section, key, value, source }) => [service, artifactType, section, key, value, source]
  ));
}

function exportWalletsCSV() {
  if (walletArtifactsData.entries.length === 0) return;
  downloadCsvRows('wallet_artifacts.csv', ['Service', 'Category', 'Artifact Type', 'Store Type', 'Browser', 'Profile', 'Emails', 'Addresses', 'Tokens', 'Seeds', 'Highlights', 'Source'], walletArtifactsData.entries.map(
    (entry) => [entry.service, entry.category, entry.artifactType, entry.storeType, entry.browser, entry.profile, entry.emailCount, entry.addressCount, entry.tokenCount, entry.seedHints, entry.highlights, entry.source]
  ));
}

function exportCardsCSV() {
  if (creditCardsData.entries.length === 0) return;
  downloadCsvRows('credit_cards.csv', ['Card Number', 'Last4', 'Name On Card', 'Expiration', 'CVC', 'Browser', 'Recovered From', 'Source'], creditCardsData.entries.map(
    ({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) => [cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source]
  ));
}

export function loadAll(fileTree, rootName) {
  return Promise.all([
    loadAccountTokensData(fileTree, rootName),
    loadServiceArtifactsData(fileTree, rootName),
    loadWalletArtifactsData(fileTree, rootName),
    loadCreditCardsData(fileTree, rootName),
  ]);
}

export function handleShowMore(pageId) {
  return pageRegistry.handleShowMore(pageId);
}

export function updateShown(pageId, newShown) {
  pageRegistry.updateShown(pageId, newShown);
}

export function updateNav() {
  pageRegistry.updateNav();
}

export function reset() {
  pageRegistry.reset();
}

export function initAssetPages() {
  const searchInputs = {
    tokens: document.getElementById('tokensSearch'),
    services: document.getElementById('servicesSearch'),
    wallets: document.getElementById('walletsSearch'),
    cards: document.getElementById('cardsSearch'),
  };
  const renderers = {
    tokens: renderTokensPage,
    services: renderServicesPage,
    wallets: renderWalletsPage,
    cards: renderCardsPage,
  };
  const tokensHideSensitive = document.getElementById('tokensHideSensitive');
  const cardsHideSensitive = document.getElementById('cardsHideSensitive');
  for (const [pageName, input] of Object.entries(searchInputs)) {
    bindDebouncedInput(input, (value) => renderers[pageName](value));
  }

  tokensHideSensitive?.addEventListener('change', () => {
    hideTokenValues = tokensHideSensitive.checked;
    renderTokensPage(searchInputs.tokens?.value || '');
  });

  cardsHideSensitive?.addEventListener('change', () => {
    hideCardNumbers = cardsHideSensitive.checked;
    renderCardsPage(searchInputs.cards?.value || '');
  });

  for (const [id, handler] of Object.entries({
    exportTokensCsv: exportTokensCSV,
    exportServicesCsv: exportServicesCSV,
    exportWalletsCsv: exportWalletsCSV,
    exportCardsCsv: exportCardsCSV,
  })) {
    document.getElementById(id)?.addEventListener('click', handler);
  }

  return {
    renders: Object.fromEntries(
      Object.entries(renderers).map(([pageName, render]) => [
        pageName,
        (q) => render(q || searchInputs[pageName]?.value || ''),
      ])
    ),
    resetSearches: () => {
      for (const input of Object.values(searchInputs)) {
        if (input) input.value = '';
      }
      if (cardsHideSensitive) cardsHideSensitive.checked = true;
      if (tokensHideSensitive) tokensHideSensitive.checked = true;
    },
  };
}

function getAccountTokensData() { return accountTokensData; }
function getServiceArtifactsData() { return serviceArtifactsData; }
function getWalletArtifactsData() { return walletArtifactsData; }
function getCreditCardsData() { return creditCardsData; }

export {
  getAccountTokensData,
  getServiceArtifactsData,
  getWalletArtifactsData,
  getCreditCardsData,
};
