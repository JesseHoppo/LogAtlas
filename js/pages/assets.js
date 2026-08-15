// Asset pages: Tokens, Services, Wallets, Credit Cards

import { escapeHtml } from '../core/utils.js';
import {
  parseAccountTokenFile,
  parseServiceArtifactFile,
} from '../transforms/structured.js';
import { parseCreditCardFile } from '../transforms/cards.js';
import { parseWalletArtifact } from '../analysis/walletArtifacts.js';
import {
  decodeBufferWithFallback,
  inferBrowserFromPath,
  inferProfileFromPath,
  parseNodeCached,
} from '../core/shared.js';
import { inferServiceFromPath, serviceFromTokenType } from '../core/serviceRegistry.js';
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
  createTableSort,
  bindTableSort,
  collectAndParse,
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

const tokensSort = createTableSort({
  service: (e) => e.service, type: (e) => e.type, value: (e) => e.value, accountId: (e) => e.accountId,
  browser: (e) => e.browser, profile: (e) => e.profile, note: (e) => e.note, source: (e) => e.source,
});
const servicesSort = createTableSort({
  service: (e) => e.service, artifactType: (e) => e.artifactType, section: (e) => e.section,
  key: (e) => e.key, value: (e) => e.value, source: (e) => e.source,
});
const walletsSort = createTableSort({
  service: (e) => e.service, category: (e) => e.category, artifactType: (e) => e.artifactType,
  storeType: (e) => e.storeType, browser: (e) => e.browser, profile: (e) => e.profile,
  emails: (e) => e.emailCount, addresses: (e) => e.addressCount, tokens: (e) => e.tokenCount,
  seeds: (e) => e.seedHints, highlights: (e) => e.highlights, source: (e) => e.source,
});
const cardsSort = createTableSort({
  cardNumber: (e) => e.cardNumber, last4: (e) => e.last4, nameOnCard: (e) => e.nameOnCard,
  expiration: (e) => e.expiration, cvc: (e) => e.cvc, browser: (e) => e.browser,
  source: (e) => e.filePath || e.source,
});

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
      tokensSort.reset();
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
      servicesSort.reset();
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
      walletsSort.reset();
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
      cardsSort.reset();
      creditCardsShown = 0;
      hideCardNumbers = true;
    },
  },
});

// Raw bytes rather than text: these loaders decode with the same fallback the
// analysis pass uses, so the parse both sides share is built from the same text.
const RAW = { decode: false };

async function loadAccountTokensData(fileTree, rootName) {
  accountTokensData = await collectAndParse(fileTree, rootName, '_accountTokenHint', (content, node, path) => {
    const text = decodeBufferWithFallback(content);
    const parsed = parseNodeCached(node, 'token', parseAccountTokenFile, text, path || node.name);
    if (!parsed || parsed.rows.length === 0) return null;
    const pathService = inferServiceFromPath(path || node.name);
    const browser = inferBrowserFromPath(path || node.name);
    const profile = inferProfileFromPath(path || node.name);
    const rows = [];
    for (const row of parsed.rows) {
      const type = (row[0] || '').trim();
      const value = (row[1] || '').trim();
      const accountId = (row[2] || '').trim();
      const note = (row[3] || '').trim();
      if (!value && !accountId) continue;
      const service = pathService || serviceFromTokenType(type) || 'Unknown';
      rows.push({ service, type, value, accountId, browser, profile, note, source: path });
    }
    return rows;
  }, RAW);
}

async function loadServiceArtifactsData(fileTree, rootName) {
  serviceArtifactsData = await collectAndParse(fileTree, rootName, '_serviceArtifactHint', (content, node, path) => {
    const text = decodeBufferWithFallback(content);
    const parsed = parseNodeCached(node, 'service', parseServiceArtifactFile, text, null);
    if (!parsed || parsed.rows.length === 0) return null;
    const service = inferServiceFromPath(path || node.name) || 'Unknown';
    const artifactType = inferServiceArtifactType(path || node.name);
    const rows = [];
    for (const row of parsed.rows) {
      const section = (row[0] || '').trim();
      const key = (row[1] || '').trim();
      const value = (row[2] || '').trim();
      if (!key && !value) continue;
      rows.push({ service, artifactType, section, key, value, source: path });
    }
    return rows;
  }, RAW);
}

async function loadWalletArtifactsData(fileTree, rootName) {
  walletArtifactsData = await collectAndParse(fileTree, rootName, '_cryptoWalletHint', (content, node, path) => {
    // Keyed on the source path: it lands in the parsed entry, and the analysis
    // pass walks a collapsed root, so a shared entry built from the other
    // side's path would quietly relabel this row's source.
    const parsed = parseNodeCached(node, 'wallet',
      (bytes, sourcePath) => parseWalletArtifact(bytes, node.name || '', sourcePath),
      content, path || node.name || '');
    return parsed || null;
  }, RAW);
}

async function loadCreditCardsData(fileTree, rootName) {
  creditCardsData = await collectAndParse(fileTree, rootName, '_creditCardHint', (content, node, path) => {
    const text = decodeBufferWithFallback(content);
    const parsed = parseNodeCached(node, 'card', parseCreditCardFile, text, null);
    if (!parsed || parsed.rows.length === 0) return null;
    const rows = [];
    for (const row of parsed.rows) {
      const cardNumber = (row[0] || '').trim();
      const nameOnCard = (row[1] || '').trim();
      const cvc = (row[2] || '').trim();
      const expiration = (row[3] || '').trim();
      const filePath = (row[4] || '').trim();
      if (!cardNumber && !nameOnCard && !cvc && !expiration && !filePath) continue;
      rows.push({ cardNumber, last4: extractCardLast4(cardNumber), nameOnCard, cvc, expiration, filePath, browser: inferBrowserFromPath(filePath || path), source: path });
    }
    return rows;
  }, RAW);
}

function accountTokenRowBuilder({ service, type, value, accountId, browser, profile, note, source }) {
  const displayValue = hideTokenValues ? maskTokenValue(value) : value;
  return `<tr><td>${escapeHtml(service || '')}</td><td>${escapeHtml(type || '')}</td><td title="${escapeHtml(displayValue)}">${escapeHtml(displayValue)}</td><td>${escapeHtml(accountId || '')}</td><td>${escapeHtml(browser || '')}</td><td>${escapeHtml(profile || '')}</td><td title="${escapeHtml(note || '')}">${escapeHtml(note || '')}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderTokensPage(searchQuery = '') {
  const summary = document.getElementById('tokensSummary');
  const stats = document.getElementById('tokensStats');
  const content = document.getElementById('tokensContent');
  if (accountTokensData.entries.length === 0) { summary.textContent = 'No account tokens found'; stats.innerHTML = ''; content.innerHTML = '<div class="no-data">No account-token data available.</div>'; return; }
  let filtered = accountTokensData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.type.toLowerCase().includes(q) || entry.value.toLowerCase().includes(q) || entry.accountId.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.note.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  accountTokensFiltered = tokensSort.apply(filtered);
  accountTokensShown = Math.min(PAGE_SIZE, filtered.length);
  const services = new Set(accountTokensData.entries.map(e => e.service).filter(Boolean));
  const withValue = accountTokensData.entries.filter(e => e.value).length;
  const withAccountId = accountTokensData.entries.filter(e => e.accountId).length;
  const tokenTypes = new Set(accountTokensData.entries.map(e => e.type).filter(Boolean));
  summary.textContent = filtered.length !== accountTokensData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${accountTokensData.entries.length.toLocaleString()} token rows from ${accountTokensData.fileCount} file(s)` : `${accountTokensData.entries.length.toLocaleString()} token rows from ${accountTokensData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withValue.toLocaleString()}</div><div class="data-page-stat-label">With Token</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withAccountId.toLocaleString()}</div><div class="data-page-stat-label">With Account ID</div></div><div class="data-page-stat"><div class="data-page-stat-value">${tokenTypes.size.toLocaleString()}</div><div class="data-page-stat-label">Token Types</div></div>`;
  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${tokensSort.th('service', 'Service')}${tokensSort.th('type', 'Type')}${tokensSort.th('value', 'Value')}${tokensSort.th('accountId', 'Account ID')}${tokensSort.th('browser', 'Browser')}${tokensSort.th('profile', 'Profile')}${tokensSort.th('note', 'Note')}${tokensSort.th('source', 'Source')}</tr></thead><tbody>`;
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
  serviceArtifactsFiltered = servicesSort.apply(filtered);
  serviceArtifactsShown = Math.min(PAGE_SIZE, filtered.length);
  const services = new Set(serviceArtifactsData.entries.map(e => e.service).filter(Boolean));
  const artifactTypes = new Set(serviceArtifactsData.entries.map(e => e.artifactType).filter(Boolean));
  const sections = new Set(serviceArtifactsData.entries.map(e => e.section).filter(Boolean));
  const withValue = serviceArtifactsData.entries.filter(e => e.value).length;
  summary.textContent = filtered.length !== serviceArtifactsData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${serviceArtifactsData.entries.length.toLocaleString()} service rows from ${serviceArtifactsData.fileCount} file(s)` : `${serviceArtifactsData.entries.length.toLocaleString()} service rows from ${serviceArtifactsData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${artifactTypes.size.toLocaleString()}</div><div class="data-page-stat-label">Artifact Types</div></div><div class="data-page-stat"><div class="data-page-stat-value">${sections.size.toLocaleString()}</div><div class="data-page-stat-label">Sections</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withValue.toLocaleString()}</div><div class="data-page-stat-label">With Value</div></div>`;
  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${servicesSort.th('service', 'Service')}${servicesSort.th('artifactType', 'Artifact Type')}${servicesSort.th('section', 'Section')}${servicesSort.th('key', 'Key')}${servicesSort.th('value', 'Value')}${servicesSort.th('source', 'Source')}</tr></thead><tbody>`;
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
  walletArtifactsFiltered = walletsSort.apply(filtered);
  walletArtifactsShown = Math.min(PAGE_SIZE, filtered.length);
  const services = new Set(walletArtifactsData.entries.map(e => e.service).filter(Boolean));
  const passwordManagers = walletArtifactsData.entries.filter(e => e.category === 'Password Manager').length;
  const rawStores = walletArtifactsData.entries.filter(e => e.storeType === 'LevelDB' || e.storeType === 'SQLite').length;
  const signalHits = walletArtifactsData.entries.reduce((sum, e) => sum + e.emailCount + e.addressCount + e.tokenCount + e.seedHints, 0);
  const seedEntries = walletArtifactsData.entries.filter(e => e.seedHints > 0 && e.category !== 'Password Manager');
  summary.textContent = filtered.length !== walletArtifactsData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${walletArtifactsData.entries.length.toLocaleString()} wallet/store artifacts from ${walletArtifactsData.fileCount} file(s)` : `${walletArtifactsData.entries.length.toLocaleString()} wallet/store artifacts from ${walletArtifactsData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${passwordManagers.toLocaleString()}</div><div class="data-page-stat-label">Password Managers</div></div><div class="data-page-stat"><div class="data-page-stat-value">${rawStores.toLocaleString()}</div><div class="data-page-stat-label">Raw Stores</div></div><div class="data-page-stat"><div class="data-page-stat-value">${signalHits.toLocaleString()}</div><div class="data-page-stat-label">Signal Hits</div></div>`;
  let html = '';
  if (seedEntries.length > 0) {
    const names = [...new Set(seedEntries.map(e => e.service).filter(Boolean))].slice(0, 6).map(n => escapeHtml(n)).join(', ');
    html += `<div class="data-page-warning"><div class="data-page-warning-title">Wallet seed phrase exposure</div><div class="data-page-warning-more">${seedEntries.length.toLocaleString()} crypto-wallet artifact(s) contain recovery-phrase indicators${names ? ` (${names})` : ''}.</div></div>`;
  }
  html += `<div class="data-table-container"><table class="data-table"><thead><tr>${walletsSort.th('service', 'Service')}${walletsSort.th('category', 'Category')}${walletsSort.th('artifactType', 'Artifact Type')}${walletsSort.th('storeType', 'Store Type')}${walletsSort.th('browser', 'Browser')}${walletsSort.th('profile', 'Profile')}${walletsSort.th('emails', 'Emails')}${walletsSort.th('addresses', 'Addresses')}${walletsSort.th('tokens', 'Tokens')}${walletsSort.th('seeds', 'Seeds')}${walletsSort.th('highlights', 'Highlights')}${walletsSort.th('source', 'Source')}</tr></thead><tbody>`;
  html += buildRowsHtml(walletArtifactRowBuilder, walletArtifactsFiltered, 0, walletArtifactsShown);
  html += '</tbody></table></div>';
  const remaining = walletArtifactsFiltered.length - walletArtifactsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'wallets');
  content.innerHTML = html;
}

function creditCardRowBuilder({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) {
  const cardDisplay = hideCardNumbers ? maskCardNumber(cardNumber) : cardNumber;
  const cvcDisplay = hideCardNumbers && cvc ? '\u2022\u2022\u2022' : cvc;
  return `<tr><td title="${escapeHtml(cardDisplay)}">${escapeHtml(cardDisplay)}</td><td>${escapeHtml(last4)}</td><td title="${escapeHtml(nameOnCard)}">${escapeHtml(nameOnCard)}</td><td>${escapeHtml(expiration)}</td><td>${escapeHtml(cvcDisplay)}</td><td>${escapeHtml(browser)}</td><td title="${escapeHtml(filePath || source)}">${escapeHtml(trimRootPath(filePath || source))}</td></tr>`;
}

function renderCardsPage(searchQuery = '') {
  const summary = document.getElementById('cardsSummary');
  const stats = document.getElementById('cardsStats');
  const content = document.getElementById('cardsContent');
  if (creditCardsData.entries.length === 0) { summary.textContent = 'No credit cards found'; stats.innerHTML = ''; content.innerHTML = '<div class="no-data">No credit-card data available.</div>'; return; }
  let filtered = creditCardsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.cardNumber.toLowerCase().includes(q) || entry.last4.toLowerCase().includes(q) || entry.nameOnCard.toLowerCase().includes(q) || entry.expiration.toLowerCase().includes(q) || entry.cvc.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.filePath.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  creditCardsFiltered = cardsSort.apply(filtered);
  creditCardsShown = Math.min(PAGE_SIZE, filtered.length);
  const withHolder = creditCardsData.entries.filter(e => e.nameOnCard).length;
  const withCvc = creditCardsData.entries.filter(e => e.cvc).length;
  const withExpiry = creditCardsData.entries.filter(e => e.expiration && e.expiration !== '/').length;
  const uniqueLast4 = new Set(creditCardsData.entries.map(e => e.last4).filter(Boolean));
  summary.textContent = filtered.length !== creditCardsData.entries.length ? `Showing ${filtered.length.toLocaleString()} of ${creditCardsData.entries.length.toLocaleString()} cards from ${creditCardsData.fileCount} file(s)` : `${creditCardsData.entries.length.toLocaleString()} cards from ${creditCardsData.fileCount} file(s)`;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${uniqueLast4.size.toLocaleString()}</div><div class="data-page-stat-label">Unique Last4</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withHolder.toLocaleString()}</div><div class="data-page-stat-label">With Cardholder</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withCvc.toLocaleString()}</div><div class="data-page-stat-label">With CVC</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withExpiry.toLocaleString()}</div><div class="data-page-stat-label">With Expiry</div></div>`;
  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${cardsSort.th('cardNumber', 'Card Number')}${cardsSort.th('last4', 'Last4')}${cardsSort.th('nameOnCard', 'Name On Card')}${cardsSort.th('expiration', 'Expiration')}${cardsSort.th('cvc', 'CVC')}${cardsSort.th('browser', 'Browser')}${cardsSort.th('source', 'Recovered From')}</tr></thead><tbody>`;
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

const pageSorts = { tokens: tokensSort, services: servicesSort, wallets: walletsSort, cards: cardsSort };

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
    bindTableSort(`${pageName}Content`, pageSorts[pageName], () => renderers[pageName](input?.value || ''));
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
