// Asset pages: Tokens, Services, Wallets, Credit cards

import { escapeHtml } from '../core/utils.js';
import {
  parseAccountTokenFile,
  parseServiceArtifactFile,
} from '../transforms/structured.js';
import { parseCreditCardFile } from '../transforms/cards.js';
import { parseFileZillaSiteManager } from '../transforms/credentials.js';
import { parseWalletArtifact } from '../analysis/walletArtifacts.js';
import {
  decodeBufferWithFallback,
  inferBrowserFromPath,
  inferProfileFromPath,
  parseNodeCached,
} from '../core/shared.js';
import { inferServiceFromPath, serviceFromTokenType } from '../core/serviceRegistry.js';
import {
  countLabel,
  datasetSummary,
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  buildNoMatchesHtml,
  bindDebouncedInput,
  trimRootPath,
  inferServiceArtifactType,
  maskValue,
  maskCardNumber,
  extractCardLast4,
  exportRows,
  createPagedCollectionRegistry,
  createTableSort,
  bindTableSort,
  collectAndParse,
} from './shared.js';
import { DATA_PAGE_EMPTY_TEXT } from './registry.js';

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
let hideServiceSecrets = true;

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
      hideServiceSecrets = true;
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
  const artifacts = await collectAndParse(fileTree, rootName, '_serviceArtifactHint', (content, node, path) => {
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

  // FileZilla site managers carry a recovered host + user + plaintext password.
  // They are their own hint, so without this pass the credential is parsed and
  // then shown nowhere.
  const ftp = await collectAndParse(fileTree, rootName, '_ftpCredentialHint', (content, node, path) => {
    const text = decodeBufferWithFallback(content);
    const parsed = parseNodeCached(node, 'filezilla', parseFileZillaSiteManager, text, null);
    if (!parsed || parsed.rows.length === 0) return null;
    const rows = [];
    parsed.rows.forEach(([url, user, password], index) => {
      const section = `Site ${index + 1}`;
      const add = (key, value) => { if (value) rows.push({ service: 'FileZilla', artifactType: 'Saved site', section, key, value, source: path }); };
      add('Host', url);
      add('Username', user);
      add('Password', password);
    });
    return rows.length > 0 ? rows : null;
  }, RAW);

  serviceArtifactsData = {
    entries: [...artifacts.entries, ...ftp.entries],
    fileCount: artifacts.fileCount + ftp.fileCount,
  };
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
  const displayValue = hideTokenValues ? maskValue(value) : value;
  const maskedAttr = hideTokenValues ? ' class="masked"' : '';
  return `<tr><td>${escapeHtml(service || '')}</td><td>${escapeHtml(type || '')}</td><td${maskedAttr} title="${escapeHtml(displayValue)}">${escapeHtml(displayValue)}</td><td>${escapeHtml(accountId || '')}</td><td>${escapeHtml(browser || '')}</td><td>${escapeHtml(profile || '')}</td><td title="${escapeHtml(note || '')}">${escapeHtml(note || '')}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderTokensPage(searchQuery = '') {
  const summary = document.getElementById('tokensSummary');
  const stats = document.getElementById('tokensStats');
  const content = document.getElementById('tokensContent');
  if (accountTokensData.entries.length === 0) { accountTokensFiltered = []; accountTokensShown = 0; summary.textContent = ''; stats.innerHTML = ''; content.innerHTML = `<div class="no-data">${DATA_PAGE_EMPTY_TEXT.tokens}</div>`; return; }
  let filtered = accountTokensData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.type.toLowerCase().includes(q) || entry.value.toLowerCase().includes(q) || entry.accountId.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.note.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  accountTokensFiltered = tokensSort.apply(filtered);
  accountTokensShown = Math.min(PAGE_SIZE, filtered.length);
  summary.textContent = datasetSummary({ shown: filtered.length, total: accountTokensData.entries.length, singular: 'token', fileCount: accountTokensData.fileCount });
  if (filtered.length === 0) { stats.innerHTML = ''; content.innerHTML = buildNoMatchesHtml('account tokens'); return; }
  const services = new Set(filtered.map(e => e.service).filter(Boolean));
  const withValue = filtered.filter(e => e.value).length;
  const withAccountId = filtered.filter(e => e.accountId).length;
  const tokenTypes = new Set(filtered.map(e => e.type).filter(Boolean));
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withValue.toLocaleString()}</div><div class="data-page-stat-label">With token</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withAccountId.toLocaleString()}</div><div class="data-page-stat-label">With account ID</div></div><div class="data-page-stat"><div class="data-page-stat-value">${tokenTypes.size.toLocaleString()}</div><div class="data-page-stat-label">Token types</div></div>`;
  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${tokensSort.th('service', 'Service')}${tokensSort.th('type', 'Type')}${tokensSort.th('value', 'Value')}${tokensSort.th('accountId', 'Account ID')}${tokensSort.th('browser', 'Browser')}${tokensSort.th('profile', 'Profile')}${tokensSort.th('note', 'Note')}${tokensSort.th('source', 'Source')}</tr></thead><tbody>`;
  html += buildRowsHtml(accountTokenRowBuilder, accountTokensFiltered, 0, accountTokensShown);
  html += '</tbody></table></div>';
  const remaining = accountTokensFiltered.length - accountTokensShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'tokens');
  content.innerHTML = html;
}

// A service config carries the real thing as often as it carries a setting: an
// AnyDesk private key, a Discord token, a recovered FileZilla password. Those
// go behind the same mask the token values use, so the key is not sitting in
// the cell, in its title, and on the clipboard of the next stray click.
const PRIVATE_KEY_BLOCK = /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----/;
// Anchored at the end of the key name: `ad.anynet.pkey` and `Discord Token`
// name a secret, `mail.account.lastKey` and `oauth2.issuer` name where one
// lives.
const SECRET_KEY_NAME = /(?:^|[\s._-])(?:pass(?:word|wd)?|pwd|secret|api[\s._-]?key|private[\s._-]?key|pkey|(?:auth|access|refresh|bearer|session)[\s._-]?tokens?|token)$/i;

function isSecretValue(key, value) {
  if (!value) return false;
  return PRIVATE_KEY_BLOCK.test(value) || SECRET_KEY_NAME.test(String(key || '').trim());
}

function serviceArtifactRowBuilder({ service, artifactType, section, key, value, source }) {
  const masked = hideServiceSecrets && isSecretValue(key, value);
  const displayValue = masked ? maskValue(value) : value;
  const maskedAttr = masked ? ' class="masked"' : '';
  return `<tr><td>${escapeHtml(service || '')}</td><td>${escapeHtml(artifactType || '')}</td><td>${escapeHtml(section || '')}</td><td title="${escapeHtml(key)}">${escapeHtml(key)}</td><td${maskedAttr} title="${escapeHtml(displayValue)}">${escapeHtml(displayValue)}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderServicesPage(searchQuery = '') {
  const summary = document.getElementById('servicesSummary');
  const stats = document.getElementById('servicesStats');
  const content = document.getElementById('servicesContent');
  if (serviceArtifactsData.entries.length === 0) { serviceArtifactsFiltered = []; serviceArtifactsShown = 0; summary.textContent = ''; stats.innerHTML = ''; content.innerHTML = `<div class="no-data">${DATA_PAGE_EMPTY_TEXT.services}</div>`; return; }
  let filtered = serviceArtifactsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.artifactType.toLowerCase().includes(q) || entry.section.toLowerCase().includes(q) || entry.key.toLowerCase().includes(q) || entry.value.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  serviceArtifactsFiltered = servicesSort.apply(filtered);
  serviceArtifactsShown = Math.min(PAGE_SIZE, filtered.length);
  summary.textContent = datasetSummary({ shown: filtered.length, total: serviceArtifactsData.entries.length, singular: 'service row', fileCount: serviceArtifactsData.fileCount });
  if (filtered.length === 0) { stats.innerHTML = ''; content.innerHTML = buildNoMatchesHtml('service rows'); return; }
  const services = new Set(filtered.map(e => e.service).filter(Boolean));
  const artifactTypes = new Set(filtered.map(e => e.artifactType).filter(Boolean));
  const sections = new Set(filtered.map(e => e.section).filter(Boolean));
  const withValue = filtered.filter(e => e.value).length;
  const secrets = filtered.filter(e => isSecretValue(e.key, e.value)).length;
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${artifactTypes.size.toLocaleString()}</div><div class="data-page-stat-label">Artifact types</div></div><div class="data-page-stat"><div class="data-page-stat-value">${sections.size.toLocaleString()}</div><div class="data-page-stat-label">Sections</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withValue.toLocaleString()}</div><div class="data-page-stat-label">With value</div></div>${secrets > 0 ? `<div class="data-page-stat" title="Rows whose value is itself a credential — a private key, an account token, a saved password. Masked until the filter is cleared."><div class="data-page-stat-value">${secrets.toLocaleString()}</div><div class="data-page-stat-label">Secret values</div></div>` : ''}`;
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
  if (walletArtifactsData.entries.length === 0) { walletArtifactsFiltered = []; walletArtifactsShown = 0; summary.textContent = ''; stats.innerHTML = ''; content.innerHTML = `<div class="no-data">${DATA_PAGE_EMPTY_TEXT.wallets}</div>`; return; }
  let filtered = walletArtifactsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.service.toLowerCase().includes(q) || entry.category.toLowerCase().includes(q) || entry.artifactType.toLowerCase().includes(q) || entry.storeType.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.highlights.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  walletArtifactsFiltered = walletsSort.apply(filtered);
  walletArtifactsShown = Math.min(PAGE_SIZE, filtered.length);
  summary.textContent = datasetSummary({ shown: filtered.length, total: walletArtifactsData.entries.length, singular: 'wallet artifact', fileCount: walletArtifactsData.fileCount });
  if (filtered.length === 0) { stats.innerHTML = ''; content.innerHTML = buildNoMatchesHtml('wallet artifacts'); return; }
  const services = new Set(filtered.map(e => e.service).filter(Boolean));
  const passwordManagers = filtered.filter(e => e.category === 'Password Manager').length;
  const rawStores = filtered.filter(e => e.storeType === 'LevelDB' || e.storeType === 'SQLite').length;
  const signalHits = filtered.reduce((sum, e) => sum + e.emailCount + e.addressCount + e.tokenCount + e.seedHints, 0);
  // A `mnemonic` / `seed phrase` keyword lands in every wallet extension's own
  // UI translation table, so the keyword count is context only. The banner needs
  // a corroborated candidate — an actual word run of seed length. It speaks for
  // the case rather than the view, so the search box does not narrow it.
  const seedEntries = walletArtifactsData.entries.filter(e => e.seedPhraseCount > 0);
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${services.size.toLocaleString()}</div><div class="data-page-stat-label">Services</div></div><div class="data-page-stat"><div class="data-page-stat-value">${passwordManagers.toLocaleString()}</div><div class="data-page-stat-label">Password managers</div></div><div class="data-page-stat"><div class="data-page-stat-value">${rawStores.toLocaleString()}</div><div class="data-page-stat-label">Raw stores</div></div><div class="data-page-stat"><div class="data-page-stat-value">${signalHits.toLocaleString()}</div><div class="data-page-stat-label">Signal hits</div></div>`;
  let html = '';
  if (seedEntries.length > 0) {
    const names = [...new Set(seedEntries.map(e => e.service).filter(Boolean))].slice(0, 6).map(n => escapeHtml(n)).join(', ');
    html += `<div class="data-page-warning"><div class="data-page-warning-title">Wallet seed phrase exposure</div><div class="data-page-warning-more">${countLabel(seedEntries.length, 'crypto-wallet artifact')} with a recovery-phrase candidate${names ? ` (${names})` : ''}.</div></div>`;
  }
  html += `<div class="data-table-container"><table class="data-table"><thead><tr>${walletsSort.th('service', 'Service')}${walletsSort.th('category', 'Category')}${walletsSort.th('artifactType', 'Artifact Type')}${walletsSort.th('storeType', 'Store Type')}${walletsSort.th('browser', 'Browser')}${walletsSort.th('profile', 'Profile')}${walletsSort.th('emails', 'Emails')}${walletsSort.th('addresses', 'Addresses')}${walletsSort.th('tokens', 'Tokens')}${walletsSort.th('seeds', 'Seed Keywords')}${walletsSort.th('highlights', 'Highlights')}${walletsSort.th('source', 'Source')}</tr></thead><tbody>`;
  html += buildRowsHtml(walletArtifactRowBuilder, walletArtifactsFiltered, 0, walletArtifactsShown);
  html += '</tbody></table></div>';
  const remaining = walletArtifactsFiltered.length - walletArtifactsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'wallets');
  content.innerHTML = html;
}

function creditCardRowBuilder({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) {
  const cardDisplay = hideCardNumbers ? maskCardNumber(cardNumber) : cardNumber;
  const cvcDisplay = hideCardNumbers && cvc ? '\u2022\u2022\u2022' : cvc;
  const maskedAttr = hideCardNumbers ? ' class="masked"' : '';
  return `<tr><td${maskedAttr} title="${escapeHtml(cardDisplay)}">${escapeHtml(cardDisplay)}</td><td>${escapeHtml(last4)}</td><td title="${escapeHtml(nameOnCard)}">${escapeHtml(nameOnCard)}</td><td>${escapeHtml(expiration)}</td><td${maskedAttr}>${escapeHtml(cvcDisplay)}</td><td>${escapeHtml(browser)}</td><td title="${escapeHtml(filePath || source)}">${escapeHtml(trimRootPath(filePath || source))}</td></tr>`;
}

function renderCardsPage(searchQuery = '') {
  const summary = document.getElementById('cardsSummary');
  const stats = document.getElementById('cardsStats');
  const content = document.getElementById('cardsContent');
  if (creditCardsData.entries.length === 0) { creditCardsFiltered = []; creditCardsShown = 0; summary.textContent = ''; stats.innerHTML = ''; content.innerHTML = `<div class="no-data">${DATA_PAGE_EMPTY_TEXT.cards}</div>`; return; }
  let filtered = creditCardsData.entries;
  if (searchQuery) { const q = searchQuery.toLowerCase(); filtered = filtered.filter(entry => entry.cardNumber.toLowerCase().includes(q) || entry.last4.toLowerCase().includes(q) || entry.nameOnCard.toLowerCase().includes(q) || entry.expiration.toLowerCase().includes(q) || entry.cvc.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.filePath.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q)); }
  creditCardsFiltered = cardsSort.apply(filtered);
  creditCardsShown = Math.min(PAGE_SIZE, filtered.length);
  summary.textContent = datasetSummary({ shown: filtered.length, total: creditCardsData.entries.length, singular: 'card', fileCount: creditCardsData.fileCount });
  if (filtered.length === 0) { stats.innerHTML = ''; content.innerHTML = buildNoMatchesHtml('cards'); return; }
  const withHolder = filtered.filter(e => e.nameOnCard).length;
  const withCvc = filtered.filter(e => e.cvc).length;
  const withExpiry = filtered.filter(e => e.expiration && e.expiration !== '/').length;
  const uniqueLast4 = new Set(filtered.map(e => e.last4).filter(Boolean));
  stats.innerHTML = `<div class="data-page-stat"><div class="data-page-stat-value">${uniqueLast4.size.toLocaleString()}</div><div class="data-page-stat-label">Unique last4</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withHolder.toLocaleString()}</div><div class="data-page-stat-label">With cardholder</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withCvc.toLocaleString()}</div><div class="data-page-stat-label">With CVC</div></div><div class="data-page-stat"><div class="data-page-stat-value">${withExpiry.toLocaleString()}</div><div class="data-page-stat-label">With expiry</div></div>`;
  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${cardsSort.th('cardNumber', 'Card Number')}${cardsSort.th('last4', 'Last4')}${cardsSort.th('nameOnCard', 'Name On Card')}${cardsSort.th('expiration', 'Expiration')}${cardsSort.th('cvc', 'CVC')}${cardsSort.th('browser', 'Browser')}${cardsSort.th('source', 'Recovered From')}</tr></thead><tbody>`;
  html += buildRowsHtml(creditCardRowBuilder, creditCardsFiltered, 0, creditCardsShown);
  html += '</tbody></table></div>';
  const remaining = creditCardsFiltered.length - creditCardsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'cards');
  content.innerHTML = html;
}

// One description of each dataset's CSV shape, so the page's own export and the
// packaged report cannot write the same table under two sets of columns.
export const CSV_SPECS = Object.freeze({
  tokens: Object.freeze({
    file: 'account_tokens.csv', noun: 'account tokens',
    headers: ['Service', 'Type', 'Value', 'Account ID', 'Browser', 'Profile', 'Note', 'Source'],
    row: ({ service, type, value, accountId, browser, profile, note, source }) => [service, type, value, accountId, browser, profile, note, source],
  }),
  services: Object.freeze({
    file: 'service_artifacts.csv', noun: 'service rows',
    headers: ['Service', 'Artifact Type', 'Section', 'Key', 'Value', 'Source'],
    row: ({ service, artifactType, section, key, value, source }) => [service, artifactType, section, key, value, source],
  }),
  wallets: Object.freeze({
    file: 'wallet_artifacts.csv', noun: 'wallet artifacts',
    headers: ['Service', 'Category', 'Artifact Type', 'Store Type', 'Browser', 'Profile', 'Emails', 'Addresses', 'Tokens', 'Seed Keywords', 'Highlights', 'Source'],
    row: (entry) => [entry.service, entry.category, entry.artifactType, entry.storeType, entry.browser, entry.profile, entry.emailCount, entry.addressCount, entry.tokenCount, entry.seedHints, entry.highlights, entry.source],
  }),
  cards: Object.freeze({
    file: 'credit_cards.csv', noun: 'cards',
    headers: ['Card Number', 'Last4', 'Name On Card', 'Expiration', 'CVC', 'Browser', 'Recovered From', 'Source'],
    // Recovered From falls back to the archive path the same way the table
    // does; Source keeps the archive path either way, so the two columns
    // together still say whether the card file named its own origin.
    row: ({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) => [cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath || source, source],
  }),
});

function exportCsv(spec, entries, filtered) {
  exportRows({ ...spec, entries, filtered });
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
  const servicesHideSecrets = document.getElementById('servicesHideSecrets');
  const cardsHideSensitive = document.getElementById('cardsHideSensitive');
  for (const [pageName, input] of Object.entries(searchInputs)) {
    bindDebouncedInput(input, (value) => renderers[pageName](value));
    bindTableSort(`${pageName}Content`, pageSorts[pageName], () => renderers[pageName](input?.value || ''));
  }

  tokensHideSensitive?.addEventListener('change', () => {
    hideTokenValues = tokensHideSensitive.checked;
    renderTokensPage(searchInputs.tokens?.value || '');
  });

  servicesHideSecrets?.addEventListener('change', () => {
    hideServiceSecrets = servicesHideSecrets.checked;
    renderServicesPage(searchInputs.services?.value || '');
  });

  cardsHideSensitive?.addEventListener('change', () => {
    hideCardNumbers = cardsHideSensitive.checked;
    renderCardsPage(searchInputs.cards?.value || '');
  });

  for (const [id, handler] of Object.entries({
    exportTokensCsv: () => exportCsv(CSV_SPECS.tokens, accountTokensData.entries, accountTokensFiltered),
    exportServicesCsv: () => exportCsv(CSV_SPECS.services, serviceArtifactsData.entries, serviceArtifactsFiltered),
    exportWalletsCsv: () => exportCsv(CSV_SPECS.wallets, walletArtifactsData.entries, walletArtifactsFiltered),
    exportCardsCsv: () => exportCsv(CSV_SPECS.cards, creditCardsData.entries, creditCardsFiltered),
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
      if (servicesHideSecrets) servicesHideSecrets.checked = true;
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
