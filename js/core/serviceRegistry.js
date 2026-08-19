import { JWT_SCAN_REGEX } from './definitions/patterns.js';

const GENERAL_SERVICE_DEFINITIONS = Object.freeze([
  { label: 'Google', patterns: [/googleaccounts/i, /googletokens?/i, /restore_(?:google[\s_-]*)?chrome[^/]*\.txt$/i] },
  { label: 'Discord', patterns: [/discord/i] },
  { label: 'Steam', patterns: [/steam/i] },
  { label: 'Facebook', patterns: [/fbfastcheck/i, /facebook/i, /token_eaab/i] },
  { label: 'Telegram', patterns: [/telegram/i] },
  { label: 'AnyDesk', patterns: [/anydesk/i] },
  { label: 'Outlook', patterns: [/outlook/i] },
  { label: 'FileZilla', patterns: [/filezilla/i, /ftp/i] },
  { label: 'Thunderbird', patterns: [/thunderbird/i] },
]);

// `patterns` decide a path segment, where the vocabulary is the stealer's own.
// `contentPatterns` decide a blob, where every byte is the victim's, so only a
// name no note or cookie domain could contain carries one — "atomic", "exodus",
// "steam", "keychain", "ronin", "keplr" and "phantom" are left path-only. A
// definition with no `contentPatterns` is simply never raised by content.
const STORE_SERVICE_DEFINITIONS = Object.freeze([
  { name: 'Bitwarden', category: 'Password Manager', patterns: [/bitwarden/i], contentPatterns: [/\bbitwarden\b/i], extensionIds: ['nngceckbapebfimnlniiiahkandclblb'] },
  { name: '1Password', category: 'Password Manager', patterns: [/1password/i, /onepassword/i, /opvault/i], contentPatterns: [/\b1password\b/i, /\bonepassword\b/i, /\bopvault\b/i], extensionIds: ['aeblfdkhhhdcdjpifhhbdiojplfjncoa', 'dppgmdbiimibapkepcbdbmkaabgiofem'] },
  { name: 'LastPass', category: 'Password Manager', patterns: [/lastpass/i], contentPatterns: [/\blastpass\b/i], extensionIds: ['hdokiejnpimakedhajhdlcegeplioahd'] },
  { name: 'Dashlane', category: 'Password Manager', patterns: [/dashlane/i], contentPatterns: [/\bdashlane\b/i], extensionIds: ['fdjamakpfbbddfjaooikfcpapjohcfmg'] },
  { name: 'NordPass', category: 'Password Manager', patterns: [/nordpass/i], contentPatterns: [/\bnordpass\b/i], extensionIds: ['fooolghllnmhmmndgjiamiiodkpenpbb'] },
  { name: 'RoboForm', category: 'Password Manager', patterns: [/roboform/i], contentPatterns: [/\broboform\b/i], extensionIds: ['pnlccmojcmeohlpggmfnbbiapkmbliob'] },
  { name: 'KeePassXC', category: 'Password Manager', patterns: [/keepassxc/i], contentPatterns: [/\bkeepassxc\b/i], extensionIds: [] },
  { name: 'KeePass', category: 'Password Manager', patterns: [/keepass/i, /\.kdbx$/i], contentPatterns: [/\bkeepass\b/i], extensionIds: [] },
  { name: 'MetaMask', category: 'Wallet', patterns: [/metamask/i], contentPatterns: [/\bmetamask\b/i, /KeyringController/, /encryptedVault/, /encryptedSeed/], extensionIds: ['nkbihfbeogaeaoehlefnkodbefgpgknn'] },
  { name: 'Phantom', category: 'Wallet', patterns: [/phantom/i], extensionIds: ['bfnaelmomeimhlpmgjnjophhpkkoljpa'] },
  { name: 'Coinbase Wallet', category: 'Wallet', patterns: [/coinbase/i], extensionIds: ['jbkfoedolllekgbhcbcoahefnbanhhlh'] },
  { name: 'Rabby', category: 'Wallet', patterns: [/rabby/i], contentPatterns: [/\brabby\b/i], extensionIds: ['acmacodkjbdgmoleebolmdjonilkdbch'] },
  { name: 'Ronin', category: 'Wallet', patterns: [/ronin/i], extensionIds: ['fnjhmkhhmkbjkkabndcnnogagogbneec'] },
  { name: 'Keplr', category: 'Wallet', patterns: [/keplr/i], extensionIds: ['dmkamcknogkgcdfhhbddcghachkejeap'] },
  { name: 'TronLink', category: 'Wallet', patterns: [/tronlink/i], contentPatterns: [/\btronlink\b/i], extensionIds: ['ibnejdfjmmkpcnlpebklmnkoeoihofec'] },
  { name: 'Exodus', category: 'Wallet', patterns: [/exodus/i], extensionIds: [] },
  { name: 'Atomic Wallet', category: 'Wallet', patterns: [/atomic/i], extensionIds: [] },
  { name: 'Electrum', category: 'Wallet', patterns: [/electrum/i], extensionIds: [] },
  { name: 'Trust Wallet', category: 'Wallet', patterns: [/trust[\s_-]*wallet/i], contentPatterns: [/\btrust[\s_-]*wallet\b/i], extensionIds: [] },
  { name: 'Steam', category: 'Token Store', patterns: [/steam/i], extensionIds: [] },
  { name: 'Apple Keychain', category: 'Secret Store', patterns: [/keychain/i], extensionIds: [] },
]);

function normaliseServiceText(value) {
  return String(value || '').replace(/\\/g, '/').toLowerCase();
}

function findServiceDefinition(value, definitions) {
  const normalised = normaliseServiceText(value);
  if (!normalised) return null;

  for (const definition of definitions) {
    if (definition.patterns.some((pattern) => pattern.test(normalised))) {
      return definition;
    }
  }

  return null;
}

function findDefinitionInSegments(pathText, definitions) {
  const segments = normaliseServiceText(pathText).split('/').filter(Boolean);

  // Deepest segment first: the folder actually holding the data outranks
  // everything above it, so an archive root named after the wallets it contains
  // or a grouping folder the stealer chose never overrides the leaf.
  for (let index = segments.length - 1; index >= 0; index--) {
    const match = definitions.find(
      (definition) => definition.patterns.some((pattern) => pattern.test(segments[index])),
    );
    if (match) return match;
  }

  return null;
}

function findStoreServiceByPath(pathText) {
  const normalisedPath = normaliseServiceText(pathText);

  // An extension id is exact identification; a folder name is only the label
  // the stealer picked, and those labels routinely disagree with the contents.
  const byExtensionId = STORE_SERVICE_DEFINITIONS.find(
    (definition) => definition.extensionIds && definition.extensionIds.some((id) => normalisedPath.includes(id)),
  );
  if (byExtensionId) return byExtensionId;

  return findDefinitionInSegments(pathText, STORE_SERVICE_DEFINITIONS);
}

function decodeJwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;

  try {
    const normalised = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - normalised.length % 4) % 4);
    const decoded = atob(normalised + padding);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

function inferServiceFromPath(pathText) {
  return findDefinitionInSegments(pathText, GENERAL_SERVICE_DEFINITIONS)?.label || '';
}

// Only kinds that name their vendor outright belong here. A restore token is
// whatever the browser signs into — every Chromium browser writes one, and only
// Chrome's is a Google account — so its vendor comes from the path or browser.
const TOKEN_TYPE_SERVICE = [
  { service: 'Google', patterns: [/google/i] },
  { service: 'Facebook', patterns: [/facebook/i] },
  { service: 'Discord', patterns: [/discord/i] },
  { service: 'Steam', patterns: [/steam/i] },
];

function serviceFromTokenType(type) {
  const normalised = String(type || '').toLowerCase();
  if (!normalised) return '';
  for (const { service, patterns } of TOKEN_TYPE_SERVICE) {
    if (patterns.some((pattern) => pattern.test(normalised))) return service;
  }
  return '';
}

const BROWSER_ACCOUNT_SERVICE = {
  Chrome: 'Google',
  Edge: 'Microsoft',
  Firefox: 'Mozilla',
  Safari: 'Apple',
  YandexBrowser: 'Yandex',
};

// Only for browsers whose sign-in is tied to one vendor; Chromium forks such as
// Brave or Opera carry accounts from anywhere, so they stay unattributed.
function serviceFromBrowser(browser) {
  return BROWSER_ACCOUNT_SERVICE[String(browser || '')] || '';
}

const STORE_CONTENT_PATTERNS = STORE_SERVICE_DEFINITIONS
  .filter((definition) => definition.contentPatterns)
  .map((definition) => ({
    definition,
    patterns: definition.contentPatterns.map((pattern) => new RegExp(pattern.source, `g${pattern.flags.replace('g', '')}`)),
  }));

// A store blob names its rivals in passing — chain lists, bundled icons, an
// imported vault — so the leader has to clear the runner-up by this much before
// its name is worth putting on the row.
const CONTENT_LEAD = 2;

function countMatches(text, pattern) {
  pattern.lastIndex = 0;
  let hits = 0;
  while (pattern.exec(text)) hits++;
  return hits;
}

function findStoreServiceByContent(text) {
  const value = String(text || '');
  if (!value) return null;

  const scored = [];
  for (const { definition, patterns } of STORE_CONTENT_PATTERNS) {
    let hits = 0;
    for (const pattern of patterns) hits += countMatches(value, pattern);
    if (hits > 0) scored.push({ definition, hits });
  }
  if (scored.length === 0) return null;

  scored.sort((a, b) => b.hits - a.hits);
  if (scored.length > 1 && scored[0].hits < scored[1].hits * CONTENT_LEAD) return null;
  return scored[0].definition;
}

function inferStoreService(pathText, text = '') {
  const fromPath = findStoreServiceByPath(pathText);
  if (fromPath) return fromPath;

  const fromText = findStoreServiceByContent(text);
  if (fromText) return fromText;

  const jwtMatches = String(text || '').match(JWT_SCAN_REGEX) || [];
  for (const token of jwtMatches.slice(0, 3)) {
    const issuer = String(decodeJwtPayload(token)?.iss || '').toLowerCase();
    if (!issuer) continue;
    // The issuer is a claim inside a signed token, not free text, so it is read
    // against the full pattern list rather than the content-safe subset.
    const fromIssuer = findServiceDefinition(issuer, STORE_SERVICE_DEFINITIONS);
    if (fromIssuer) return fromIssuer;
  }

  return { name: 'Unknown', category: 'Store' };
}

export {
  inferServiceFromPath,
  inferStoreService,
  serviceFromBrowser,
  serviceFromTokenType,
};
