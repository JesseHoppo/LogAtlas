import { JWT_SCAN_REGEX } from './definitions/patterns.js';

const GENERAL_SERVICE_DEFINITIONS = Object.freeze([
  { label: 'Google', patterns: [/googleaccounts/i, /googletokens?/i, /restore_[^/]+\.txt$/i] },
  { label: 'Discord', patterns: [/discord/i] },
  { label: 'Steam', patterns: [/steam/i] },
  { label: 'Facebook', patterns: [/fbfastcheck/i, /facebook/i, /token_eaab/i] },
  { label: 'Telegram', patterns: [/telegram/i] },
  { label: 'AnyDesk', patterns: [/anydesk/i] },
  { label: 'Outlook', patterns: [/outlook/i] },
  { label: 'FileZilla', patterns: [/filezilla/i, /ftp/i] },
  { label: 'Thunderbird', patterns: [/thunderbird/i] },
]);

const STORE_SERVICE_DEFINITIONS = Object.freeze([
  { name: 'Bitwarden', category: 'Password Manager', patterns: [/bitwarden/i], extensionIds: ['nngceckbapebfimnlniiiahkandclblb'] },
  { name: '1Password', category: 'Password Manager', patterns: [/1password/i, /onepassword/i, /opvault/i], extensionIds: ['aeblfdkhhhdcdjpifhhbdiojplfjncoa', 'dppgmdbiimibapkepcbdbmkaabgiofem'] },
  { name: 'LastPass', category: 'Password Manager', patterns: [/lastpass/i], extensionIds: ['hdokiejnpimakedhajhdlcegeplioahd'] },
  { name: 'Dashlane', category: 'Password Manager', patterns: [/dashlane/i], extensionIds: ['fdjamakpfbbddfjaooikfcpapjohcfmg'] },
  { name: 'NordPass', category: 'Password Manager', patterns: [/nordpass/i], extensionIds: ['fooolghllnmhmmndgjiamiiodkpenpbb'] },
  { name: 'RoboForm', category: 'Password Manager', patterns: [/roboform/i], extensionIds: ['pnlccmojcmeohlpggmfnbbiapkmbliob'] },
  { name: 'KeePassXC', category: 'Password Manager', patterns: [/keepassxc/i], extensionIds: [] },
  { name: 'KeePass', category: 'Password Manager', patterns: [/keepass/i, /\.kdbx$/i], extensionIds: [] },
  { name: 'MetaMask', category: 'Wallet', patterns: [/metamask/i], extensionIds: ['nkbihfbeogaeaoehlefnkodbefgpgknn'] },
  { name: 'Phantom', category: 'Wallet', patterns: [/phantom/i], extensionIds: ['bfnaelmomeimhlpmgjnjophhpkkoljpa'] },
  { name: 'Rabby', category: 'Wallet', patterns: [/rabby/i], extensionIds: ['acmacodkjbdgmoleebolmdjonilkdbch'] },
  { name: 'Ronin', category: 'Wallet', patterns: [/ronin/i], extensionIds: ['fnjhmkhhmkbjkkabndcnnogagogbneec'] },
  { name: 'Keplr', category: 'Wallet', patterns: [/keplr/i], extensionIds: ['dmkamcknogkgcdfhhbddcghachkejeap'] },
  { name: 'TronLink', category: 'Wallet', patterns: [/tronlink/i], extensionIds: ['ibnejdfjmmkpcnlpebklmnkoeoihofec'] },
  { name: 'Exodus', category: 'Wallet', patterns: [/exodus/i], extensionIds: [] },
  { name: 'Atomic Wallet', category: 'Wallet', patterns: [/atomic/i], extensionIds: [] },
  { name: 'Electrum', category: 'Wallet', patterns: [/electrum/i], extensionIds: [] },
  { name: 'Trust Wallet', category: 'Wallet', patterns: [/trust[\s_-]*wallet/i], extensionIds: [] },
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
  return findServiceDefinition(pathText, GENERAL_SERVICE_DEFINITIONS)?.label || '';
}

const TOKEN_TYPE_SERVICE = [
  { service: 'Google', patterns: [/google/i, /restore[\s_-]*token/i, /oauth/i] },
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

function inferStoreService(pathText, text = '') {
  const fromPath = findStoreServiceByPath(pathText);
  if (fromPath) return fromPath;

  const fromText = findServiceDefinition(text, STORE_SERVICE_DEFINITIONS);
  if (fromText) return fromText;

  const jwtMatches = String(text || '').match(JWT_SCAN_REGEX) || [];
  for (const token of jwtMatches.slice(0, 3)) {
    const issuer = String(decodeJwtPayload(token)?.iss || '').toLowerCase();
    if (!issuer) continue;
    const fromIssuer = findServiceDefinition(issuer, STORE_SERVICE_DEFINITIONS);
    if (fromIssuer) return fromIssuer;
  }

  return { name: 'Unknown', category: 'Store' };
}

export {
  inferServiceFromPath,
  inferStoreService,
  serviceFromTokenType,
};
