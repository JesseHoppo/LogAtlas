import { JWT_SCAN_REGEX } from './definitions/patterns.js';

const GENERAL_SERVICE_DEFINITIONS = Object.freeze([
  { label: 'Google', patterns: [/googleaccounts/i, /googletokens?/i, /restore_[^/]+\.txt$/i] },
  { label: 'Discord', patterns: [/discord/i] },
  { label: 'Steam', patterns: [/steam/i] },
  { label: 'Facebook', patterns: [/fbfastcheck/i, /facebook/i, /token_eaab/i] },
  { label: 'Telegram', patterns: [/telegram/i] },
  { label: 'AnyDesk', patterns: [/anydesk/i] },
  { label: 'Outlook', patterns: [/outlook/i] },
]);

const STORE_SERVICE_DEFINITIONS = Object.freeze([
  { name: 'Bitwarden', category: 'Vault', patterns: [/bitwarden/i], extensionIds: ['nngceckbapebfimnlniiiahkandclblb'] },
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

function normalizeServiceText(value) {
  return String(value || '').replace(/\\/g, '/').toLowerCase();
}

function findServiceDefinition(value, definitions) {
  const normalized = normalizeServiceText(value);
  if (!normalized) return null;

  for (const definition of definitions) {
    if (definition.patterns.some((pattern) => pattern.test(normalized))) {
      return definition;
    }
  }

  return null;
}

function findStoreServiceByPath(pathText) {
  const normalizedPath = normalizeServiceText(pathText);
  if (!normalizedPath) return null;

  for (const definition of STORE_SERVICE_DEFINITIONS) {
    if (definition.patterns.some((pattern) => pattern.test(normalizedPath))) {
      return definition;
    }
    if (definition.extensionIds.some((id) => normalizedPath.includes(id))) {
      return definition;
    }
  }

  return null;
}

function decodeJwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;

  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - normalized.length % 4) % 4);
    const decoded = atob(normalized + padding);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

function inferServiceFromPath(pathText) {
  return findServiceDefinition(pathText, GENERAL_SERVICE_DEFINITIONS)?.label || '';
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
};
