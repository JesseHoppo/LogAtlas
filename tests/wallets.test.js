import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseWalletArtifact } from '../js/analysis/walletArtifacts.js';
import { seedBannerText } from '../js/app/dashboard.js';
import { analyseCase } from './helpers/case.js';
import { redlineLog } from './helpers/fixtures.js';

const encode = (text) => new TextEncoder().encode(text);
const METAMASK_DIR = 'Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn';
const SEED = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

test('a wallet store is named from its extension folder', () => {
  const entry = parseWalletArtifact(encode('{"vault":"{\\"data\\":\\"x\\"}"}'), '000003.log', `${METAMASK_DIR}/000003.log`);
  assert.equal(entry.service, 'MetaMask');
  assert.equal(entry.storeType, 'LevelDB');
});

test('only checksum-valid Bitcoin addresses are counted out of a store', () => {
  const entry = parseWalletArtifact(
    encode('recv 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 and noise 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3'),
    'addresses.txt',
    'Wallets/Electrum/addresses.txt',
  );
  assert.equal(entry.addressCount, 1);
});

test('a written-down seed counts as a seed phrase; a UI keyword only as a hint', () => {
  const seedFile = parseWalletArtifact(encode(SEED), 'seed.txt', 'Wallets/Exodus/seed.txt');
  assert.equal(seedFile.seedPhraseCount, 1);

  const keywordOnly = parseWalletArtifact(encode('Reveal Secret Recovery Phrase'), '000003.log', `${METAMASK_DIR}/000003.log`);
  assert.equal(keywordOnly.seedPhraseCount, 0);
  assert.ok(keywordOnly.seedHints > 0);
});

test('a password manager never raises seed hints from its own UI strings', () => {
  const entry = parseWalletArtifact(encode('Store your recovery phrase safely'), 'data.json', 'Wallets/Bitwarden/data.json');
  assert.equal(entry.seedHints, 0);
});

test('the wallet summary covers every store in the case', async () => {
  const files = redlineLog();
  files['Wallets/Exodus/seed.txt'] = SEED;
  files[`${METAMASK_DIR}/000003.log`] = 'Reveal Secret Recovery Phrase';
  const { events } = await analyseCase(files);
  assert.equal(events.wallets.fileCount, 2);
  assert.deepEqual(events.wallets.services.map((s) => s.value).sort(), ['Exodus', 'MetaMask']);
});

test('the Overview seed banner stays down for a store holding only UI keywords', async () => {
  const files = redlineLog();
  files[`${METAMASK_DIR}/000003.log`] = '{"vault":"{\\"data\\":\\"x\\"}","i18n":"Reveal Secret Recovery Phrase"}';
  files['Wallets/MetaMask/state.json'] = '{"OnboardingController":{"seedPhraseBackedUp":true}}';
  const { events } = await analyseCase(files);
  assert.equal(events.wallets.withSeedPhrase, 0);
  assert.equal(seedBannerText(events.wallets, events.notes), '');
});

test('the Overview seed banner goes up for a seed written down in a wallet folder', async () => {
  const files = redlineLog();
  files['Wallets/Exodus/seed.txt'] = SEED;
  const { events } = await analyseCase(files);
  assert.equal(events.wallets.withSeedPhrase, 1);
  assert.match(seedBannerText(events.wallets, events.notes), /^1 wallet store with seed/);
});

test('a seed kept in a note raises the same banner', async () => {
  const files = redlineLog();
  files['Notes/backup.txt'] = `my wallet words\n${SEED}\n`;
  const { events } = await analyseCase(files);
  assert.equal(events.notes.seedPhraseNotes, 1);
  assert.match(seedBannerText(events.wallets, events.notes), /^1 note with seed/);
});
