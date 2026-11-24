import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseCase, findNode, hintsOf } from './helpers/case.js';
import { combolist, passwordBlocks, DEFAULT_CREDENTIALS } from './helpers/fixtures.js';

async function hintsFor(files) {
  const { tree } = await analyseCase(files);
  return (path) => hintsOf(findNode(tree, path));
}

test('filename and folder rules classify the common stealer files', async () => {
  const hints = await hintsFor({
    'Passwords.txt': passwordBlocks(DEFAULT_CREDENTIALS),
    'Cookies/Chrome_Default.txt': '.example.com\tTRUE\t/\tTRUE\t1893456000\tprefs\tv',
    'Autofills/Chrome_Default.txt': 'Name: email\nValue: a@example.com\n',
    'History/Chrome_Default.txt': 'https://www.example.com/\n',
    'UserInformation.txt': 'IP: 192.0.2.1\nCountry: AU\n',
    'CC/Chrome_Default.txt': 'Card: 4111 1111 1111 1111\n',
    'Wallets/Exodus/seed.txt': 'placeholder\n',
    'Screenshot.jpg': new Uint8Array([0xff, 0xd8, 0xff]),
    'DomainDetects.txt': 'Banks\n',
  });
  assert.ok(hints('Passwords.txt').includes('_passwordFileHint'));
  assert.ok(hints('Cookies/Chrome_Default.txt').includes('_cookieFileHint'));
  assert.ok(hints('Autofills/Chrome_Default.txt').includes('_autofillHint'));
  assert.ok(hints('History/Chrome_Default.txt').includes('_historyHint'));
  assert.ok(hints('UserInformation.txt').includes('_sysInfoHint'));
  assert.ok(hints('CC/Chrome_Default.txt').includes('_creditCardHint'));
  assert.ok(hints('Wallets/Exodus/seed.txt').includes('_cryptoWalletHint'));
  assert.ok(hints('Screenshot.jpg').includes('_screenshotHint'));
  assert.ok(hints('DomainDetects.txt').includes('_domainDetectHint'));
});

test('an aggregate password dump is promoted to a password file', async () => {
  const hints = await hintsFor({ 'All Passwords.txt': passwordBlocks(DEFAULT_CREDENTIALS) });
  assert.deepEqual(hints('All Passwords.txt'), ['_passwordFileHint']);
});

test('names that only resemble stealer output stay unclassified', async () => {
  const hints = await hintsFor({
    'display-ad-banner.png': new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
    'gift card.txt': 'Happy birthday!\n',
    'wordlist.txt': 'password\nletmein\n',
  });
  assert.ok(!hints('display-ad-banner.png').includes('_screenshotHint'));
  assert.ok(!hints('gift card.txt').includes('_creditCardHint'));
  assert.ok(!hints('wordlist.txt').includes('_passwordFileHint'));
});

test('a weak sysinfo name under a grabbed-files root is the victim\'s file, not the profile', async () => {
  const hints = await hintsFor({
    'UserInformation.txt': 'IP: 192.0.2.1\n',
    'Files/Desktop/info.txt': 'Call the plumber on Tuesday\n',
  });
  const grabbed = hints('Files/Desktop/info.txt');
  assert.ok(grabbed.includes('_grabbedFileHint'));
  assert.ok(!grabbed.includes('_sysInfoHint'));
});

test('a host:user:pass pool with no filename rule is recognised by its content', async () => {
  const hints = await hintsFor({
    'UserInformation.txt': 'IP: 192.0.2.1\n',
    '14,4K ULP PRIV.txt': combolist(),
  });
  assert.ok(hints('14,4K ULP PRIV.txt').includes('_passwordFileHint'));
});
