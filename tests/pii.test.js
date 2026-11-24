import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { detectNationalIds, detectStructuredPii, countSeedPhrases, isLuhnValid } from '../js/analysis/structuredPii.js';
import { isValidBitcoinAddress } from '../js/core/cryptoAddress.js';

const SEED = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

const typesIn = (text) => detectNationalIds(text).map((id) => id.type);

test('national identifiers are only reported when their checksum holds', () => {
  assert.deepEqual(typesIn('CPF 111.444.777-35'), ['CPF']);
  assert.deepEqual(typesIn('CPF 111.444.777-36'), []);
  assert.deepEqual(typesIn('Aadhaar 2345 6789 0124'), ['Aadhaar']);
  assert.deepEqual(typesIn('Aadhaar 2345 6789 0125'), []);
  assert.deepEqual(typesIn('CUIT 20-12345678-6'), ['CUIT/DNI']);
  assert.deepEqual(typesIn('CUIT 20-12345678-5'), []);
  assert.deepEqual(typesIn('SSN 123-45-6789'), ['SSN']);
  assert.deepEqual(typesIn('SSN 666-45-6789 and 000-12-3456'), []);
});

test('card numbers need a valid Luhn digit', () => {
  assert.equal(isLuhnValid('4111111111111111'), true);
  assert.equal(isLuhnValid('4111111111111112'), false);
  assert.equal(detectStructuredPii('card 4111 1111 1111 1111').panCount, 1);
  assert.equal(detectStructuredPii('card 4111 1111 1111 1112').panCount, 0);
});

test('IBANs need a valid mod-97 check', () => {
  assert.equal(detectStructuredPii('pay to DE89 3704 0044 0532 0130 00').ibanCount, 1);
  assert.equal(detectStructuredPii('pay to DE88 3704 0044 0532 0130 00').ibanCount, 0);
});

test('a seed phrase is a run of distinct BIP39 words, however it is written down', () => {
  assert.equal(countSeedPhrases(SEED), 1);
  assert.equal(countSeedPhrases(SEED.split(' ').map((w, i) => `${i + 1}. ${w}`).join('\n')), 1);
  assert.equal(countSeedPhrases(`${SEED}\n${SEED.split(' ').reverse().join(', ')}`), 2);
  assert.equal(countSeedPhrases('true, true, true, true, true, true, true, true, true, true, true, true'), 0);
  assert.equal(countSeedPhrases('The quick brown fox jumps over the lazy dog every single morning again'), 0);
});

test('Bitcoin addresses are accepted only when their checksum agrees', () => {
  assert.equal(isValidBitcoinAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'), true);
  assert.equal(isValidBitcoinAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3'), false);
  assert.equal(isValidBitcoinAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), true);
  assert.equal(isValidBitcoinAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5'), false);
  assert.equal(isValidBitcoinAddress('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'), true);
});
