// Wallet-address recognition that a checksum has to agree with.
//
// Raw stores are binary, so the printable-string pass hands the matcher long
// runs of base58-shaped noise. Pattern alone accepted them: every "BTC address"
// reported from one corpus Bitwarden LevelDB failed its checksum, i.e. the tool
// was putting invented addresses in front of an analyst.

// Shapes only. What the pattern nominates still has to survive the checksum,
// and an Ethereum address has none to survive.
export const BTC_ADDRESS_REGEX = /\b(?:bc1[a-z0-9]{25,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
export const ETH_ADDRESS_REGEX = /\b0x[a-fA-F0-9]{40}\b/g;

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map([...BASE58_ALPHABET].map((ch, i) => [ch, i]));

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// Small synchronous SHA-256: the checksum has to be decided inside a plain
// string scan, and crypto.subtle is async.
function sha256(bytes) {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const bitLength = bytes.length * 8;
  const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  new DataView(padded.buffer).setUint32(padded.length - 4, bitLength >>> 0);
  new DataView(padded.buffer).setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000));

  const w = new Uint32Array(64);
  const view = new DataView(padded.buffer);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15];
      const b = w[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i]);
  return out;
}

function base58Decode(value) {
  const bytes = [0];
  for (const ch of value) {
    const digit = BASE58_INDEX.get(ch);
    if (digit === undefined) return null;
    let carry = digit;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < value.length && value[i] === '1'; i++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

export function isValidBase58Check(value) {
  const decoded = base58Decode(value);
  if (!decoded || decoded.length !== 25) return false;
  const payload = decoded.subarray(0, 21);
  const expected = sha256(sha256(payload));
  for (let i = 0; i < 4; i++) {
    if (decoded[21 + i] !== expected[i]) return false;
  }
  return true;
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values) {
  const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) checksum ^= generator[i];
    }
  }
  return checksum >>> 0;
}

// bc1 addresses are bech32 (v0) or bech32m (v1+); the constant is the only
// difference and the witness version decides which.
function isValidBech32(value) {
  const lower = value.toLowerCase();
  const split = lower.lastIndexOf('1');
  if (split < 1 || split + 7 > lower.length) return false;
  const hrp = lower.slice(0, split);
  const data = [];
  for (const ch of lower.slice(split + 1)) {
    const index = BECH32_CHARSET.indexOf(ch);
    if (index < 0) return false;
    data.push(index);
  }
  const expanded = [
    ...[...hrp].map(ch => ch.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map(ch => ch.charCodeAt(0) & 31),
    ...data,
  ];
  const constant = data[0] === 0 ? 1 : 0x2bc830a3;
  return bech32Polymod(expanded) === constant;
}

export function isValidBitcoinAddress(value) {
  const address = String(value || '').trim();
  if (/^(bc1|tb1)/i.test(address)) return isValidBech32(address);
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address)) return isValidBase58Check(address);
  return false;
}
