// Loads the vendored domain reference lists (data/site-domains, data/email-domains)
// and exposes a fast eTLD+1 classifier. Lists are refreshed by scripts/refresh-domain-data.sh;
// entries the upstream classes get wrong are subtracted at index time from
// data/site-domains/overrides.txt so the correction survives that refresh.
//
// All lookups normalise to a registrable domain so subdomain entries in the source
// files (e.g. mail.google.com) collapse into the base used by credential URLs.

import { extractBaseDomain } from './shared.js';
import { emit } from './state.js';

const FILES = {
  popular:         'data/site-domains/popular.txt',
  bank:            'data/site-domains/bank.txt',
  finance:         'data/site-domains/finance.txt',
  retailer:        'data/site-domains/retailer.txt',
  airline:         'data/site-domains/airline.txt',
  university:      'data/site-domains/university.txt',
  socialMedia:     'data/site-domains/social-media.txt',
  searchEngine:    'data/site-domains/search-engine.txt',
  aiAssistant:     'data/site-domains/ai-assistant.txt',
  ddns:            'data/site-domains/ddns.txt',
  rmm:             'data/site-domains/rmm.txt',
  gambling:        'data/site-domains/gambling.txt',
};

// Who runs the mailbox, which is a different question from what the site is:
// an address at a consumer webmail is the victim's own, an address at a
// throwaway provider belongs to a burner account or to whoever built the dump.
// The refresh script subtracts the disposable list from the free one, so the
// two never both match.
const EMAIL_FILES = {
  freeProvider: 'data/email-domains/free-providers.txt',
  disposable:   'data/email-domains/disposable.txt',
};

const OVERRIDES_FILE = 'data/site-domains/overrides.txt';

const LIST_BY_FILENAME = new Map(
  Object.entries({ ...FILES, ...EMAIL_FILES })
    .map(([name, url]) => [url.replace(/^.*\//, '').replace(/\.txt$/, ''), name])
);

const CATEGORY_LABELS = {
  bank:            'Bank',
  finance:         'Finance',
  airline:         'Airline',
  socialMedia:     'Social',
  searchEngine:    'Search',
  aiAssistant:     'AI',
  gov:             'Government',
  military:        'Military',
  edu:             'Education',
  ddns:            'Dynamic DNS',
  rmm:             'Remote Access',
  gambling:        'Gambling',
  localDevice:     'Local Device',
  known:           'Known Site',
  sensitive:       'Sensitive',
};

// Tranco is a traffic ranking and Wikidata's online-shop class is broad enough
// to hold Microsoft, Netflix, OpenAI and half the banks in bank.txt, so neither
// says anything about an account beyond "this host is a real, indexed site".
// They collapse into one key whose value is the inverse reading: a credential
// for a host in neither list is a host nobody publishes.
const KNOWN_SITE_LISTS = ['popular', 'retailer'];

// A domain can sit in several lists honestly — Wikidata calls chatgpt.com a
// search engine and Matomo an AI assistant — so the order below decides which
// one an analyst reads. It ranks by what the label changes about the work:
// a regulated victim first, then money, then the credentials that lead back
// into the network, then everything that is only an identity.
const SITE_CATEGORY_PRIORITY = [
  'gov',
  'military',
  'bank',
  'finance',
  'localDevice',     // console on the victim's own network
  'rmm',
  'ddns',
  'gambling',
  'edu',
  'airline',
  'aiAssistant',
  'searchEngine',
  'socialMedia',
  'known',           // no category, just an indexed site
];

// `known` says the host is not obscure and nothing else, so it earns a filter
// but not a per-row badge.
const GENERIC_CATEGORIES = new Set(['known']);

const SENSITIVE_CATEGORIES = new Set(['gov', 'military', 'bank', 'finance']);

// Most governments sit under <gov-ish label>.<ccTLD> and enumerating every one
// is hopeless. Two-letter TLDs are country codes by IANA policy, so anchoring on
// label length keeps the rule off gTLD lookalikes such as go.com and go.dev.
const GOV_PATTERN = /(?:^|\.)(?:gov|gob|gouv|govt|go)\.[a-z]{2}$/;
const MILITARY_PATTERN = /(?:^|\.)mil\.[a-z]{2}$/;
const EDU_PATTERN = /(?:^|\.)(?:edu|ac|sch)\.[a-z]{2}$/;

// The irregulars the patterns cannot express.
const GOV_SUFFIXES = ['.gov', '.gc.ca', '.gouv.qc.ca', '.admin.ch', '.bund.de'];
const MILITARY_SUFFIXES = ['.mil', '.forces.gc.ca'];
const EDU_SUFFIXES = ['.edu'];

const SUFFIX_RULES = [
  { key: 'gov', pattern: GOV_PATTERN, suffixes: GOV_SUFFIXES },
  { key: 'military', pattern: MILITARY_PATTERN, suffixes: MILITARY_SUFFIXES },
  { key: 'edu', pattern: EDU_PATTERN, suffixes: EDU_SUFFIXES },
];

// A saved password for 192.168.1.1 is a router, NAS or printer console on the
// victim's own network — a foothold rather than an account on a public service,
// and no reference list can enumerate them.
const IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const PRIVATE_IPV4_PATTERN = /^(?:10|127)\.|^192\.168\.|^169\.254\.|^172\.(?:1[6-9]|2\d|3[01])\./;
const LOCAL_SUFFIXES = ['.local', '.lan', '.home', '.internal', '.localdomain'];

function isLocalDevice(host) {
  if (host === 'localhost') return true;
  if (IPV4_PATTERN.test(host)) return PRIVATE_IPV4_PATTERN.test(host);
  return LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

function matchSuffixCategory(host) {
  const out = [];
  for (const { key, pattern, suffixes } of SUFFIX_RULES) {
    if (pattern.test(host)) { out.push(key); continue; }
    if (suffixes.some((suffix) => host === suffix.slice(1) || host.endsWith(suffix))) out.push(key);
  }
  return out;
}

// extractBaseDomain() covers the common second-level registries; these are the
// public ones it misses, where the label in front of the ccTLD is a registry and
// not an organisation. Without them every host under gob.ve or go.jp collapses
// into the bare suffix and distinct agencies count as one domain.
const REGISTRY_SLD_PATTERN = /\.(?:gob|govt|go|mil|sch)\.[a-z]{2}$/;
// Canada registers federal under gc.ca and everything else under a provincial
// suffix, so gouv.qc.ca is one organisation and qc.ca is a registry.
const REGISTRY_SUFFIXES = new Set([
  'gc.ca', 'ab.ca', 'bc.ca', 'mb.ca', 'nb.ca', 'nl.ca', 'ns.ca', 'nt.ca',
  'nu.ca', 'on.ca', 'pe.ca', 'qc.ca', 'sk.ca', 'yt.ca',
]);

function registrableDomain(host) {
  const parts = host.split('.');
  if (parts.length > 2 && (REGISTRY_SUFFIXES.has(parts.slice(-2).join('.')) || REGISTRY_SLD_PATTERN.test(host))) {
    return parts.slice(-3).join('.');
  }
  return extractBaseDomain(host) || host;
}

const sets = {};
let loadingPromise = null;
let loaded = false;

// Index each entry verbatim (lowercased, www-stripped). The lookup walks up
// labels, so a list entry like `gemini.google.com` matches `gemini.google.com`
// but NOT plain `google.com`, which is the right semantics for sub-product
// taxonomies (Matomo lists Gemini as AI, but google.com itself shouldn't be).
function indexLines(text) {
  const set = new Set();
  if (!text) return set;
  for (const raw of text.split('\n')) {
    const line = raw.trim().toLowerCase().replace(/^www\./, '');
    if (!line || line.startsWith('#')) continue;
    set.add(line);
  }
  return set;
}

// Walk parent labels: `mail.foo.example.com` → `mail.foo.example.com`,
// `foo.example.com`, `example.com`. Stops at the eTLD+1 boundary so we don't
// emit just `com`.
function* hostAncestors(host) {
  if (!host) return;
  const cleanHost = host.toLowerCase().replace(/^www\./, '');
  yield cleanHost;
  const base = registrableDomain(cleanHost);
  let cur = cleanHost;
  while (true) {
    if (cur === base) break;
    const dot = cur.indexOf('.');
    if (dot < 0) break;
    cur = cur.slice(dot + 1);
    if (cur && cur !== cleanHost) yield cur;
  }
}

function setMatchesHost(set, host) {
  if (!set || !host) return false;
  for (const ancestor of hostAncestors(host)) {
    if (set.has(ancestor)) return true;
  }
  return false;
}

async function fetchText(url) {
  try {
    const res = await fetch(url, { cache: 'force-cache' });
    return res.ok ? await res.text() : '';
  } catch {
    return '';
  }
}

// `<list> <domain>` per line, where <list> is a file basename or `*`.
function parseOverrides(text) {
  const out = new Map();
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim().toLowerCase();
    if (!line) continue;
    const [list, domain] = line.split(/\s+/);
    if (!domain) continue;
    if (!out.has(list)) out.set(list, new Set());
    out.get(list).add(domain.replace(/^www\./, ''));
  }
  return out;
}

function applyOverrides(overrides) {
  const everyList = overrides.get('*');
  for (const [filename, name] of LIST_BY_FILENAME) {
    const set = sets[name];
    if (!set) continue;
    for (const domain of everyList || []) set.delete(domain);
    for (const domain of overrides.get(filename) || []) set.delete(domain);
  }
}

function loadDomainCategories() {
  if (loadingPromise) return loadingPromise;
  const lists = Promise.all(
    Object.entries({ ...FILES, ...EMAIL_FILES }).map(([name, url]) =>
      fetchText(url).then((text) => { sets[name] = indexLines(text); })
    )
  );
  loadingPromise = Promise.all([lists, fetchText(OVERRIDES_FILE)]).then(([, overrideText]) => {
    applyOverrides(parseOverrides(overrideText));
    loaded = true;
    emit('domains:categoriesLoaded', { sizes: getSizes() });
    return sets;
  });
  return loadingPromise;
}

// Everything except the suffix rules needs the lists, so a view rendering before
// they land shows an all-uncategorised breakdown that means nothing.
function areCategoriesLoaded() {
  return loaded;
}

function getSizes() {
  const out = {};
  for (const k of [...Object.keys(FILES), ...Object.keys(EMAIL_FILES)]) out[k] = sets[k]?.size || 0;
  return out;
}

// An address or a bare domain; anything before the last `@` is the local part
// and says nothing about who runs the mailbox.
function emailHost(value) {
  const text = String(value || '').trim().toLowerCase();
  const at = text.lastIndexOf('@');
  return normaliseHost(at >= 0 ? text.slice(at + 1) : text);
}

function isFreeEmailProvider(value) {
  return setMatchesHost(sets.freeProvider, emailHost(value));
}

function isDisposableEmailDomain(value) {
  return setMatchesHost(sets.disposable, emailHost(value));
}

function normaliseHost(host) {
  return String(host || '').toLowerCase().replace(/^www\./, '').replace(/[\/?#].*/, '');
}

function matchesCategory(key, host) {
  if (key === 'known') return KNOWN_SITE_LISTS.some((name) => setMatchesHost(sets[name], host));
  return setMatchesHost(sets[key], host);
}

function classifySiteDomain(host) {
  const cleanHost = normaliseHost(host);
  if (!cleanHost) return { base: '', categories: [], primaryKey: null, primaryLabel: '' };
  const base = registrableDomain(cleanHost);
  const suffixMatches = new Set(matchSuffixCategory(cleanHost));
  if (isLocalDevice(cleanHost)) suffixMatches.add('localDevice');
  if (setMatchesHost(sets.university, cleanHost)) suffixMatches.add('edu');
  const categories = [];
  for (const key of SITE_CATEGORY_PRIORITY) {
    if (suffixMatches.has(key) || matchesCategory(key, cleanHost)) categories.push(key);
  }
  const primaryKey = categories[0] || null;
  // Escalate on the label we actually show, not on any match: a bank that is
  // also a government agency reads as Government and is escalated once.
  if (SENSITIVE_CATEGORIES.has(primaryKey)) categories.push('sensitive');
  return {
    base,
    categories,
    primaryKey,
    primaryLabel: primaryKey ? CATEGORY_LABELS[primaryKey] : '',
  };
}

function getCategoryLabel(key) {
  return CATEGORY_LABELS[key] || '';
}

// What a badge is standing on, for the analyst who wants to know why a domain
// carries it. Keys with no single source (`sensitive` is an escalation of
// whichever category won) are left to the caller's generic wording.
const SUFFIX_RULE_SOURCES = {
  gov: 'Matched the government suffix rule: .gov, gov/gob/gouv/govt/go under a country code, or a listed national suffix',
  military: 'Matched the military suffix rule: .mil, mil under a country code, or a listed national suffix',
  edu: 'Matched the education suffix rule (.edu, or edu/ac/sch under a country code) or data/site-domains/university.txt',
  localDevice: 'Matched the local-device rule: a private or loopback IP address, or a .local/.lan/.internal name',
};

function getCategorySource(key) {
  if (key === 'known') return `Matched ${KNOWN_SITE_LISTS.map((name) => FILES[name]).join(' or ')}`;
  if (SUFFIX_RULE_SOURCES[key]) return SUFFIX_RULE_SOURCES[key];
  return FILES[key] ? `Matched ${FILES[key]}` : '';
}

function isGenericCategory(key) {
  return GENERIC_CATEGORIES.has(key);
}

export {
  loadDomainCategories,
  areCategoriesLoaded,
  isFreeEmailProvider,
  isDisposableEmailDomain,
  classifySiteDomain,
  getCategoryLabel,
  getCategorySource,
  isGenericCategory,
  SITE_CATEGORY_PRIORITY,
};
