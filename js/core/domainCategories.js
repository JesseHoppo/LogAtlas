// Loads the vendored domain reference lists (data/site-domains, data/email-domains)
// and exposes a fast eTLD+1 classifier. Lists are refreshed by scripts/refresh-domain-data.sh.
//
// All lookups normalise to extractBaseDomain() so subdomain entries in the source
// files (e.g. mail.google.com) collapse into the base used by credential URLs.

import { extractBaseDomain } from './shared.js';
import { emit } from './state.js';

const FILES = {
  popular:         'data/site-domains/popular.txt',
  bank:            'data/site-domains/bank.txt',
  retailer:        'data/site-domains/retailer.txt',
  news:            'data/site-domains/news.txt',
  airline:         'data/site-domains/airline.txt',
  university:      'data/site-domains/university.txt',
  socialMedia:     'data/site-domains/social-media.txt',
  searchEngine:    'data/site-domains/search-engine.txt',
  aiAssistant:     'data/site-domains/ai-assistant.txt',
  ddns:            'data/site-domains/ddns.txt',
  rmm:             'data/site-domains/rmm.txt',
  gambling:        'data/site-domains/gambling.txt',
};

const CATEGORY_LABELS = {
  bank:            'Bank',
  retailer:        'Retailer',
  news:            'News',
  airline:         'Airline',
  university:      'University',
  socialMedia:     'Social',
  searchEngine:    'Search',
  aiAssistant:     'AI',
  popular:         'Popular',
  gov:             'Government',
  military:        'Military',
  edu:             'Education',
  ddns:            'Dynamic DNS',
  rmm:             'Remote Access',
  gambling:        'Gambling',
  sensitive:       'Sensitive',
};

// Site categories ranked by source precision (cleanest list first). When a
// domain matches several lists, the first match here is the displayed label.
// `retailer` is last among specific categories because Wikidata's online-shop
// class is very broad and catches popular sites like google.com that are
// better labelled by their primary function.
const SITE_CATEGORY_PRIORITY = [
  'gov',             // suffix rule, highest-value
  'military',        // suffix rule, highest-value
  'edu',             // suffix rule + university list
  'rmm',             // curated remote-access tooling
  'ddns',            // curated dynamic-DNS providers
  'aiAssistant',     // Matomo curated, 20 entries, very precise
  'searchEngine',    // Matomo curated, ~600 entries, very precise
  'socialMedia',     // Matomo + Wikidata, ~600 entries
  'bank',            // Wikidata Q22687 direct
  'gambling',        // curated operators
  'airline',         // Wikidata Q46970 direct
  'news',            // Wikidata Q1110794 direct
  'university',      // Wikidata Q3918 direct
  'retailer',        // Wikidata Q4830453, broad, used as a last-resort label
  'popular',         // Tranco, generic "consumer site" fallback
];

const SENSITIVE_CATEGORIES = new Set(['gov', 'military', 'bank']);

const GOV_SUFFIXES = [
  '.gov', '.gov.uk', '.gov.au', '.gov.in', '.gov.za', '.gov.sg', '.gov.my',
  '.gov.br', '.gov.co', '.gov.tr', '.gov.ph', '.gov.pk', '.gob.mx', '.gob.es',
  '.gob.ar', '.gob.cl', '.gob.pe', '.gob.ec', '.gouv.fr', '.go.id', '.go.th',
  '.go.jp', '.go.kr', '.govt.nz', '.gc.ca', '.admin.ch', '.bund.de',
];
const MILITARY_SUFFIXES = ['.mil', '.mil.uk', '.mil.au', '.forces.gc.ca'];
const EDU_SUFFIXES = [
  '.edu', '.edu.au', '.edu.cn', '.edu.in', '.edu.sg', '.edu.my', '.edu.br',
  '.edu.mx', '.edu.tr', '.edu.pk', '.ac.uk', '.ac.nz', '.ac.jp', '.ac.kr',
  '.ac.in', '.ac.za', '.ac.id', '.ac.th', '.sch.uk', '.sch.id',
];

const SUFFIX_RULES = [
  { key: 'gov', suffixes: GOV_SUFFIXES },
  { key: 'military', suffixes: MILITARY_SUFFIXES },
  { key: 'edu', suffixes: EDU_SUFFIXES },
];

function matchSuffixCategory(host) {
  const out = [];
  for (const { key, suffixes } of SUFFIX_RULES) {
    if (suffixes.some((suffix) => host === suffix.slice(1) || host.endsWith(suffix))) out.push(key);
  }
  return out;
}

const sets = {};
let loadingPromise = null;

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
  const base = extractBaseDomain(cleanHost) || cleanHost;
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

async function fetchSet(url) {
  try {
    const res = await fetch(url, { cache: 'force-cache' });
    if (!res.ok) return new Set();
    return indexLines(await res.text());
  } catch {
    return new Set();
  }
}

function loadDomainCategories() {
  if (loadingPromise) return loadingPromise;
  loadingPromise = Promise.all(
    Object.entries(FILES).map(([name, url]) =>
      fetchSet(url).then((set) => { sets[name] = set; })
    )
  ).then(() => {
    emit('domains:categoriesLoaded', { sizes: getSizes() });
    return sets;
  });
  return loadingPromise;
}

function getSizes() {
  const out = {};
  for (const k of Object.keys(FILES)) out[k] = sets[k]?.size || 0;
  return out;
}

function normaliseHost(host) {
  return String(host || '').toLowerCase().replace(/^www\./, '').replace(/[\/?#].*/, '');
}

function classifySiteDomain(host) {
  const cleanHost = normaliseHost(host);
  if (!cleanHost) return { base: '', categories: [], primaryKey: null, primaryLabel: '' };
  const base = extractBaseDomain(cleanHost) || cleanHost;
  const suffixMatches = new Set(matchSuffixCategory(cleanHost));
  if (setMatchesHost(sets.university, cleanHost)) suffixMatches.add('edu');
  const categories = [];
  for (const key of SITE_CATEGORY_PRIORITY) {
    if (suffixMatches.has(key) || setMatchesHost(sets[key], cleanHost)) categories.push(key);
  }
  if (categories.some((key) => SENSITIVE_CATEGORIES.has(key))) categories.push('sensitive');
  const primaryKey = categories[0] || null;
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

export {
  loadDomainCategories,
  classifySiteDomain,
  getCategoryLabel,
  matchSuffixCategory,
  getSizes,
  SITE_CATEGORY_PRIORITY,
};
