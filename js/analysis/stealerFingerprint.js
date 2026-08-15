// Stealer family fingerprinting based on directory layout, filenames, and sysinfo.

import { SIGNAL_WEIGHTS as W, SIGNATURES, CONFIDENCE_THRESHOLDS } from '../core/definitions/signatures.js';
import { FILE_TYPE_PATTERNS } from '../core/definitions/fileTypes.js';

// Signals shared across many families — credential/cookie/screenshot dumps and
// negation-based layout tests. They don't distinguish one family from another,
// so the structure-only fallback ignores them when judging distinctiveness.
const GENERIC_LABELS = /^(?:File: (?:All |unique_)?[Pp]asswords?\.txt(?: \(root\))?|File: [Cc]ookies?\.txt|File: cookie_list\.txt|File: [Ss]creenshot\.(?:png|jpg)|File: Screen\.png|File: domain detect\.txt|File: DomainDetects?\.txt|Structure: flat layout|Structure: top-level Autofills\/Cookies)/;

// A self-ID that is a single bare word ("xfiles", "skalka", "stealc") also
// reads as ordinary text, so a captured password, cookie domain or clipboard
// line must not be able to raise it — those patterns only count inside sysinfo.
// Multi-token brands and banner art stay case-global: resale brands stamp those
// on the password and cookie dumps themselves.
const BARE_WORD_SELF_ID = /^[a-z0-9]+$/i;

function selfIdIsSysinfoOnly(si) {
  if (si.scope) return si.scope === 'sysinfo';
  return BARE_WORD_SELF_ID.test(si.pattern.source.replace(/\\b/g, ''));
}

function scoreFamily(familyName, sig, ctx) {
  let score = 0;
  let maxScore = 0;
  const matched = [];
  const matchedCounts = {
    selfId: 0,
    sysinfoFile: 0,
    sysinfoKey: 0,
    sysinfoContent: 0,
    asciiBanner: 0,
    folder: 0,
    file: 0,
    structure: 0,
  };

  // 1. Self-identification (stealer names itself explicitly).
  // SELF_ID + ASCII banners are case-global signals — pull from
  // `combinedSysinfoText` (all candidates joined) so multi-file cases
  // don't lose evidence when the per-candidate `sysinfoText` doesn't
  // happen to include the banner.
  const globalText = [ctx.combinedSysinfoText || ctx.sysinfoText, ctx.creditsText, ctx.passwordHeaderText, ctx.clipboardText, ctx.browserHeaderText].filter(Boolean).join('\n');
  const sysinfoOnlyText = ctx.combinedSysinfoText || ctx.sysinfoText || '';
  if (sig.selfId && sig.selfId.length > 0) {
    maxScore += W.SELF_ID;
    for (const si of sig.selfId) {
      const target = selfIdIsSysinfoOnly(si) ? sysinfoOnlyText : globalText;
      if (target && si.pattern.test(target)) {
        score += W.SELF_ID;
        matched.push(si.label);
        matchedCounts.selfId++;
        break;
      }
    }
  }

  // 2. Sysinfo filename
  if (sig.sysinfoFile) {
    maxScore += sig.sysinfoFile.weight;
    if (ctx.sysinfoFilename && sig.sysinfoFile.pattern.test(ctx.sysinfoFilename)) {
      score += sig.sysinfoFile.weight;
      matched.push(`Sysinfo file: ${ctx.sysinfoFilename}`);
      matchedCounts.sysinfoFile++;
    }
  }

  // 3. Sysinfo keys
  for (const sk of sig.sysinfoKeys) {
    maxScore += W.SYSINFO_KEY;
    if (ctx.sysinfoKeys.some(k => sk.pattern.test(k))) {
      score += W.SYSINFO_KEY;
      matched.push(sk.label);
      matchedCounts.sysinfoKey++;
    }
  }

  // 4. Sysinfo content patterns
  for (const sc of sig.sysinfoContent) {
    maxScore += W.SYSINFO_CONTENT;
    if (ctx.sysinfoText && sc.pattern.test(ctx.sysinfoText)) {
      score += W.SYSINFO_CONTENT;
      matched.push(sc.label);
      matchedCounts.sysinfoContent++;
    }
  }

  // 5. ASCII banners (whitespace-normalised comparison)
  if (sig.asciiBanners && sig.asciiBanners.length > 0) {
    maxScore += W.ASCII_BANNER;
    if (globalText) {
      const normText = globalText.replace(/[ \t]+/g, ' ');
      for (const banner of sig.asciiBanners) {
        const normBanner = banner.replace(/[ \t]+/g, ' ');
        if (normText.includes(normBanner)) {
          score += W.ASCII_BANNER;
          matched.push(`ASCII banner: ${familyName} art detected`);
          matchedCounts.asciiBanner++;
          break;
        }
      }
    }
  }

  // 6. Folder matches
  for (const f of sig.folders) {
    maxScore += W.FOLDER;
    if (ctx.dirs.some(d => f.pattern.test(d))) {
      score += W.FOLDER;
      matched.push(f.label);
      matchedCounts.folder++;
    }
  }

  // 7. File pattern matches
  for (const fp of sig.files) {
    maxScore += W.FILE_PATTERN;
    if (ctx.files.some(f => fp.pattern.test(f))) {
      score += W.FILE_PATTERN;
      matched.push(fp.label);
      matchedCounts.file++;
    }
  }

  // 8. Structural tests
  for (const s of sig.structures) {
    maxScore += W.STRUCTURE;
    if (s.test(ctx.dirs, ctx.files)) {
      score += W.STRUCTURE;
      matched.push(s.label);
      matchedCounts.structure++;
    }
  }

  const signalState = { ctx, matchedCounts, matched };

  const selfEvidence = matchedCounts.selfId > 0 || matchedCounts.asciiBanner > 0;
  if (sig.exclusions && !selfEvidence && sig.exclusions.some(rule => rule.test(signalState))) {
    return { family: familyName, score: 0, maxScore, matched: [], matchedCounts, selfIdMatched: false, excluded: true };
  }

  if (sig.require && !sig.require(signalState)) {
    return { family: familyName, score: 0, maxScore, matched: [], matchedCounts, selfIdMatched: false, blocked: true };
  }

  const selfIdMatched = matchedCounts.selfId > 0;

  return { family: familyName, score, maxScore, matched, matchedCounts, selfIdMatched, osClass: sig.osClass || null, sysinfoFilename: ctx.sysinfoFilename || '' };
}

// Platform reading. Windows logs list macOS SDK packages and macOS logs list
// "Windows App", so a single substring decides nothing: take the OS line when
// the sysinfo has one, else weigh how many distinct platform-only cues each
// side shows.
const OS_KEY_PATTERN = /(?:^|[\s|>*-])(?:OS|OS[\s_-]*Name|OS[\s_-]*Version|Operat(?:ing|ion)[\s_-]*System|System[\s_-]*Version|ProductName|Windows)[ \t]*[:=][ \t]*([^\r\n|]{0,60})/gi;
const MACOS_NAME = /\b(?:mac\s?os|os\s?x|darwin)\b/i;
const WINDOWS_NAME = /\bwindows\b/i;
const WINDOWS_CUES = [
  /\bWindows[\s_](?:1[01]|[78]|XP|Vista|Server|NT)\b/i,
  /\bMicrosoft Windows\b/i,
  /\b[A-Za-z]:[\\/](?:Users|Windows|Program Files)/i,
  /\bAppData[\\/](?:Roaming|Local)/i,
  /\bHKEY_[A-Z_]+/,
  /\bWindows Defender/i,
];
const MACOS_CUES = [
  /\bmac\s?os\b/i,
  /\bos\s?x\b/i,
  /\bdarwin\b/i,
  /\b(?:MacBook|iMac|Mac\s?mini|Mac\s?Studio|Macintosh)\b/i,
  /\bApple\s+M[1-9]\b/i,
  /\/Users\/[^/\s]+\/Library\b/,
  /\bSystem Integrity Protection\b/i,
];

function classifyOs(text) {
  if (!text) return { osClass: null, keyed: false };

  for (const m of text.matchAll(OS_KEY_PATTERN)) {
    if (MACOS_NAME.test(m[1])) return { osClass: 'macos', keyed: true };
    if (WINDOWS_NAME.test(m[1])) return { osClass: 'windows', keyed: true };
  }

  // A lone hardware or SDK name decides nothing, in either direction.
  const win = WINDOWS_CUES.reduce((n, rx) => n + (rx.test(text) ? 1 : 0), 0);
  const mac = MACOS_CUES.reduce((n, rx) => n + (rx.test(text) ? 1 : 0), 0);
  if (win === mac || Math.max(win, mac) < 2) return { osClass: null, keyed: false };
  return { osClass: win > mac ? 'windows' : 'macos', keyed: false };
}

// Walk the file tree and collect dirs, files, sysinfo node, and credits files.
function collectContext(node, basePath, ctx) {
  if (!node || !node.children) return;

  for (const child of Object.values(node.children)) {
    const relPath = basePath ? basePath + '/' + child.name : child.name;

    if (child.type === 'directory') {
      ctx.dirs.push(relPath);
      collectContext(child, relPath, ctx);
    } else {
      ctx.files.push(relPath);

      if (child._sysInfoHint || FILE_TYPE_PATTERNS.sysinfo.filePatterns.some(rx => rx.test(child.name))) {
        ctx.sysinfoNodes.push(child);
      }

      if (child._creditsFileHint || FILE_TYPE_PATTERNS.credits.filePatterns.some(rx => rx.test(child.name))) {
        ctx.creditsNodes.push(child);
      }
      if (child._clipboardHint || FILE_TYPE_PATTERNS.clipboard.filePatterns.some(rx => rx.test(child.name))) {
        ctx.clipboardNodes.push(child);
      }
      if (child._passwordFileHint || /^(?:passwords?|unique[\s_-]*passwords?)\.txt$/i.test(child.name)) {
        if (!ctx.passwordNode) ctx.passwordNode = child;
      }
      if (child._cookieFileHint || child._autofillHint) {
        if (!ctx.browserHeaderNodes) ctx.browserHeaderNodes = [];
        if (ctx.browserHeaderNodes.length < 6) ctx.browserHeaderNodes.push(child);
      }
    }
  }
}

function scoreStructureOnly(familyName, sig, ctx) {
  let score = 0;
  let maxScore = 0;
  const matched = [];
  const matchedCounts = {
    selfId: 0,
    sysinfoFile: 0,
    sysinfoKey: 0,
    sysinfoContent: 0,
    asciiBanner: 0,
    folder: 0,
    file: 0,
    structure: 0,
  };

  for (const f of sig.folders) {
    maxScore += W.FOLDER;
    if (ctx.dirs.some(d => f.pattern.test(d))) {
      score += W.FOLDER;
      matched.push(f.label);
      matchedCounts.folder++;
    }
  }
  let distinctive = 0;
  for (const fp of sig.files) {
    maxScore += W.FILE_PATTERN;
    if (ctx.files.some(f => fp.pattern.test(f))) {
      score += W.FILE_PATTERN;
      matched.push(fp.label);
      matchedCounts.file++;
      if (!GENERIC_LABELS.test(fp.label)) distinctive++;
    }
  }
  for (const s of sig.structures) {
    maxScore += W.STRUCTURE;
    if (s.test(ctx.dirs, ctx.files)) {
      score += W.STRUCTURE;
      matched.push(s.label);
      matchedCounts.structure++;
      if (!GENERIC_LABELS.test(s.label)) distinctive++;
    }
  }

  // Same gates as the full pass. With no sysinfo evidence here, families that
  // require it (or that exclude on structure) stay out instead of matching on
  // layout alone.
  const signalState = { ctx, matchedCounts, matched };
  if (sig.exclusions && sig.exclusions.some(rule => rule.test(signalState))) return null;
  if (sig.require && !sig.require(signalState)) return null;

  return { family: familyName, score, maxScore, matched, distinctive, osClass: sig.osClass || null };
}

function fingerprintStealer(ctx) {
  const results = [];
  const sysinfoCandidates = ctx.sysinfoCandidates && ctx.sysinfoCandidates.length > 0
    ? ctx.sysinfoCandidates
    : [{ sysinfoFilename: null, sysinfoText: null, sysinfoKeys: [] }];

  for (const [family, sig] of Object.entries(SIGNATURES)) {
    let bestForFamily = null;

    for (const candidate of sysinfoCandidates) {
      const result = scoreFamily(family, sig, { ...ctx, ...candidate });
      if (result.maxScore <= 0) continue;
      result.pct = result.score / result.maxScore;

      if (
        !bestForFamily ||
        result.score > bestForFamily.score ||
        (result.score === bestForFamily.score && result.pct > bestForFamily.pct)
      ) {
        bestForFamily = result;
      }
    }

    if (bestForFamily && bestForFamily.score > 0) {
      results.push(bestForFamily);
    }
  }

  const strongCategoryCount = (c) => (c.sysinfoKey > 0 ? 1 : 0) + (c.sysinfoContent > 0 ? 1 : 0) +
    (c.folder > 0 ? 1 : 0) + (c.file > 0 ? 1 : 0) + (c.structure > 0 ? 1 : 0);

  // A matched self-ID/banner dominates; next a keyed sysinfo match with corroborating
  // categories (so a long optional signature list can't dilute it below a folder-only
  // score); then the proportional gate; raw evidence breaks ties within a band.
  const evidenceTier = (r) => {
    const c = r.matchedCounts;
    if (r.selfIdMatched || c.asciiBanner > 0) return 3;
    if (c.sysinfoFile > 0 && strongCategoryCount(c) >= 2) return 2;
    if (r.pct >= CONFIDENCE_THRESHOLDS.min) return 1;
    return 0;
  };

  results.sort((a, b) =>
    evidenceTier(b) - evidenceTier(a) ||
    b.score - a.score ||
    b.pct - a.pct);

  // OS-class veto: a Windows stealer family must not win a macOS log (and a
  // macOS family must not win a Windows log). macOS families are tagged
  // osClass:'macos'. Unknown OS → no veto, and a family that named itself
  // outranks a platform inferred from loose cues rather than the OS line.
  const os = classifyOs(ctx.combinedSysinfoText || ctx.sysinfoText || '');
  const osEligible = (r) => {
    if (!os.osClass) return true;
    if ((r.osClass === 'macos') === (os.osClass === 'macos')) return true;
    return !os.keyed && (r.selfIdMatched || (r.matchedCounts && r.matchedCounts.asciiBanner > 0));
  };

  let best = results.find(osEligible);
  if (!os.keyed && (!best || evidenceTier(best) < 1)) {
    // The veto picks between candidates. Unless the OS line itself contradicts
    // the family, it must not erase an identification the evidence supports.
    best = results.find(r => evidenceTier(r) >= 2) || best;
  }

  if (best && evidenceTier(best) >= 1) {
    const c = best.matchedCounts;
    const strongCats = strongCategoryCount(c);
    const hasSysinfoFile = c.sysinfoFile > 0;

    let confidence;
    if (best.selfIdMatched || c.asciiBanner > 0) confidence = 'high';
    else if (hasSysinfoFile && strongCats >= 2) confidence = 'high';
    else if (hasSysinfoFile || strongCats >= 2) confidence = 'medium';
    else if (best.pct >= CONFIDENCE_THRESHOLDS.high) confidence = 'high';
    else if (best.pct >= CONFIDENCE_THRESHOLDS.medium) confidence = 'medium';
    else confidence = 'low';

    return {
      family: best.family,
      confidence,
      score: Math.round(best.pct * 100) / 100,
      matchedSignals: best.matched,
    };
  }

  // Structure-only fallback: no sysinfo/SELF_ID lined up, but folder + file
  // layout may still betray a stealer family. Conservative threshold so
  // a lone `Autofill/` folder doesn't fire.
  const structureResults = [];
  for (const [family, sig] of Object.entries(SIGNATURES)) {
    const r = scoreStructureOnly(family, sig, ctx);
    if (!r || r.maxScore <= 0) continue;
    if (r.score < W.FOLDER * 2 && r.score < W.STRUCTURE) continue;
    r.pct = r.score / r.maxScore;
    structureResults.push(r);
  }
  structureResults.sort((a, b) => b.score - a.score || b.pct - a.pct);

  const structBest = structureResults.find(osEligible);

  if (structBest) {
    if (structBest.distinctive >= 2) {
      return {
        family: structBest.family,
        confidence: 'low',
        score: Math.round(structBest.pct * 100) / 100,
        matchedSignals: structBest.matched,
        source: 'structure-only',
      };
    }
    return {
      family: 'Generic stealer layout',
      confidence: 'low',
      score: Math.round(structBest.pct * 100) / 100,
      matchedSignals: structBest.matched,
      source: 'structure-only',
    };
  }

  return null;
}

export { collectContext, fingerprintStealer };
