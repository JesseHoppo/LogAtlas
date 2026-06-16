// Stealer family fingerprinting based on directory layout, filenames, and sysinfo.

import { SIGNAL_WEIGHTS as W, SIGNATURES, CONFIDENCE_THRESHOLDS } from '../core/definitions/signatures.js';
import { FILE_TYPE_PATTERNS } from '../core/definitions/fileTypes.js';

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
  const globalText = [ctx.combinedSysinfoText || ctx.sysinfoText, ctx.creditsText, ctx.passwordHeaderText, ctx.clipboardText].filter(Boolean).join('\n');
  if (sig.selfId && sig.selfId.length > 0) {
    maxScore += W.SELF_ID;
    if (globalText) {
      for (const si of sig.selfId) {
        if (si.pattern.test(globalText)) {
          score += W.SELF_ID;
          matched.push(si.label);
          matchedCounts.selfId++;
          break;
        }
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

  if (sig.exclusions && sig.exclusions.some(rule => rule.test(signalState))) {
    return { family: familyName, score: 0, maxScore, matched: [], matchedCounts, selfIdMatched: false, excluded: true };
  }

  if (sig.require && !sig.require(signalState)) {
    return { family: familyName, score: 0, maxScore, matched: [], matchedCounts, selfIdMatched: false, blocked: true };
  }

  const selfIdMatched = matchedCounts.selfId > 0;

  return { family: familyName, score, maxScore, matched, matchedCounts, selfIdMatched, sysinfoFilename: ctx.sysinfoFilename || '' };
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

  for (const f of sig.folders || []) {
    maxScore += W.FOLDER;
    if (ctx.dirs.some(d => f.pattern.test(d))) {
      score += W.FOLDER;
      matched.push(f.label);
      matchedCounts.folder++;
    }
  }
  for (const fp of sig.files || []) {
    maxScore += W.FILE_PATTERN;
    if (ctx.files.some(f => fp.pattern.test(f))) {
      score += W.FILE_PATTERN;
      matched.push(fp.label);
      matchedCounts.file++;
    }
  }
  for (const s of sig.structures || []) {
    maxScore += W.STRUCTURE;
    if (s.test(ctx.dirs, ctx.files)) {
      score += W.STRUCTURE;
      matched.push(s.label);
      matchedCounts.structure++;
    }
  }

  // Same gates as the full pass. With no sysinfo evidence here, families that
  // require it (or that exclude on structure) stay out instead of matching on
  // layout alone.
  const signalState = { ctx, matchedCounts, matched };
  if (sig.exclusions && sig.exclusions.some(rule => rule.test(signalState))) return null;
  if (sig.require && !sig.require(signalState)) return null;

  return { family: familyName, score, maxScore, matched };
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

  // Prefer families with more total matched evidence, then break ties by how complete the match is.
  results.sort((a, b) => b.score - a.score || b.pct - a.pct);

  const best = results[0];
  if (best && best.pct >= CONFIDENCE_THRESHOLDS.min) {
    let confidence;
    if (best.selfIdMatched) confidence = 'high';
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
  const structBest = structureResults[0];
  if (structBest) {
    return {
      family: structBest.family,
      confidence: 'low',
      score: Math.round(structBest.pct * 100) / 100,
      matchedSignals: structBest.matched,
      source: 'structure-only',
    };
  }

  return null;
}

export { collectContext, fingerprintStealer };
