// Stealer family fingerprinting based on directory layout, filenames, and sysinfo.

import { SIGNAL_WEIGHTS as W, SIGNATURES, CONFIDENCE_THRESHOLDS } from './definitions.js';

function scoreFamily(familyName, sig, ctx) {
  let score = 0;
  let maxScore = 0;
  const matched = [];

  // 1. Sysinfo filename
  if (sig.sysinfoFile) {
    maxScore += sig.sysinfoFile.weight;
    if (ctx.sysinfoFilename && sig.sysinfoFile.pattern.test(ctx.sysinfoFilename)) {
      score += sig.sysinfoFile.weight;
      matched.push(`Sysinfo file: ${ctx.sysinfoFilename}`);
    }
  }

  // 2. Sysinfo keys
  for (const sk of sig.sysinfoKeys) {
    maxScore += W.SYSINFO_KEY;
    if (ctx.sysinfoKeys.some(k => sk.pattern.test(k))) {
      score += W.SYSINFO_KEY;
      matched.push(sk.label);
    }
  }

  // 3. Sysinfo content patterns
  for (const sc of sig.sysinfoContent) {
    maxScore += W.SYSINFO_CONTENT;
    if (ctx.sysinfoText && sc.pattern.test(ctx.sysinfoText)) {
      score += W.SYSINFO_CONTENT;
      matched.push(sc.label);
    }
  }

  // 4. Folder matches
  for (const f of sig.folders) {
    maxScore += W.FOLDER;
    if (ctx.dirs.some(d => f.pattern.test(d))) {
      score += W.FOLDER;
      matched.push(f.label);
    }
  }

  // 5. File pattern matches
  for (const fp of sig.files) {
    maxScore += W.FILE_PATTERN;
    if (ctx.files.some(f => fp.pattern.test(f))) {
      score += W.FILE_PATTERN;
      matched.push(fp.label);
    }
  }

  // 6. Structural tests
  for (const s of sig.structures) {
    maxScore += W.STRUCTURE;
    if (s.test(ctx.dirs, ctx.files)) {
      score += W.STRUCTURE;
      matched.push(s.label);
    }
  }

  return { family: familyName, score, maxScore, matched };
}

// Walk the file tree and collect dirs, files, and sysinfo node.
function collectContext(node, basePath, ctx) {
  if (!node || !node.children) return;

  for (const child of Object.values(node.children)) {
    const relPath = basePath ? basePath + '/' + child.name : child.name;

    if (child.type === 'directory') {
      ctx.dirs.push(relPath);
      collectContext(child, relPath, ctx);
    } else {
      ctx.files.push(relPath);

      // Detect sysinfo filename by common patterns
      if (child._sysInfoHint || /^(?:information|UserInformation|system_info|Info|user_info|system|pc_info|build_info)\.txt$/i.test(child.name)) {
        if (!ctx.sysinfoFilename) {
          ctx.sysinfoFilename = child.name;
          ctx.sysinfoNode = child;
        }
      }
    }
  }
}

function fingerprintStealer(ctx) {
  const results = [];

  for (const [family, sig] of Object.entries(SIGNATURES)) {
    const result = scoreFamily(family, sig, ctx);
    if (result.maxScore > 0) {
      result.pct = result.score / result.maxScore;
      results.push(result);
    }
  }

  // Sort by percentage score descending, then by absolute score
  results.sort((a, b) => b.pct - a.pct || b.score - a.score);

  const best = results[0];
  if (!best || best.pct < CONFIDENCE_THRESHOLDS.min) {
    return null;
  }

  let confidence;
  if (best.pct >= CONFIDENCE_THRESHOLDS.high) confidence = 'high';
  else if (best.pct >= CONFIDENCE_THRESHOLDS.medium) confidence = 'medium';
  else confidence = 'low';

  return {
    family: best.family,
    confidence,
    score: Math.round(best.pct * 100) / 100,
    matchedSignals: best.matched,
  };
}

export { collectContext, fingerprintStealer };
