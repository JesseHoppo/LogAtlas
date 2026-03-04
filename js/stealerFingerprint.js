// Stealer family fingerprinting based on directory layout, filenames, and sysinfo.

import { SIGNAL_WEIGHTS as W, SIGNATURES, CONFIDENCE_THRESHOLDS, FILE_TYPE_PATTERNS } from './definitions.js';

function scoreFamily(familyName, sig, ctx) {
  let score = 0;
  let maxScore = 0;
  const matched = [];

  // 1. Self-identification (stealer names itself explicitly)
  if (sig.selfId && sig.selfId.length > 0) {
    maxScore += W.SELF_ID;
    const allText = [ctx.sysinfoText, ctx.creditsText, ctx.passwordHeaderText].filter(Boolean).join('\n');
    if (allText) {
      for (const si of sig.selfId) {
        if (si.pattern.test(allText)) {
          score += W.SELF_ID;
          matched.push(si.label);
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
    }
  }

  // 3. Sysinfo keys
  for (const sk of sig.sysinfoKeys) {
    maxScore += W.SYSINFO_KEY;
    if (ctx.sysinfoKeys.some(k => sk.pattern.test(k))) {
      score += W.SYSINFO_KEY;
      matched.push(sk.label);
    }
  }

  // 4. Sysinfo content patterns
  for (const sc of sig.sysinfoContent) {
    maxScore += W.SYSINFO_CONTENT;
    if (ctx.sysinfoText && sc.pattern.test(ctx.sysinfoText)) {
      score += W.SYSINFO_CONTENT;
      matched.push(sc.label);
    }
  }

  // 5. ASCII banners (whitespace-normalized comparison)
  if (sig.asciiBanners && sig.asciiBanners.length > 0) {
    maxScore += W.ASCII_BANNER;
    const allText = [ctx.sysinfoText, ctx.creditsText, ctx.passwordHeaderText].filter(Boolean).join('\n');
    if (allText) {
      const normText = allText.replace(/[ \t]+/g, ' ');
      for (const banner of sig.asciiBanners) {
        const normBanner = banner.replace(/[ \t]+/g, ' ');
        if (normText.includes(normBanner)) {
          score += W.ASCII_BANNER;
          matched.push(`ASCII banner: ${familyName} art detected`);
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
    }
  }

  // 7. File pattern matches
  for (const fp of sig.files) {
    maxScore += W.FILE_PATTERN;
    if (ctx.files.some(f => fp.pattern.test(f))) {
      score += W.FILE_PATTERN;
      matched.push(fp.label);
    }
  }

  // 8. Structural tests
  for (const s of sig.structures) {
    maxScore += W.STRUCTURE;
    if (s.test(ctx.dirs, ctx.files)) {
      score += W.STRUCTURE;
      matched.push(s.label);
    }
  }

  return { family: familyName, score, maxScore, matched };
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

      if (child._sysInfoHint || /^(?:information|UserInformation|system_info|Info|user_info|system|pc_info|build_info|UserInfo|_Information|identification|environment)\.(?:txt|json)$/i.test(child.name)) {
        if (!ctx.sysinfoFilename) {
          ctx.sysinfoFilename = child.name;
          ctx.sysinfoNode = child;
        }
      }

      if (child._creditsFileHint || FILE_TYPE_PATTERNS.credits.filePatterns.some(rx => rx.test(child.name))) {
        ctx.creditsNodes.push(child);
      }
      if (child._passwordFileHint || /^(?:passwords?|unique[\s_-]*passwords?)\.txt$/i.test(child.name)) {
        if (!ctx.passwordNode) ctx.passwordNode = child;
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
