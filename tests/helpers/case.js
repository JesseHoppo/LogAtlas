// Runs synthetic logs through the app's own ingestion and analysis code, so a
// test exercises what a folder drop does: filename detection, the content
// sniff, aggregate promotion and wrapper collapse, then the full analysis pass
// with every event it publishes. Fixtures are invented throughout: example
// domains, documentation address ranges, made-up people.

import { on, resetState, state } from '../../js/core/state.js';
import { addFilesToTree } from '../../js/files/extractor.js';
import { runAnalysis } from '../../js/analysis/analysis.js';

const ANALYSIS_EVENTS = [
  'sysinfo', 'software', 'processList', 'timezone', 'history', 'browserclock',
  'capture', 'credentials', 'cookies', 'autofill', 'notes', 'bookmarks',
  'browserMetadata', 'stealerDebug', 'accountTokens', 'serviceArtifacts',
  'wallets', 'downloads', 'creditCards', 'domainDetect', 'clipboard',
  'grabbedFiles', 'screenshot', 'fingerprint', 'readErrors', 'complete',
];

// The bus has no unsubscribe, so one listener per event routes into whichever
// case is running.
let collecting = null;
for (const name of ANALYSIS_EVENTS) {
  on(`analysis:${name}`, (data) => {
    if (!collecting) return;
    const value = name === 'complete' ? true : (data ?? null);
    collecting.events[name] = value;
    (collecting.emitted[name] ||= []).push(value);
  });
}

const encoder = new TextEncoder();

function toFile(relativePath, spec) {
  const { content, mtime } = typeof spec === 'object' && !(spec instanceof Uint8Array)
    ? spec
    : { content: spec, mtime: 0 };
  const bytes = typeof content === 'string' ? encoder.encode(content) : content;
  const name = relativePath.split('/').pop();
  const file = new File([bytes], name, { lastModified: mtime || 0 });
  // Browsers set this on a folder pick; the extractor rebuilds the tree from it.
  Object.defineProperty(file, 'webkitRelativePath', { value: relativePath });
  return file;
}

// `files` maps a path inside the dropped folder to its text (or bytes, or
// `{ content, mtime }`). `root` names that folder, the way a dropped log
// directory would be named; pass '' for loose files with no folder.
export async function analyseCase(files, { root = 'case' } = {}) {
  resetState();
  const list = Object.entries(files).map(([path, spec]) => toFile(root ? `${root}/${path}` : path, spec));
  await addFilesToTree(list, { trustMtime: true });

  collecting = { events: {}, emitted: {} };
  try {
    await runAnalysis(state.fileTree, state.rootZipName);
    return { ...collecting, tree: state.fileTree, rootName: state.rootZipName };
  } finally {
    collecting = null;
  }
}

export function findNode(tree, path) {
  let node = tree;
  for (const segment of path.split('/')) {
    node = node?.children?.[segment];
    if (!node) return null;
  }
  return node;
}

export function hintsOf(node) {
  return Object.keys(node || {}).filter((key) => key.endsWith('Hint') && node[key]).sort();
}
