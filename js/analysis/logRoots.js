// Where each log in a case starts.
//
// A log is the directory its stealer wrote the system profile into. Family
// signatures describe layouts relative to that directory, and a profile names
// one victim. The archive root is often neither: a resale note dropped beside
// the log folder stops the single-folder collapse, and a bundle of several
// victims puts each log a level or more down. Reading layouts from the archive
// root lost the fingerprint in the first case and merged unrelated victims in
// the second.

import { FILE_TYPE_PATTERNS } from '../core/definitions/fileTypes.js';

// A profile kept in a folder of its own (`System/Info.txt`) belongs to the log
// above that folder.
const PROFILE_FOLDERS = FILE_TYPE_PATTERNS.sysinfo.dirPatterns;
// An environment-variable dump sits beside the profile; it locates nothing the
// profile doesn't.
const ENVIRONMENT_DUMP = /environment/i;

function isBelow(ancestorPath, path) {
  return ancestorPath === '' ? path !== '' : path.startsWith(`${ancestorPath}/`);
}

// Log roots in tree walk order, the order analysis reads sysinfo in, so the
// first root is the one whose profile wins the merged sysinfo. Each carries the
// profile nodes that placed it.
function findLogRoots(root) {
  const found = [];
  const byNode = new Map();

  function visit(dir, path, parent) {
    for (const child of Object.values(dir.children || {})) {
      if (child.type === 'directory') {
        visit(child, path ? `${path}/${child.name}` : child.name, { node: dir, path });
        continue;
      }
      if (!child._sysInfoHint || child._grabbedFileHint || ENVIRONMENT_DUMP.test(child.name || '')) continue;
      const logDir = parent && PROFILE_FOLDERS.some((rx) => rx.test(dir.name || '')) ? parent : { node: dir, path };
      let entry = byNode.get(logDir.node);
      if (!entry) {
        entry = { node: logDir.node, path: logDir.path, name: logDir.node.name || '', sysinfoNodes: [] };
        byNode.set(logDir.node, entry);
        found.push(entry);
      }
      entry.sysinfoNodes.push(child);
    }
  }

  if (root) visit(root, '', null);

  // A document grabbed from the victim's desktop can carry a profile's name.
  // It sits inside its log, so only the outermost root of a nesting chain is a
  // log of its own.
  return found.filter((entry) => !found.some((other) => other !== entry && isBelow(other.path, entry.path)));
}

const USER_KEY = /^(?:user\s*name|username|user|pc\s*user)$/i;
const COMPUTER_KEY = /^(?:computer\s*name|computer|pc\s*name|pc|host\s*name|hostname|netbios|machine\s*name)$/i;
const COUNTRY_KEY = /^(?:country(?:\s*code)?|geo)$/i;

// Who a log belongs to, read from the profiles analysis already parsed.
function describeLogRoot(entry) {
  const pick = (pattern) => {
    for (const node of entry.sysinfoNodes) {
      for (const [key, value] of Object.entries(node._parsedSysinfo?.entries || {})) {
        if (value && pattern.test(key.trim())) return String(value).trim();
      }
    }
    return '';
  };
  return {
    path: entry.path,
    name: entry.name,
    user: pick(USER_KEY),
    computer: pick(COMPUTER_KEY),
    country: pick(COUNTRY_KEY),
  };
}

export { findLogRoots, describeLogRoot };
