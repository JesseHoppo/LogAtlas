// Software / process-line evaluation, shared by the analysis engine and the
// headless `scripts/` reporters so a fix to a supported format lands once.
// Nothing here touches the DOM or the event bus.

import { isPromotionalNoiseLine } from '../transforms/shared.js';
import { parseSoftwareLine } from '../core/shared.js';

const RUNNING_PROCESSES_HEADER = /^===\s*running processes\s*===$/i;
const PROCESS_NAME_PREFIX = /^[-*•]\s+/;

// Parse one process line across the union of observed formats. Returns
// { name, pid, sessionId, commandLine } or null when nothing usable remains.
function parseProcessLine(rawLine) {
  const line = String(rawLine || '').trim();
  if (!line) return null;

  let name = line;
  let pid = null;
  let sessionId = null;
  let commandLine = '';

  const labelled = line.match(/^PID:\s*(\d+)(?:\s*,\s*SessionID:\s*([^,]+))?\s*,\s*Name:\s*([^,]+)(?:\s*,\s*CommandLine:\s*(.*))?$/i);
  const idLabelled = labelled ? null : line.match(/^ID:\s*(\d+)\s*,\s*Name:\s*([^,]+?)(?:\s*,\s*CommandLine:\s*(.*))?$/i);
  if (labelled) {
    pid = labelled[1];
    sessionId = (labelled[2] || '').trim();
    name = labelled[3].trim();
    commandLine = (labelled[4] || '').trim();
  } else if (idLabelled) {
    pid = idLabelled[1];
    name = idLabelled[2].trim();
    commandLine = (idLabelled[3] || '').trim();
  } else {
    const pidDashMatch = line.match(/^PID:\s*(\d+)\s*-\s*(.+)$/i);
    if (pidDashMatch) {
      pid = pidDashMatch[1];
      name = pidDashMatch[2].trim();
    } else {
      const bracketPrefix = line.match(/^\[(\d+)\]\s+(.+)$/);
      if (bracketPrefix) {
        pid = bracketPrefix[1];
        name = bracketPrefix[2].trim();
      } else {
        const bracketSuffix = line.match(/^(.+?)\s*[\[(](\d+)[\])]\s*$/);
        if (bracketSuffix) {
          name = bracketSuffix[1].trim();
          pid = bracketSuffix[2];
        } else {
          const parts = line.split('\t').map(p => p.trim()).filter(Boolean);
          if (parts.length >= 2 && /^\d+$/.test(parts[1])) {
            name = parts[0];
            pid = parts[1];
            if (parts.length >= 3) commandLine = parts.slice(2).join(' ');
          } else if (parts.length === 1) {
            name = parts[0];
          }
        }
      }
    }
  }

  name = name.replace(PROCESS_NAME_PREFIX, '').trim();
  if (name.length > 200) return null;
  if (!name && !commandLine) return null;

  return { name, pid, sessionId, commandLine };
}

// Collect deduped process entries from candidate lines. `lines` is an iterable
// of raw lines (already section-bounded for the inline path, whole-file for the
// file path). The file path strips a leading promo banner before calling.
function parseProcessLines(lines, entryMap = new Map()) {
  for (const rawLine of lines) {
    const line = String(rawLine || '').trim();
    if (!line) continue;
    if (isPromotionalNoiseLine(line)) continue;
    if (/^[-=*#]{3,}$/.test(line)) continue;            // separators
    if (RUNNING_PROCESSES_HEADER.test(line)) continue;
    if (/^(Process|Name|PID|Image)/i.test(line) && /\t/.test(line)) continue;  // header row

    const parsed = parseProcessLine(line);
    if (!parsed) continue;

    const key = [parsed.name, parsed.pid || '', parsed.sessionId || '', parsed.commandLine].join(' ').toLowerCase();
    if (!entryMap.has(key)) entryMap.set(key, parsed);
  }
  return entryMap;
}

// Stealers append an install-path + install-date tail to each installed-app
// line (` - C:\...\Package Cache\... - 20240925`), pushing it past the length
// guard and dropping ~half the apps. Drop a trailing 8-digit date and/or a
// trailing absolute-path segment, keeping name+version+vendor for the parser.
function stripSoftwareTail(line) {
  let out = line;
  // trailing ` - YYYYMMDD` install date
  out = out.replace(/\s+-\s+\d{8}\s*$/, '');
  // trailing ` - <absolute path>` (Windows drive or POSIX root)
  out = out.replace(/\s+-\s+(?:[A-Za-z]:[\\/]|\\\\|\/).*$/, '');
  return out.trim();
}

// Collect deduped software entries from candidate lines.
function parseSoftwareLines(lines, entries = [], seen = new Set()) {
  for (const rawLine of lines) {
    const raw = String(rawLine || '').trim();
    if (!raw) continue;
    const line = stripSoftwareTail(raw);
    if (!line) continue;
    if (line.includes('   ')) continue;
    if (/https?:\/\//i.test(line) || /www\./i.test(line)) continue;
    if (/(===|\*\*\*|###|\$\$\$)/.test(line)) continue;
    if (line.length > 120) continue;
    if (/^[-=*#]{3,}$/.test(line)) continue;

    const parsed = parseSoftwareLine(line);
    if (!parsed) continue;
    const { name, version } = parsed;
    if (!name) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({ name, version });
  }
  return entries;
}

// Split a sysinfo file into its inline "Installed Apps:" / "Process List:"
// blocks. A section the file does not carry comes back null rather than empty,
// so the caller can tell absent from present-but-empty.
function splitInlineSections(text) {
  const lines = text ? String(text).split('\n') : [];

  const SOFTWARE_HEADER = /^Installed (?:Apps|Software|Programs)\s*:/i;
  const PROCESS_HEADER = /^Process (?:List|es)\s*:/i;
  // XFiles opens its process list with a header that ends in `[` and runs the
  // bare process names until a closing `]` on its own line.
  const PROCESS_BRACKET_HEADER = /^(?:Windows )?Processes?\s*\[\s*$/i;
  const BRACKET_SOFTWARE = /^\[Software\]/i;
  const BRACKET_PROCESS = /^\[Process(?:es)?\](?:\[\d+\])?/i;
  const BRACKET_SECTION = /^\[[A-Za-z][A-Za-z ]*\](?:\[\d+\])?$/;
  const SECTION_HEADER = /^[A-Z][A-Za-z ]+:$/;
  const SUB_HEADER = /^(?:All Users|Current User)\s*:/i;

  let softwareLines = null;
  let processLines = null;
  let currentTarget = null;
  // 'bracket' = `[Software]`/`[Processes]` block; 'fence' = XFiles `[ … ]`
  // multi-line list ended by a lone `]`; 'colon' = `Header:` block whose
  // entries run until a blank line or the next section header.
  let sectionMode = null;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();

    if (SOFTWARE_HEADER.test(trimmed) || BRACKET_SOFTWARE.test(trimmed)) {
      softwareLines = [];
      currentTarget = softwareLines;
      sectionMode = BRACKET_SOFTWARE.test(trimmed) ? 'bracket' : 'colon';
      continue;
    }
    if (PROCESS_HEADER.test(trimmed) || BRACKET_PROCESS.test(trimmed) || PROCESS_BRACKET_HEADER.test(trimmed)) {
      processLines = [];
      currentTarget = processLines;
      sectionMode = BRACKET_PROCESS.test(trimmed) ? 'bracket'
        : PROCESS_BRACKET_HEADER.test(trimmed) ? 'fence'
        : 'colon';
      continue;
    }

    // A fenced (`[ … ]`) list ends only at its closing bracket.
    if (currentTarget && sectionMode === 'fence') {
      if (trimmed === ']') { currentTarget = null; sectionMode = null; continue; }
      if (trimmed && !isPromotionalNoiseLine(trimmed)) currentTarget.push(trimmed);
      continue;
    }

    // A new section header ends the current section.
    if (currentTarget && trimmed) {
      if (BRACKET_SECTION.test(trimmed) || (!rawLine.startsWith('\t') && SECTION_HEADER.test(trimmed) && !SUB_HEADER.test(trimmed))) {
        currentTarget = null;
        sectionMode = null;
        continue;
      }
    }

    // Colon-headed lists run as one block: entries (incl. colon-bearing app
    // names) until the first blank line. Sub-headers like "All Users:" don't
    // count as blanks. Bracket lists ignore blank lines and end at the next
    // bracket/section header handled above.
    if (currentTarget && sectionMode === 'colon' && !trimmed) {
      currentTarget = null;
      sectionMode = null;
      continue;
    }

    // Skip sub-headers
    if (currentTarget && SUB_HEADER.test(trimmed)) continue;

    if (currentTarget && trimmed && !isPromotionalNoiseLine(trimmed)) {
      currentTarget.push(trimmed);
    }
  }

  return { softwareLines, processLines };
}

// The inline sections as parsed entries, empty arrays when absent.
function evaluateInlineSections(text) {
  const { softwareLines, processLines } = splitInlineSections(text);
  return {
    softwareEntries: softwareLines ? parseSoftwareLines(softwareLines) : [],
    processEntries: processLines ? [...parseProcessLines(processLines).values()] : [],
  };
}

export {
  parseProcessLine,
  parseProcessLines,
  stripSoftwareTail,
  parseSoftwareLines,
  splitInlineSections,
  evaluateInlineSections,
};
