import { state } from '../core/state.js';
import { downloadBlob, showNotification } from '../core/shared.js';
import { countLabel, downloadCsvRows } from '../pages/shared.js';
import { getPasswordsData } from '../pages/credentials.js';
import { TOOL_NAME, TOOL_VERSION } from '../views/exports.js';

function exportFileListCsv() {
  downloadCsvRows('file-list.csv', ['Path', 'Name', 'Type', 'Size (bytes)', 'Depth', 'Is Nested Archive', 'Encrypted'], state.flatFiles.map((file) => [
    file.path,
    file.name,
    file.type,
    file.size,
    file.depth,
    file.isNestedArchive ? 'Yes' : 'No',
    file.encrypted ? 'Yes' : 'No',
  ]));
}

function exportFileListJson() {
  const payload = {
    tool: TOOL_NAME,
    toolVersion: TOOL_VERSION,
    source: state.rootZipName || '',
    // UTC, ISO-8601 with the Z suffix: this file is read by tools, not people.
    exportedAt: new Date().toISOString(),
    totalFiles: state.flatFiles.filter((file) => file.type === 'file').length,
    totalFolders: state.flatFiles.filter((file) => file.type === 'directory').length,
    errors: state.errors,
    files: state.flatFiles,
  };

  downloadBlob(JSON.stringify(payload, null, 2), 'file-list.json', 'application/json');
}

function exportAllCredentials() {
  const data = getPasswordsData();
  if (!data || data.rows.length === 0) {
    showNotification('No credential data available to export.', 'error');
    return;
  }

  downloadCsvRows('all_credentials.csv', ['Source File', ...data.headers], data.rows.map(
    ({ row, source }) => [source, ...row]
  ));
  showNotification(`Exported ${data.rows.length} credential rows from ${data.fileCount} file(s).`, 'info');
}

export function initFileExportActions() {
  document.getElementById('exportCsv')?.addEventListener('click', exportFileListCsv);
  document.getElementById('exportJson')?.addEventListener('click', exportFileListJson);
  document.getElementById('exportCredentials')?.addEventListener('click', () => {
    exportAllCredentials();
  });
}
