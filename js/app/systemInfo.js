import { copyToClipboard, showNotification } from '../core/shared.js';
import { downloadCsvRows, openSourcePreview, resolveSourcePathSegments } from '../pages/shared.js';
import { getNodeAtPath } from '../files/extractor.js';

function getSystemInfoRows() {
  return Array.from(document.querySelectorAll('#dashSysInfoBody .dash-kv-row')).map((row) => ({
    key: row.querySelector('.dash-kv-key')?.textContent || '',
    value: row.querySelector('.dash-kv-value')?.textContent || '',
  }));
}

export function initSystemInfoActions({ getSysInfoSourcePath, navigateToPage, navigateTo }) {
  document.getElementById('sysInfoCopyAll')?.addEventListener('click', () => {
    const text = getSystemInfoRows().map(({ key, value }) => `${key}: ${value}`).join('\n');

    copyToClipboard(text).then((ok) => {
      if (ok) showNotification('System info copied to clipboard.');
    });
  });

  document.getElementById('sysInfoExportCsv')?.addEventListener('click', () => {
    downloadCsvRows('system_info.csv', ['Key', 'Value'], getSystemInfoRows().map(({ key, value }) => [key, value]));
  });

  document.getElementById('sysInfoOpenBtn')?.addEventListener('click', () => {
    const sourcePath = getSysInfoSourcePath();
    if (!sourcePath) return;

    const pathSegments = resolveSourcePathSegments(sourcePath);
    if (!getNodeAtPath(pathSegments)) {
      showNotification('Source file is no longer available in the current session.', 'error');
      return;
    }

    navigateTo(pathSegments.slice(0, -1));
    navigateToPage('browser');
    openSourcePreview(sourcePath);
  });
}
