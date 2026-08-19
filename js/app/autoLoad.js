import { showNotification } from '../core/shared.js';
import { openTransientModal } from '../core/modal.js';
import { escapeHtml, formatBytes } from '../core/utils.js';
import { LIMITS } from '../core/definitions/patterns.js';

function isAllowedFileUrl(parsedUrl) {
  return parsedUrl.protocol === 'https:' || parsedUrl.origin === window.location.origin;
}

function confirmFileLoad(parsedUrl) {
  return new Promise((resolve) => {
    const modal = openTransientModal(`
      <div class="modal">
        <h3>Load file from URL?</h3>
        <p>Opened with a <code>?file=</code> URL. Fetched and parsed in this browser only.</p>
        <p><strong>Source:</strong> <code>${escapeHtml(parsedUrl.host)}</code></p>
        <p style="font-size:0.8rem;color:var(--text-muted);">URL: ${escapeHtml(parsedUrl.href)}</p>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="autoLoadCancel">Cancel</button>
          <button class="modal-btn modal-btn-submit" id="autoLoadProceed">Load file</button>
        </div>
      </div>
    `, { onDismiss: () => resolve(false) });
    if (!modal) { resolve(false); return; }

    const answer = (result) => {
      modal.close();
      resolve(result);
    };
    modal.overlay.querySelector('#autoLoadCancel').addEventListener('click', () => answer(false));
    modal.overlay.querySelector('#autoLoadProceed').addEventListener('click', () => answer(true));
  });
}

export async function autoLoadFromQuery(handleFiles) {
  const params = new URLSearchParams(window.location.search);
  const fileUrl = params.get('file');
  if (!fileUrl) return;

  let parsed;
  try {
    parsed = new URL(fileUrl);
    if (!isAllowedFileUrl(parsed)) {
      showNotification('Only HTTPS or same-origin file URLs are supported.', 'error');
      return;
    }
  } catch {
    showNotification('Invalid file URL.', 'error');
    return;
  }

  const dropZone = document.getElementById('dropZone');
  const uploadInfo = document.getElementById('uploadInfo');
  const loading = document.getElementById('loading');
  const loadingText = document.getElementById('loadingText');

  const proceed = await confirmFileLoad(parsed);
  if (!proceed) return;

  dropZone.style.display = 'none';
  uploadInfo.style.display = 'none';
  loading.classList.add('visible');
  loadingText.textContent = 'Loading file...';

  try {
    const response = await fetch(fileUrl);
    if (!response.ok) {
      throw new Error(`Download failed: ${response.status} ${response.statusText}`);
    }

    // Streamed cap catches servers that don't expose Content-Length.
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('Streaming not supported by this browser.');
    }

    const chunks = [];
    let received = 0;
    let lastTextUpdate = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > LIMITS.autoLoadMaxBytes) {
        try { await reader.cancel(); } catch { /* reader already closed */ }
        throw new Error(
          `Remote file exceeded ${formatBytes(LIMITS.autoLoadMaxBytes)} cap (cancelled at ${formatBytes(received)}).`
        );
      }
      chunks.push(value);
      const now = performance.now();
      if (now - lastTextUpdate > 100) {
        loadingText.textContent = `Loading file... ${formatBytes(received)}`;
        lastTextUpdate = now;
      }
    }

    const blob = new Blob(chunks, { type: response.headers.get('content-type') || 'application/octet-stream' });
    // Trailing-slash / empty paths and malformed escapes must not sink a good download.
    let fileName = '';
    try {
      const segment = parsed.pathname.split('/').filter(Boolean).pop() || '';
      fileName = decodeURIComponent(segment);
    } catch { /* malformed escape; fall through to default */ }
    if (!fileName) fileName = 'download.zip';
    const file = new File([blob], fileName, { type: blob.type });

    loading.classList.remove('visible');
    await handleFiles([file]);
  } catch (error) {
    loading.classList.remove('visible');
    dropZone.style.display = '';
    uploadInfo.style.display = '';
    showNotification(`Failed to load file: ${error.message}`, 'error');
  }
}
