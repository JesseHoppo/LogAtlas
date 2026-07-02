import { showNotification } from '../core/shared.js';
import { escapeHtml, formatBytes } from '../core/utils.js';
import { LIMITS } from '../core/definitions/patterns.js';

function isAllowedFileUrl(parsedUrl) {
  return parsedUrl.protocol === 'https:' || parsedUrl.origin === window.location.origin;
}

function confirmFileLoad(parsedUrl) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay visible';
    overlay.id = 'autoLoadConfirmModal';
    overlay.innerHTML = `
      <div class="modal">
        <h3>Load file from URL?</h3>
        <p>Log Atlas was opened with a <code>?file=</code> URL. The file will be loaded into this browser for analysis. Nothing is uploaded.</p>
        <p><strong>Source:</strong> <code>${escapeHtml(parsedUrl.host)}</code></p>
        <p style="font-size:0.8rem;color:var(--text-muted);">URL: ${escapeHtml(parsedUrl.href)}</p>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="autoLoadCancel">Cancel</button>
          <button class="modal-btn modal-btn-submit" id="autoLoadProceed">Load File</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const cleanup = (result) => {
      overlay.remove();
      document.removeEventListener('keydown', onKey);
      resolve(result);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); cleanup(false); }
    };
    document.addEventListener('keydown', onKey);

    overlay.querySelector('#autoLoadCancel').addEventListener('click', () => cleanup(false));
    overlay.querySelector('#autoLoadProceed').addEventListener('click', () => cleanup(true));
    overlay.addEventListener('click', (ev) => { if (ev.target === overlay) cleanup(false); });
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
