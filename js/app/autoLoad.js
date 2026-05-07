import { showNotification } from '../core/shared.js';
import { escapeHtml, formatBytes } from '../core/utils.js';
import { LIMITS } from '../core/definitions/patterns.js';

function confirmRemoteDownload(parsedUrl, sizeBytes) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay visible';
    overlay.id = 'autoLoadConfirmModal';
    const sizeLabel = sizeBytes > 0 ? formatBytes(sizeBytes) : 'unknown size';
    overlay.innerHTML = `
      <div class="modal">
        <h3>Download remote file?</h3>
        <p>Log Atlas was opened with a <code>?file=</code> URL. The file will be downloaded into your browser for analysis. No data will be sent anywhere.</p>
        <p><strong>Source:</strong> <code>${escapeHtml(parsedUrl.host)}</code></p>
        <p><strong>Size:</strong> ${escapeHtml(sizeLabel)}</p>
        <p style="font-size:0.8rem;color:var(--text-muted);">URL: ${escapeHtml(parsedUrl.href)}</p>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="autoLoadCancel">Cancel</button>
          <button class="modal-btn modal-btn-submit" id="autoLoadProceed">Download</button>
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

// Returns -1 when the size can't be probed; the streaming cap below catches
// servers that block HEAD or don't expose Content-Length.
async function probeRemoteSize(fileUrl) {
  try {
    const head = await fetch(fileUrl, { method: 'HEAD' });
    if (!head.ok) return -1;
    const contentLength = head.headers.get('content-length');
    return contentLength ? parseInt(contentLength, 10) : -1;
  } catch {
    return -1;
  }
}

export async function autoLoadFromQuery(handleFiles) {
  const params = new URLSearchParams(window.location.search);
  const fileUrl = params.get('file');
  if (!fileUrl) return;

  let parsed;
  try {
    parsed = new URL(fileUrl);
    if (parsed.protocol !== 'https:') {
      showNotification('Only HTTPS file URLs are supported.', 'error');
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

  const reportedSize = await probeRemoteSize(fileUrl);
  if (reportedSize > LIMITS.autoLoadMaxBytes) {
    showNotification(
      `Remote file is ${formatBytes(reportedSize)}, exceeds ${formatBytes(LIMITS.autoLoadMaxBytes)} cap.`,
      'error',
    );
    return;
  }

  const proceed = await confirmRemoteDownload(parsed, reportedSize);
  if (!proceed) return;

  dropZone.style.display = 'none';
  uploadInfo.style.display = 'none';
  loading.classList.add('visible');
  loadingText.textContent = 'Downloading file...';

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
        try { await reader.cancel(); } catch (_) { /* ignore */ }
        throw new Error(
          `Remote file exceeded ${formatBytes(LIMITS.autoLoadMaxBytes)} cap (cancelled at ${formatBytes(received)}).`
        );
      }
      chunks.push(value);
      const now = performance.now();
      if (now - lastTextUpdate > 100) {
        loadingText.textContent = `Downloading file... ${formatBytes(received)}`;
        lastTextUpdate = now;
      }
    }

    const blob = new Blob(chunks, { type: response.headers.get('content-type') || 'application/octet-stream' });
    const fileName = decodeURIComponent(fileUrl.split('/').pop().split('?')[0]) || 'download.zip';
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
