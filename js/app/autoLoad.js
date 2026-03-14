import { showNotification } from '../core/shared.js';

export async function autoLoadFromQuery(handleFiles) {
  const params = new URLSearchParams(window.location.search);
  const fileUrl = params.get('file');
  if (!fileUrl) return;

  try {
    const parsed = new URL(fileUrl);
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

  dropZone.style.display = 'none';
  uploadInfo.style.display = 'none';
  loading.classList.add('visible');
  loadingText.textContent = 'Downloading file...';

  try {
    const response = await fetch(fileUrl);
    if (!response.ok) {
      throw new Error(`Download failed: ${response.status} ${response.statusText}`);
    }

    const blob = await response.blob();
    const fileName = decodeURIComponent(fileUrl.split('/').pop().split('?')[0]) || 'download.zip';
    const file = new File([blob], fileName, { type: blob.type || 'application/octet-stream' });

    loading.classList.remove('visible');
    await handleFiles([file]);
  } catch (error) {
    loading.classList.remove('visible');
    dropZone.style.display = '';
    uploadInfo.style.display = '';
    showNotification(`Failed to load file: ${error.message}`, 'error');
  }
}
