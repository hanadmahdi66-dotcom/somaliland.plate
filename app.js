/**
 * Somaliland Plate Tracker — Secure Government Registry
 * Storage: localStorage with XOR + Base64 + checksum validation
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'sl_plate_vault_v1';
  const XOR_KEY = 'SL-GOV-L2-SECURE-VAULT-2026';
  const MIN_PHOTOS = 3;
  const SPLASH_MS = 4000;
  const MAX_PHOTO_WIDTH = 900;
  const JPEG_QUALITY = 0.72;

  /** @type {string[]} */
  let pendingPhotos = [];

  /** In-memory fallback when localStorage is blocked (e.g. some file:// contexts) */
  let memoryVault = null;
  let useMemoryStore = false;

  // ─── Security Layer ───

  function computeChecksum(str) {
    let sum = 0;
    for (let i = 0; i < str.length; i++) {
      sum = ((sum << 5) - sum + str.charCodeAt(i)) | 0;
    }
    return (sum >>> 0).toString(16).padStart(8, '0');
  }

  function xorCipher(input, key) {
    let out = '';
    for (let i = 0; i < input.length; i++) {
      out += String.fromCharCode(
        input.charCodeAt(i) ^ key.charCodeAt(i % key.length)
      );
    }
    return out;
  }

  function bytesToBase64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function encryptPayload(data) {
    const json = JSON.stringify(data);
    const xored = xorCipher(json, XOR_KEY);
    const bytes = new TextEncoder().encode(xored);
    const b64 = bytesToBase64(bytes);
    const checksum = computeChecksum(b64);
    return JSON.stringify({ payload: b64, checksum, v: 2 });
  }

  function decryptPayload(stored) {
    const wrapper = JSON.parse(stored);
    const { payload, checksum } = wrapper;
    if (computeChecksum(payload) !== checksum) {
      throw new Error('INTEGRITY_FAIL');
    }

    let xored;
    if (wrapper.v === 2) {
      xored = new TextDecoder().decode(base64ToBytes(payload));
    } else {
      xored = decodeURIComponent(
        atob(payload)
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
    }

    const json = xorCipher(xored, XOR_KEY);
    return JSON.parse(json);
  }

  function readRawVault() {
    if (useMemoryStore) return memoryVault;
    return localStorage.getItem(STORAGE_KEY);
  }

  function writeRawVault(encrypted) {
    if (useMemoryStore) {
      memoryVault = encrypted;
      return true;
    }
    localStorage.setItem(STORAGE_KEY, encrypted);
    return true;
  }

  function initStorage() {
    try {
      const testKey = '__sl_storage_test__';
      localStorage.setItem(testKey, 'ok');
      localStorage.removeItem(testKey);
      useMemoryStore = false;
    } catch {
      useMemoryStore = true;
      memoryVault = memoryVault || null;
      console.warn('[Vault] localStorage unavailable — using session memory.');
    }
  }

  function loadVehicles() {
    try {
      const raw = readRawVault();
      if (!raw) return [];
      const data = decryptPayload(raw);
      return Array.isArray(data) ? data : [];
    } catch (err) {
      console.warn('[Vault] Load failed:', err);
      return [];
    }
  }

  function saveVehicles(vehicles) {
    const encrypted = encryptPayload(vehicles);
    try {
      writeRawVault(encrypted);
      const verify = loadVehicles();
      if (verify.length !== vehicles.length) {
        throw new Error('VERIFY_FAIL');
      }
      return { ok: true };
    } catch (err) {
      if (err && (err.name === 'QuotaExceededError' || err.code === 22)) {
        return { ok: false, error: 'quota' };
      }
      return { ok: false, error: err && err.message ? err.message : 'save_failed' };
    }
  }

  // ─── UI Helpers ───

  function $(id) {
    return document.getElementById(id);
  }

  function showToast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.remove('hidden');
    el.classList.add('show');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.classList.add('hidden'), 300);
    }, 2800);
  }

  function showView(viewId) {
    document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
    $(viewId).classList.add('active');
  }

  function formatDate(iso) {
    try {
      return new Date(iso).toLocaleString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return iso;
    }
  }

  // ─── Splash ───

  function initSplash() {
    setTimeout(() => {
      const splash = $('splash');
      splash.classList.add('fade-out');
      splash.setAttribute('aria-hidden', 'true');
      const app = $('app');
      app.classList.remove('hidden');
      app.setAttribute('aria-hidden', 'false');
      setTimeout(() => splash.classList.add('hidden'), 650);
    }, SPLASH_MS);
  }

  // ─── Photo Handling ───

  function updatePhotoUI() {
    const count = pendingPhotos.length;
    const countEl = $('photo-count');
    countEl.textContent = `${count} / ${MIN_PHOTOS} minimum`;
    countEl.classList.toggle('valid', count >= MIN_PHOTOS);

    const preview = $('photo-preview');
    preview.innerHTML = '';
    pendingPhotos.forEach((dataUrl, index) => {
      const wrap = document.createElement('div');
      wrap.className = 'photo-thumb';
      wrap.setAttribute('role', 'listitem');
      const img = document.createElement('img');
      img.src = dataUrl;
      img.alt = `Vehicle photo ${index + 1}`;
      const del = document.createElement('button');
      del.type = 'button';
      del.className = 'delete-photo';
      del.setAttribute('aria-label', `Remove photo ${index + 1}`);
      del.textContent = '×';
      del.addEventListener('click', (e) => {
        e.preventDefault();
        pendingPhotos.splice(index, 1);
        updatePhotoUI();
        validateForm();
      });
      wrap.appendChild(img);
      wrap.appendChild(del);
      preview.appendChild(wrap);
    });

    validateForm();
  }

  function readFileAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  function compressImage(dataUrl) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        let w = img.naturalWidth || img.width;
        let h = img.naturalHeight || img.height;
        if (w > MAX_PHOTO_WIDTH) {
          h = Math.round((h * MAX_PHOTO_WIDTH) / w);
          w = MAX_PHOTO_WIDTH;
        }
        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          resolve(dataUrl);
          return;
        }
        ctx.drawImage(img, 0, 0, w, h);
        try {
          resolve(canvas.toDataURL('image/jpeg', JPEG_QUALITY));
        } catch {
          resolve(dataUrl);
        }
      };
      img.onerror = () => reject(new Error('image_load_failed'));
      img.src = dataUrl;
    });
  }

  async function handlePhotoInput(e) {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    for (const file of files) {
      const isImage =
        (file.type && file.type.startsWith('image/')) ||
        /\.(jpe?g|png|gif|webp|bmp|heic|heif)$/i.test(file.name || '');
      if (!isImage) continue;
      try {
        const dataUrl = await readFileAsDataURL(file);
        const compressed = await compressImage(dataUrl);
        pendingPhotos.push(compressed);
      } catch {
        showToast('Failed to read image.');
      }
    }
    updatePhotoUI();
  }

  function validateForm() {
    const owner = $('owner-name').value.trim();
    const plate = $('plate-number').value.trim();
    const mobile = $('mobile').value.trim();
    const valid =
      owner.length >= 2 &&
      plate.length >= 2 &&
      mobile.length >= 6 &&
      pendingPhotos.length >= MIN_PHOTOS;
    $('btn-save').disabled = !valid;
    return valid;
  }

  function resetForm() {
    $('plate-form').reset();
    pendingPhotos = [];
    updatePhotoUI();
  }

  // ─── Vehicle List & Search ───

  function renderList(filter = '') {
    const vehicles = loadVehicles();
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? vehicles.filter(
          (v) =>
            v.ownerName.toLowerCase().includes(q) ||
            v.plateNumber.toLowerCase().includes(q)
        )
      : vehicles;

    const list = $('vehicle-list');
    const empty = $('empty-state');
    const countEl = $('vehicle-count');

    countEl.textContent = String(filtered.length);
    list.innerHTML = '';

    if (filtered.length === 0) {
      empty.classList.remove('hidden');
      empty.textContent = q
        ? 'No matches found for your search.'
        : 'No vehicles registered. Tap "ADD NEW PLATE" to begin.';
      return;
    }

    empty.classList.add('hidden');

    filtered.forEach((v) => {
      const card = document.createElement('article');
      card.className = 'vehicle-card';
      card.setAttribute('role', 'listitem');
      card.innerHTML = `
        <div class="plate">${escapeHtml(v.plateNumber)}</div>
        <div class="owner">${escapeHtml(v.ownerName)}</div>
        <div class="meta">
          <span>📱 ${escapeHtml(v.mobile)}</span>
          <span>📷 ${v.photos.length} photo(s)</span>
          <span>🔒 Encrypted</span>
        </div>
      `;
      card.addEventListener('click', () => openDetail(v));
      list.appendChild(card);
    });
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function openDetail(vehicle) {
    const body = $('modal-body');
    const gallery = vehicle.photos
      .map(
        (src, i) =>
          `<img src="${src}" alt="Vehicle photo ${i + 1}" loading="lazy">`
      )
      .join('');

    body.innerHTML = `
      <div class="modal-detail">
        <h3>${escapeHtml(vehicle.ownerName)}</h3>
        <p class="plate-big">${escapeHtml(vehicle.plateNumber)}</p>
        <div class="info-row"><span>Mobile</span><span>${escapeHtml(vehicle.mobile)}</span></div>
        <div class="info-row"><span>Photos stored</span><span>${vehicle.photos.length}</span></div>
        <div class="info-row"><span>Registered</span><span>${formatDate(vehicle.createdAt)}</span></div>
        <div class="info-row"><span>Record ID</span><span>${escapeHtml(vehicle.id.slice(0, 12))}…</span></div>
        <h4 style="margin-top:1rem;color:var(--gold-light);font-size:0.9rem;">Vehicle Photos</h4>
        <div class="modal-gallery">${gallery}</div>
      </div>
    `;

    const modal = $('detail-modal');
    if (typeof modal.showModal === 'function') {
      modal.showModal();
    } else {
      modal.setAttribute('open', '');
    }
  }

  function closeModal() {
    const modal = $('detail-modal');
    if (modal.open) modal.close();
    modal.removeAttribute('open');
  }

  // ─── Save Vehicle ───

  function handleSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();

    if (!validateForm()) {
      showToast(`Fill all fields and add at least ${MIN_PHOTOS} photos.`);
      return;
    }

    const ownerName = $('owner-name').value.trim();
    const plateNumber = $('plate-number').value.trim().toUpperCase();
    const mobile = $('mobile').value.trim();

    const vehicles = loadVehicles();
    const duplicate = vehicles.some(
      (v) => v.plateNumber.toUpperCase() === plateNumber
    );
    if (duplicate) {
      showToast('This plate number is already registered.');
      return;
    }

    const record = {
      id: typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : `sl-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      ownerName,
      plateNumber,
      mobile,
      photos: pendingPhotos.slice(),
      createdAt: new Date().toISOString(),
    };

    const saveBtn = $('btn-save');
    saveBtn.disabled = true;
    saveBtn.textContent = 'SAVING…';

    vehicles.unshift(record);
    const result = saveVehicles(vehicles);

    saveBtn.textContent = 'ADD LIST';

    if (!result.ok) {
      validateForm();
      if (result.error === 'quota') {
        showToast('Storage full. Remove old records or use smaller photos.');
      } else {
        showToast('Save failed. Please try again.');
      }
      console.error('[Vault] Save error:', result.error);
      return;
    }

    $('search-input').value = '';
    resetForm();
    showView('view-home');
    renderList('');

    showToast('✓ Record saved — now in the list.');
  }

  // ─── Event Bindings ───

  function init() {
    initStorage();
    initSplash();

    $('btn-add-plate').addEventListener('click', () => {
      resetForm();
      showView('view-form');
    });

    $('btn-back').addEventListener('click', () => {
      showView('view-home');
    });

    $('photo-input').addEventListener('change', handlePhotoInput);

    ['owner-name', 'plate-number', 'mobile'].forEach((id) => {
      $(id).addEventListener('input', validateForm);
    });

    $('plate-number').addEventListener('input', (e) => {
      e.target.value = e.target.value.toUpperCase();
    });

    $('plate-form').addEventListener('submit', handleSubmit);

    $('btn-save').addEventListener('click', (e) => {
      if ($('btn-save').disabled) {
        e.preventDefault();
        showToast(`Fill all fields and add at least ${MIN_PHOTOS} photos.`);
        return;
      }
    });

    $('search-input').addEventListener('input', (e) => {
      renderList(e.target.value);
    });

    $('modal-close').addEventListener('click', closeModal);
    $('detail-modal').addEventListener('click', (e) => {
      if (e.target === $('detail-modal')) closeModal();
    });

    renderList();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
