/* =============================================
   TAGEBUCH – app.js
   Verschlüsseltes Tagebuch mit GitHub Pages
   ============================================= */

// ─────────────────────────────────────────────
// CRYPTO
// ─────────────────────────────────────────────

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password),
    { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 120000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  );
}

async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(data))
  );
  const combined = new Uint8Array(12 + enc.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(enc), 12);
  // base64 encode safely for large data
  let binary = '';
  combined.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

async function decrypt(b64, key) {
  try {
    const binary = atob(b64);
    const combined = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) combined[i] = binary.charCodeAt(i);
    const iv = combined.slice(0, 12);
    const enc = combined.slice(12);
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, enc);
    return JSON.parse(new TextDecoder().decode(dec));
  } catch { return null; }
}

// ─────────────────────────────────────────────
// STORAGE
// ─────────────────────────────────────────────

const S = {
  get(k)    { const v = localStorage.getItem('diary__' + k); if (!v) return null; try { return JSON.parse(v); } catch { return v; } },
  set(k, v) { localStorage.setItem('diary__' + k, typeof v === 'string' ? v : JSON.stringify(v)); },
  del(k)    { localStorage.removeItem('diary__' + k); },
};

function genId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────

const state = {
  masterKey: null,
  masterPassword: null,
  masterIndex: null,       // { pages: [{id, name, callPassword, editPassword}] }
  page: null,              // { id, key, content }
  editBlocks: [],
};

// ─────────────────────────────────────────────
// UI HELPERS
// ─────────────────────────────────────────────

function show(id) {
  document.querySelectorAll('.screen').forEach(el => el.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}

function showModal(id) { document.getElementById(id).classList.remove('hidden'); }
function hideModal(id) { document.getElementById(id).classList.add('hidden'); }

function showSpinner(text = 'Lädt…') {
  let el = document.getElementById('spinner-overlay');
  el.querySelector('.spinner-text').textContent = text;
  el.classList.remove('hidden');
}
function hideSpinner() { document.getElementById('spinner-overlay').classList.add('hidden'); }

let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

function setError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 4000);
}
function clearError(id) { document.getElementById(id).classList.add('hidden'); }

function escHtml(s) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(s ?? ''));
  return d.innerHTML;
}
function escAttr(s) { return (s ?? '').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Versucht bekannte Share-Links in direkte Bild-URLs umzuwandeln
function normalizeImageUrl(url) {
  if (!url) return url;

  // Google Drive: /file/d/ID/view  →  direkter Download-Link
  const gdMatch = url.match(/drive\.google\.com\/file\/d\/([^/?#]+)/);
  if (gdMatch) return `https://drive.google.com/uc?export=view&id=${gdMatch[1]}`;

  // Google Drive: /open?id=ID
  const gdOpen = url.match(/drive\.google\.com\/open\?id=([^&]+)/);
  if (gdOpen) return `https://drive.google.com/uc?export=view&id=${gdOpen[1]}`;

  return url; // alle anderen URLs unverändert zurückgeben
}

function imgErrorHtml() {
  return `<div class="img-error">
    ⚠️ Bild konnte nicht geladen werden.<br>
    <small>Direkte Bild-URLs funktionieren – Share-Links von OneDrive/Google Drive meist nicht.<br>
    Empfehlung: <strong>imgur.com</strong> (kostenlos, direkte Links)</small>
  </div>`;
}

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────

async function init() {
  const masterHash = S.get('master_hash');
  show(masterHash ? 'login-screen' : 'setup-screen');
}

// ─────────────────────────────────────────────
// SETUP (Ersteinrichtung)
// ─────────────────────────────────────────────

async function setupMaster() {
  const pw  = document.getElementById('setup-pw').value;
  const pw2 = document.getElementById('setup-pw2').value;
  clearError('setup-error');

  if (pw.length < 4)  return setError('setup-error', 'Passwort muss mindestens 4 Zeichen haben.');
  if (pw !== pw2)     return setError('setup-error', 'Passwörter stimmen nicht überein.');

  showSpinner('Einrichten…');
  const hash = await sha256hex(pw);
  const salt = genId();
  S.set('master_hash', hash);
  S.set('master_salt', salt);

  const key = await deriveKey(pw, salt);
  const enc = await encrypt({ pages: [] }, key);
  S.set('master_index', enc);
  S.set('page_ids', []);

  hideSpinner();
  document.getElementById('setup-pw').value = '';
  document.getElementById('setup-pw2').value = '';
  show('login-screen');
  toast('Tagebuch eingerichtet!');
}

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────

async function loginMain() {
  const pw = document.getElementById('login-pw').value;
  document.getElementById('login-pw').value = '';
  await authenticate(pw, 'login-error');
}

async function loginSecondary() {
  const pw = document.getElementById('secondary-pw').value;
  document.getElementById('secondary-pw').value = '';
  await authenticate(pw, 'secondary-error');
}

async function authenticate(pw, errorId) {
  clearError(errorId);
  if (!pw) return setError(errorId, 'Bitte ein Passwort eingeben.');

  showSpinner('Prüfe Passwort…');

  // Master?
  const masterHash = S.get('master_hash');
  const inputHash  = await sha256hex(pw);

  if (inputHash === masterHash) {
    const salt = S.get('master_salt');
    const key  = await deriveKey(pw, salt);
    const enc  = S.get('master_index');
    const idx  = await decrypt(enc, key);
    hideSpinner();
    if (!idx) return setError(errorId, 'Fehler beim Lesen des Indexes.');
    state.masterKey      = key;
    state.masterPassword = pw;
    state.masterIndex    = idx;
    hideModal('secondary-modal');
    renderMasterView();
    show('master-view');
    return;
  }

  // Aufruf-Passwort einer Seite?
  const pageIds = S.get('page_ids') || [];
  for (const id of pageIds) {
    const ph = S.get(`page_${id}_hash`);
    if (ph && ph === inputHash) {
      await openPage(id, pw);
      hideSpinner();
      hideModal('secondary-modal');
      return;
    }
  }

  hideSpinner();
  setError(errorId, 'Falsches Passwort.');
}

async function openPage(id, pw) {
  const salt = S.get(`page_${id}_salt`);
  const key  = await deriveKey(pw, salt);
  const enc  = S.get(`page_${id}_content`);

  let content;
  if (enc) {
    content = await decrypt(enc, key);
    if (!content) { toast('Fehler beim Entschlüsseln.'); return; }
  } else {
    content = { title: S.get(`page_${id}_name`) || 'Tagebuch', blocks: [] };
  }

  state.page = { id, password: pw, key, content };
  renderPageView(content);
  show('page-view');
}

// ─────────────────────────────────────────────
// PAGE VIEW
// ─────────────────────────────────────────────

function renderPageView(content) {
  document.getElementById('page-title').textContent = content.title || 'Tagebuch';
  const wrap = document.getElementById('page-content');
  wrap.innerHTML = '';

  if (!content.blocks?.length) {
    wrap.innerHTML = '<div class="empty-state"><p>Diese Seite ist noch leer.</p><p>Klicke auf <strong>Bearbeiten</strong>, um Inhalte hinzuzufügen.</p></div>';
    return;
  }

  content.blocks.forEach(b => wrap.appendChild(makeViewBlock(b)));
}

function makeViewBlock(block) {
  const el = document.createElement('div');
  el.className = 'content-block';

  if (block.type === 'text') {
    el.classList.add('text-block');
    const dateHtml = block.date ? `<div class="block-date">${escHtml(block.date)}</div>` : '';
    el.innerHTML = `${dateHtml}<div class="text-content">${escHtml(block.content ?? '').replace(/\n/g,'<br>')}</div>`;

  } else if (block.type === 'image') {
    el.classList.add('image-block');
    const src = normalizeImageUrl(block.content ?? '');
    const alt = block.alt ?? '';
    const errHandler = `this.parentElement.innerHTML=imgErrorHtml()`;
    if (alt) {
      el.innerHTML = `<figure><img src="${escAttr(src)}" alt="${escAttr(alt)}" loading="lazy" onerror="${errHandler}"><figcaption>${escHtml(alt)}</figcaption></figure>`;
    } else {
      el.innerHTML = `<img src="${escAttr(src)}" alt="" loading="lazy" onerror="${errHandler}">`;
    }

  } else if (block.type === 'video') {
    el.classList.add('video-block');
    const src = block.content ?? '';
    if (!src) return el;

    const ytMatch = src.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([^&\n?#]+)/);
    const vimeoMatch = src.match(/vimeo\.com\/(\d+)/);

    if (ytMatch) {
      el.innerHTML = `<div class="video-embed"><iframe src="https://www.youtube.com/embed/${escAttr(ytMatch[1])}" allowfullscreen loading="lazy"></iframe></div>`;
    } else if (vimeoMatch) {
      el.innerHTML = `<div class="video-embed"><iframe src="https://player.vimeo.com/video/${escAttr(vimeoMatch[1])}" allowfullscreen loading="lazy"></iframe></div>`;
    } else {
      el.innerHTML = `<video controls preload="metadata"><source src="${escAttr(src)}"><p>Video kann nicht angezeigt werden.</p></video>`;
    }
  }

  return el;
}

// ─────────────────────────────────────────────
// MASTER VIEW
// ─────────────────────────────────────────────

function renderMasterView() {
  const idx  = state.masterIndex;
  const wrap = document.getElementById('master-content');
  wrap.innerHTML = '';

  if (!idx.pages?.length) {
    wrap.innerHTML = '<div class="empty-state"><p>Noch keine Seiten vorhanden.</p><p>Klicke auf <strong>+ Seite</strong>, um eine neue Seite zu erstellen.</p></div>';
    return;
  }

  const label = document.createElement('div');
  label.className = 'section-label';
  label.textContent = `${idx.pages.length} Seite${idx.pages.length !== 1 ? 'n' : ''}`;
  wrap.appendChild(label);

  idx.pages.forEach(page => {
    const el = document.createElement('div');
    el.className = 'master-page-card';
    el.innerHTML = `
      <div class="master-page-info">
        <h3>${escHtml(page.name)}</h3>
        <div class="password-display">
          <span class="password-label">Aufruf:</span>
          <span class="password-value" title="Klicken zum Kopieren" onclick="copyPw('${escAttr(page.callPassword)}')">${escHtml(page.callPassword)}</span>
        </div>
        <div class="password-display">
          <span class="password-label">Bearbeitung:</span>
          <span class="password-value" title="Klicken zum Kopieren" onclick="copyPw('${escAttr(page.editPassword)}')">${escHtml(page.editPassword)}</span>
        </div>
      </div>
      <div class="master-page-actions">
        <button class="btn-secondary btn-small" onclick="masterOpenPage('${escAttr(page.id)}')">Öffnen</button>
        <button class="btn-danger btn-small" onclick="masterDeletePage('${escAttr(page.id)}')">Löschen</button>
      </div>`;
    wrap.appendChild(el);
  });
}

function copyPw(pw) {
  navigator.clipboard?.writeText(pw).then(() => toast('Passwort kopiert!'));
}

async function masterOpenPage(id) {
  const page = state.masterIndex.pages.find(p => p.id === id);
  if (!page) return;
  showSpinner('Öffne Seite…');
  await openPage(id, page.callPassword);
  hideSpinner();
}

async function masterDeletePage(id) {
  const page = state.masterIndex.pages.find(p => p.id === id);
  if (!page) return;
  if (!confirm(`Seite "${page.name}" wirklich löschen?\nDies kann nicht rückgängig gemacht werden!`)) return;

  state.masterIndex.pages = state.masterIndex.pages.filter(p => p.id !== id);
  ['hash','salt','content','name','edit_hash'].forEach(k => S.del(`page_${id}_${k}`));
  const ids = (S.get('page_ids') || []).filter(x => x !== id);
  S.set('page_ids', ids);
  await saveMasterIndex();
  renderMasterView();
  toast('Seite gelöscht.');
}

async function saveMasterIndex() {
  const enc = await encrypt(state.masterIndex, state.masterKey);
  S.set('master_index', enc);
}

// ─────────────────────────────────────────────
// ADD PAGE MODAL
// ─────────────────────────────────────────────

function showAddPage() { showModal('add-page-modal'); }
function closeAddPage() {
  hideModal('add-page-modal');
  document.getElementById('new-page-name').value    = '';
  document.getElementById('new-page-call-pw').value = '';
  document.getElementById('new-page-edit-pw').value = '';
  clearError('add-page-error');
}

async function createPage() {
  const name   = document.getElementById('new-page-name').value.trim();
  const callPw = document.getElementById('new-page-call-pw').value;
  const editPw = document.getElementById('new-page-edit-pw').value;
  clearError('add-page-error');

  if (!name)          return setError('add-page-error', 'Bitte einen Seitennamen eingeben.');
  if (callPw.length < 4) return setError('add-page-error', 'Aufruf-Passwort muss mindestens 4 Zeichen haben.');
  if (editPw.length < 4) return setError('add-page-error', 'Änderungs-Passwort muss mindestens 4 Zeichen haben.');

  showSpinner('Seite erstellen…');
  const id       = genId();
  const callHash = await sha256hex(callPw);
  const editHash = await sha256hex(editPw);
  const salt     = genId();
  const key      = await deriveKey(callPw, salt);
  const enc      = await encrypt({ title: name, blocks: [] }, key);

  S.set(`page_${id}_hash`,      callHash);
  S.set(`page_${id}_salt`,      salt);
  S.set(`page_${id}_name`,      name);
  S.set(`page_${id}_content`,   enc);
  S.set(`page_${id}_edit_hash`, editHash);

  const ids = S.get('page_ids') || [];
  ids.push(id);
  S.set('page_ids', ids);

  state.masterIndex.pages.push({ id, name, callPassword: callPw, editPassword: editPw });
  await saveMasterIndex();

  hideSpinner();
  closeAddPage();
  renderMasterView();
  toast(`Seite "${name}" erstellt.`);
}

// ─────────────────────────────────────────────
// EDIT FLOW
// ─────────────────────────────────────────────

function requestEdit() {
  document.getElementById('edit-pw-input').value = '';
  clearError('edit-pw-error');
  showModal('edit-pw-modal');
  setTimeout(() => document.getElementById('edit-pw-input').focus(), 80);
}

function closeEditPwModal() { hideModal('edit-pw-modal'); }

async function verifyEditPw() {
  const pw = document.getElementById('edit-pw-input').value;
  clearError('edit-pw-error');

  const inputHash  = await sha256hex(pw);
  // Änderungs-Passwort der Seite; falls noch keins gesetzt (alte Seiten) → Aufruf-Hash als Fallback
  const editHash   = S.get(`page_${state.page.id}_edit_hash`) || S.get(`page_${state.page.id}_hash`);
  const masterHash = S.get('master_hash');

  if (inputHash === editHash || inputHash === masterHash) {
    closeEditPwModal();
    enterEdit();
  } else {
    setError('edit-pw-error', 'Falsches Änderungs-Passwort.');
  }
}

function enterEdit() {
  state.editBlocks = JSON.parse(JSON.stringify(state.page.content.blocks ?? []));
  renderEditView();
  show('edit-view');
}

function cancelEdit() {
  show('page-view');
}

async function saveEdit() {
  const titleEl = document.getElementById('edit-title-input');
  const title   = titleEl?.value?.trim() || state.page.content.title || 'Tagebuch';
  const content = { title, blocks: state.editBlocks };

  showSpinner('Speichere…');
  const enc = await encrypt(content, state.page.key);
  S.set(`page_${state.page.id}_content`, enc);
  S.set(`page_${state.page.id}_name`, title);

  // sync name in master index
  if (state.masterIndex) {
    const p = state.masterIndex.pages.find(p => p.id === state.page.id);
    if (p) { p.name = title; await saveMasterIndex(); }
  }

  state.page.content = content;
  hideSpinner();
  renderPageView(content);
  show('page-view');
  toast('Gespeichert!');
}

// ─────────────────────────────────────────────
// EDIT VIEW RENDER
// ─────────────────────────────────────────────

function renderEditView() {
  const wrap = document.getElementById('edit-content');
  wrap.innerHTML = '';

  // Title
  const titleWrap = document.createElement('div');
  titleWrap.className = 'edit-title-wrapper';
  titleWrap.innerHTML = `<input type="text" id="edit-title-input" class="edit-title-input" value="${escAttr(state.page.content.title ?? '')}" placeholder="Seitentitel">`;
  wrap.appendChild(titleWrap);

  state.editBlocks.forEach((block, i) => wrap.appendChild(makeEditBlock(block, i)));
}

function makeEditBlock(block, i) {
  const total = state.editBlocks.length;
  const el = document.createElement('div');
  el.className = 'edit-block';

  const controls = `
    <div class="block-controls">
      ${i > 0         ? `<button class="btn-ghost btn-tiny" onclick="moveBlock(${i},-1)" title="Nach oben">↑</button>` : ''}
      ${i < total - 1 ? `<button class="btn-ghost btn-tiny" onclick="moveBlock(${i}, 1)" title="Nach unten">↓</button>` : ''}
      <button class="btn-danger btn-tiny" onclick="removeBlock(${i})" title="Löschen">✕</button>
    </div>`;

  if (block.type === 'text') {
    el.innerHTML = `
      <div class="edit-block-header"><span class="block-type-badge">📝 Text</span>${controls}</div>
      <textarea class="block-textarea" rows="7" placeholder="Text eingeben…" oninput="updateBlock(${i},'content',this.value)">${escHtml(block.content ?? '')}</textarea>
      <input class="block-input" type="text" placeholder="Datum (optional, z.B. 28.06.2026)" oninput="updateBlock(${i},'date',this.value)" value="${escAttr(block.date ?? '')}">`;

  } else if (block.type === 'image') {
    const isData = (block.content ?? '').startsWith('data:');
    el.innerHTML = `
      <div class="edit-block-header"><span class="block-type-badge">🖼️ Bild</span>${controls}</div>
      <div class="image-input-group">
        <input class="block-input" type="text" placeholder="Direkte Bild-URL (imgur.com empfohlen)"
          value="${isData ? '' : escAttr(block.content ?? '')}"
          oninput="updateBlock(${i},'content',this.value);refreshPreview(${i})">
        <div class="url-hint">✅ funktioniert: imgur.com, direkte .jpg/.png-Links&nbsp;&nbsp;⚠️ funktioniert meist nicht: OneDrive/Google Drive Share-Links</div>
        <div class="or-divider">ODER</div>
        <label class="file-upload-btn">📁 Bild hochladen (max. 5 MB, nur auf diesem Gerät)<input type="file" accept="image/*" style="display:none" onchange="uploadImage(event,${i})"></label>
      </div>
      <input class="block-input" type="text" placeholder="Bildunterschrift (optional)"
        oninput="updateBlock(${i},'alt',this.value)" value="${escAttr(block.alt ?? '')}">
      <div id="preview-${i}" class="block-preview">
        ${block.content ? `<img src="${escAttr(normalizeImageUrl(block.content))}" class="preview-img" alt="" onerror="this.outerHTML=imgErrorHtml()">` : '<div class="no-preview">Kein Bild ausgewählt</div>'}
      </div>`;

  } else if (block.type === 'video') {
    const isData = (block.content ?? '').startsWith('data:');
    el.innerHTML = `
      <div class="edit-block-header"><span class="block-type-badge">🎥 Video</span>${controls}</div>
      <div class="image-input-group">
        <input class="block-input" type="text" placeholder="Video-URL (YouTube, Vimeo, OneDrive…)"
          value="${isData ? '' : escAttr(block.content ?? '')}"
          oninput="updateBlock(${i},'content',this.value);refreshVideoPreview(${i})">
        <div class="or-divider">ODER</div>
        <label class="file-upload-btn">📁 Video hochladen (max. 50 MB)<input type="file" accept="video/*" style="display:none" onchange="uploadVideo(event,${i})"></label>
      </div>
      <div id="preview-${i}" class="block-preview">
        ${block.content
          ? `<div class="video-preview-label">✅ Video gesetzt</div>`
          : '<div class="no-preview">Kein Video ausgewählt</div>'}
      </div>`;
  }

  return el;
}

function updateBlock(i, field, val) { state.editBlocks[i][field] = val; }

function moveBlock(i, dir) {
  const j = i + dir;
  if (j < 0 || j >= state.editBlocks.length) return;
  [state.editBlocks[i], state.editBlocks[j]] = [state.editBlocks[j], state.editBlocks[i]];
  renderEditView();
}

function removeBlock(i) {
  if (!confirm('Diesen Block wirklich entfernen?')) return;
  state.editBlocks.splice(i, 1);
  renderEditView();
}

function addBlock(type) {
  state.editBlocks.push({ type, content: '', ...(type==='text' ? {date:''} : {}), ...(type==='image' ? {alt:''} : {}) });
  renderEditView();
  setTimeout(() => {
    const wrap = document.getElementById('edit-content');
    wrap.lastElementChild?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

function refreshPreview(i) {
  const wrap = document.getElementById(`preview-${i}`);
  if (!wrap) return;
  const src = normalizeImageUrl(state.editBlocks[i]?.content ?? '');
  wrap.innerHTML = src
    ? `<img src="${escAttr(src)}" class="preview-img" alt="" onerror="this.outerHTML=imgErrorHtml()">`
    : '<div class="no-preview">Kein Bild ausgewählt</div>';
}

function refreshVideoPreview(i) {
  const wrap = document.getElementById(`preview-${i}`);
  if (!wrap) return;
  const src = state.editBlocks[i]?.content ?? '';
  wrap.innerHTML = src
    ? '<div class="video-preview-label">✅ Video gesetzt</div>'
    : '<div class="no-preview">Kein Video ausgewählt</div>';
}

function uploadImage(evt, i) {
  const file = evt.target.files[0];
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) {
    toast('Bild zu groß (max. 5 MB). Bitte verwende eine URL.');
    return;
  }
  const reader = new FileReader();
  reader.onload = e => {
    state.editBlocks[i].content = e.target.result;
    refreshPreview(i);
    // Clear URL input
    evt.target.closest('.image-input-group')?.querySelector('input[type=text]')
      && (evt.target.closest('.image-input-group').querySelector('input[type=text]').value = '');
  };
  reader.readAsDataURL(file);
}

function uploadVideo(evt, i) {
  const file = evt.target.files[0];
  if (!file) return;
  if (file.size > 50 * 1024 * 1024) {
    toast('Video zu groß (max. 50 MB). Bitte verwende eine URL (z.B. OneDrive).');
    return;
  }
  const reader = new FileReader();
  reader.onload = e => {
    state.editBlocks[i].content = e.target.result;
    refreshVideoPreview(i);
  };
  reader.readAsDataURL(file);
}

// ─────────────────────────────────────────────
// NAVIGATION / LOGOUT
// ─────────────────────────────────────────────

function logout() {
  state.masterKey = null;
  state.masterPassword = null;
  state.masterIndex = null;
  state.page = null;
  state.editBlocks = [];
  document.getElementById('login-pw').value = '';
  show('login-screen');
}

function resetAll() {
  showModal('reset-confirm-modal');
}

function closeResetModal() {
  hideModal('reset-confirm-modal');
}

function doReset() {
  Object.keys(localStorage)
    .filter(k => k.startsWith('diary__'))
    .forEach(k => localStorage.removeItem(k));
  location.reload();
}

function showSecondaryLogin() {
  clearError('secondary-error');
  showModal('secondary-modal');
  setTimeout(() => document.getElementById('secondary-pw').focus(), 80);
}
function closeSecondaryLogin() {
  hideModal('secondary-modal');
  document.getElementById('secondary-pw').value = '';
}

// ─────────────────────────────────────────────
// MASTER PASSWORD CHANGE
// ─────────────────────────────────────────────

function showChangeMasterPw() {
  document.getElementById('change-master-old').value  = '';
  document.getElementById('change-master-new').value  = '';
  document.getElementById('change-master-new2').value = '';
  clearError('change-master-error');
  showModal('change-master-modal');
}
function closeChangeMasterPw() { hideModal('change-master-modal'); }

async function doChangeMasterPw() {
  const oldPw  = document.getElementById('change-master-old').value;
  const newPw  = document.getElementById('change-master-new').value;
  const newPw2 = document.getElementById('change-master-new2').value;
  clearError('change-master-error');

  const oldHash = await sha256hex(oldPw);
  if (oldHash !== S.get('master_hash')) return setError('change-master-error', 'Altes Passwort falsch.');
  if (newPw.length < 4) return setError('change-master-error', 'Neues Passwort zu kurz (min. 4 Zeichen).');
  if (newPw !== newPw2) return setError('change-master-error', 'Neue Passwörter stimmen nicht überein.');

  showSpinner('Passwort ändern…');
  const newHash = await sha256hex(newPw);
  const newSalt = genId();
  const newKey  = await deriveKey(newPw, newSalt);
  const enc     = await encrypt(state.masterIndex, newKey);

  S.set('master_hash',  newHash);
  S.set('master_salt',  newSalt);
  S.set('master_index', enc);

  state.masterKey      = newKey;
  state.masterPassword = newPw;

  hideSpinner();
  closeChangeMasterPw();
  toast('Master-Passwort geändert.');
}

// ─────────────────────────────────────────────
// PAGE SETTINGS (Passwörter ändern)
// ─────────────────────────────────────────────

function showPageSettings() {
  ['chg-call-master','chg-call-new','chg-call-new2',
   'chg-edit-old','chg-edit-new','chg-edit-new2'].forEach(id => {
    document.getElementById(id).value = '';
  });
  clearError('chg-call-error');
  clearError('chg-edit-error');
  showModal('page-settings-modal');
}
function closePageSettings() { hideModal('page-settings-modal'); }

async function doChangeCallPw() {
  const masterPw = document.getElementById('chg-call-master').value;
  const newPw    = document.getElementById('chg-call-new').value;
  const newPw2   = document.getElementById('chg-call-new2').value;
  clearError('chg-call-error');

  const masterHash = S.get('master_hash');
  if (await sha256hex(masterPw) !== masterHash) return setError('chg-call-error', 'Master-Passwort falsch.');
  if (newPw.length < 4) return setError('chg-call-error', 'Passwort zu kurz (min. 4 Zeichen).');
  if (newPw !== newPw2) return setError('chg-call-error', 'Passwörter stimmen nicht überein.');

  showSpinner('Aufruf-Passwort ändern…');
  const id      = state.page.id;
  const newHash = await sha256hex(newPw);
  const newSalt = genId();
  const newKey  = await deriveKey(newPw, newSalt);
  const enc     = await encrypt(state.page.content, newKey);

  S.set(`page_${id}_hash`,    newHash);
  S.set(`page_${id}_salt`,    newSalt);
  S.set(`page_${id}_content`, enc);
  state.page.key = newKey;

  if (state.masterIndex) {
    const p = state.masterIndex.pages.find(p => p.id === id);
    if (p) { p.callPassword = newPw; await saveMasterIndex(); }
  }

  hideSpinner();
  document.getElementById('chg-call-master').value = '';
  document.getElementById('chg-call-new').value    = '';
  document.getElementById('chg-call-new2').value   = '';
  toast('Aufruf-Passwort geändert.');
}

async function doChangeEditPw() {
  const oldPw  = document.getElementById('chg-edit-old').value;
  const newPw  = document.getElementById('chg-edit-new').value;
  const newPw2 = document.getElementById('chg-edit-new2').value;
  clearError('chg-edit-error');

  const inputHash  = await sha256hex(oldPw);
  const editHash   = S.get(`page_${state.page.id}_edit_hash`) || S.get(`page_${state.page.id}_hash`);
  const masterHash = S.get('master_hash');

  if (inputHash !== editHash && inputHash !== masterHash)
    return setError('chg-edit-error', 'Aktuelles Änderungs- oder Master-Passwort falsch.');
  if (newPw.length < 4) return setError('chg-edit-error', 'Passwort zu kurz (min. 4 Zeichen).');
  if (newPw !== newPw2) return setError('chg-edit-error', 'Passwörter stimmen nicht überein.');

  showSpinner('Änderungs-Passwort ändern…');
  const newEditHash = await sha256hex(newPw);
  S.set(`page_${state.page.id}_edit_hash`, newEditHash);

  if (state.masterIndex) {
    const p = state.masterIndex.pages.find(p => p.id === state.page.id);
    if (p) { p.editPassword = newPw; await saveMasterIndex(); }
  }

  hideSpinner();
  document.getElementById('chg-edit-old').value  = '';
  document.getElementById('chg-edit-new').value  = '';
  document.getElementById('chg-edit-new2').value = '';
  toast('Änderungs-Passwort geändert.');
}

// ─────────────────────────────────────────────
// KEYBOARD SHORTCUTS
// ─────────────────────────────────────────────

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    // Close any open modal
    ['secondary-modal','edit-pw-modal','add-page-modal','change-master-modal','page-settings-modal'].forEach(hideModal);
  }
});

function onKey(e, fn) { if (e.key === 'Enter') fn(); }

// ─────────────────────────────────────────────
// BOOTSTRAP
// ─────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', init);
