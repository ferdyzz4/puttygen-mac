/* PuTTYgen untuk Mac — logika tampilan.
   Semua operasi kunci dikirim ke sisi Swift (window.webkit.messageHandlers.api),
   yang menjalankan puttygen. */
(() => {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];
  const icons = () => lucide.createIcons({ icons: lucide.icons });

  const PPK_DEFAULT = { version: 3, kdf: 'argon2id', memory: 8192, mode: 'time', time: 100, passes: 13, parallelism: 1 };

  const state = {
    key: null,            // { pubBody, comment, fingerprint, algorithm, bits, isSSH1, hasCert }
    type: 'eddsa',
    bits: { rsa: 2048, dsa: 2048, rsa1: 2048 },
    curve: 'nistp256',
    edcurve: 'ed25519',
    primes: 'probable',
    strong: false,
    fp: 'sha256',
    ppk: { ...PPK_DEFAULT },
    busy: false,
  };

  // ---------- Penyimpanan preferensi (hanya kenyamanan, boleh gagal) ----------
  const PREF_KEY = 'puttygen-prefs';
  function loadPrefs() {
    try {
      const p = JSON.parse(localStorage.getItem(PREF_KEY) || '{}');
      for (const k of ['type', 'curve', 'edcurve', 'primes', 'strong', 'fp']) if (k in p) state[k] = p[k];
      if (p.bits) Object.assign(state.bits, p.bits);
      if (p.ppk) state.ppk = { ...PPK_DEFAULT, ...p.ppk };
    } catch (_) { /* abaikan */ }
  }
  function savePrefs() {
    try {
      const { type, bits, curve, edcurve, primes, strong, fp, ppk } = state;
      localStorage.setItem(PREF_KEY, JSON.stringify({ type, bits, curve, edcurve, primes, strong, fp, ppk }));
    } catch (_) { /* abaikan */ }
  }

  // ---------- Jembatan ke Swift ----------
  const native = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.api;

  async function api(cmd, args = {}) {
    const r = native ? await native.postMessage({ cmd, args }) : await mockApi(cmd, args);
    if (!r || !r.ok) {
      const e = new Error((r && r.error) || 'Terjadi kesalahan.');
      e.code = r && r.code;
      throw e;
    }
    return r;
  }

  function syncMenu() {
    const k = state.key;
    api('syncMenu', {
      busy: state.busy, hasKey: !!k, isSSH1: !!(k && k.isSSH1), algorithm: k ? k.algorithm : '',
      hasCert: !!(k && k.hasCert), type: state.type, primes: state.primes, strong: state.strong, fp: state.fp,
    }).catch(() => {});
  }

  // ---------- Umpan balik UI ----------
  function setBusy(on, text = 'Memproses…', sub = '') {
    state.busy = on;
    $('#busyText').textContent = text;
    $('#busySub').textContent = sub;
    $('#busy').classList.toggle('d-none', !on);
    updateEnabled();
    syncMenu();
  }

  function toast(text, kind = 'success', path = null) {
    const el = document.createElement('div');
    el.className = 'toast align-items-center border-0 shadow';
    const icon = kind === 'success' ? 'circle-check' : 'info';
    const color = kind === 'success' ? 'text-success' : 'text-primary';
    el.innerHTML = `<div class="d-flex"><div class="toast-body d-flex gap-2 align-items-start">
        <i data-lucide="${icon}" class="icon-sm ${color} mt-1"></i><div class="small"></div></div>
        <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
    el.querySelector('.small').textContent = text;
    if (path) {
      const a = document.createElement('a');
      a.href = '#';
      a.className = 'd-block mt-1 text-decoration-none';
      a.textContent = 'Tampilkan di Finder';
      a.addEventListener('click', (ev) => { ev.preventDefault(); api('reveal', { path }).catch(() => {}); });
      el.querySelector('.small').appendChild(a);
    }
    $('#toasts').appendChild(el);
    icons();
    const t = new bootstrap.Toast(el, { delay: 4000 });
    el.addEventListener('hidden.bs.toast', () => el.remove());
    t.show();
  }

  const msgModal = new bootstrap.Modal('#msgModal');
  let msgResolve = null;
  /** kind: error | warning | info | question */
  function message({ title, text = '', pre = '', kind = 'info', okText = 'OK', cancel = false }) {
    const styles = {
      error: ['circle-x', 'bg-danger-subtle text-danger-emphasis', 'btn-danger'],
      warning: ['triangle-alert', 'bg-warning-subtle text-warning-emphasis', 'btn-primary'],
      info: ['info', 'bg-primary-subtle text-primary-emphasis', 'btn-primary'],
      question: ['circle-help', 'bg-primary-subtle text-primary-emphasis', 'btn-primary'],
    }[kind];
    $('#msgIcon').className = 'msg-icon ' + styles[1];
    $('#msgIcon').innerHTML = `<i data-lucide="${styles[0]}"></i>`;
    $('#msgTitle').textContent = title;
    $('#msgText').textContent = text;
    $('#msgPre').textContent = pre;
    $('#msgPre').classList.toggle('d-none', !pre);
    $('#msgOk').textContent = okText;
    $('#msgOk').className = 'btn ' + styles[2];
    $('#msgCancel').classList.toggle('d-none', !cancel);
    icons();
    return new Promise((resolve) => {
      msgResolve = resolve;
      msgModal.show();
    });
  }
  $('#msgOk').addEventListener('click', () => { const r = msgResolve; msgResolve = null; msgModal.hide(); r && r(true); });
  $('#msgCancel').addEventListener('click', () => msgModal.hide());
  $('#msgModal').addEventListener('hidden.bs.modal', () => { const r = msgResolve; msgResolve = null; r && r(false); });
  $('#msgModal').addEventListener('shown.bs.modal', () => $('#msgOk').focus());

  const showError = (err, title = 'Terjadi kesalahan') =>
    message({ title, text: err.message || String(err), kind: 'error' });

  // ---------- Tampilan kunci ----------
  function publicText() {
    const k = state.key;
    if (!k) return '';
    const c = $('#comment').value;
    return c ? `${k.pubBody} ${c}` : k.pubBody;
  }

  function renderKey() {
    const k = state.key;
    $('#keyEmpty').classList.toggle('d-none', !!k);
    $('#keyPanel').classList.toggle('d-none', !k);
    const badges = $('#keyBadges');
    badges.innerHTML = '';
    if (k) {
      const algo = k.algorithm.replace('-cert-v01@openssh.com', '');
      const add = (html, cls) => {
        const s = document.createElement('span');
        s.className = 'badge rounded-pill ' + cls;
        s.innerHTML = html;
        badges.appendChild(s);
      };
      add('', 'text-bg-primary'); badges.lastChild.textContent = algo;
      add('', 'text-bg-secondary'); badges.lastChild.textContent = `${k.bits} bit`;
      if (k.hasCert) add('<i data-lucide="award" class="icon-sm"></i> Sertifikat', 'text-bg-warning');
      $('#pubLabel').textContent = k.isSSH1
        ? 'Public key SSH-1 untuk ditempel ke file authorized_keys:'
        : 'Public key untuk ditempel ke file authorized_keys OpenSSH:';
      $('#pubkey').value = publicText();
      $('#fingerprint').value = k.fingerprint;
      $('#fpType').value = state.fp;
      $('#fpType').disabled = k.isSSH1;
      for (const o of $('#fpType').options) o.disabled = o.value.endsWith('-cert') && !k.hasCert;
    }
    icons();
    updateEnabled();
    syncMenu();
  }

  function setKey(key, { passphrase = '' } = {}) {
    state.key = key;
    $('#comment').value = key.comment;
    $('#pass1').value = passphrase;
    $('#pass2').value = passphrase;
    $('#pass2').classList.remove('is-invalid');
    renderKey();
    // Tampilkan fingerprint sesuai jenis yang dipilih (puttygen mengembalikan SHA256).
    if (state.fp !== 'sha256' && !key.isSSH1) refreshFingerprint();
  }

  async function refreshFingerprint() {
    if (!state.key || state.key.isSSH1) return;
    let type = state.fp;
    if (type.endsWith('-cert') && !state.key.hasCert) type = type.replace('-cert', '');
    try {
      const r = await api('fingerprint', { type });
      state.key.fingerprint = r.fingerprint;
      $('#fingerprint').value = r.fingerprint;
    } catch (e) { showError(e); }
  }

  function updateEnabled() {
    const k = state.key;
    const b = state.busy;
    $$('.needs-key').forEach((el) => { el.disabled = !k || b; });
    const can = {
      import: !b,
      exportOpenSSH: !!k && !k.isSSH1,
      exportOpenSSHNew: !!k && !k.isSSH1,
      exportSshcom: !!k && ['ssh-rsa', 'ssh-dss'].includes(k.algorithm),
      addCert: !!k && !k.isSSH1,
      removeCert: !!k && k.hasCert,
      certInfo: !!k && k.hasCert,
    };
    $$('.dropdown-item[data-action]').forEach((a) => a.classList.toggle('disabled', !can[a.dataset.action]));
  }

  // ---------- Parameter pembuatan kunci ----------
  function renderParams() {
    const t = state.type;
    $(`#t-${t}`).checked = true;
    const hasBits = ['rsa', 'dsa', 'rsa1'].includes(t);
    $('#bitsRow').classList.toggle('d-none', !hasBits);
    $('#curveRow').classList.toggle('d-none', t !== 'ecdsa');
    $('#edRow').classList.toggle('d-none', t !== 'eddsa');
    $('#primeRow').classList.toggle('d-none', !hasBits);
    $('#strongRow').classList.toggle('d-none', t === 'dsa');
    if (hasBits) $('#bits').value = state.bits[t];
    $('#curve').value = state.curve;
    $('#edcurve').value = state.edcurve;
    $('#primes').value = state.primes;
    $('#strong').checked = state.strong;
    syncMenu();
  }

  function setType(t) { state.type = t; savePrefs(); renderParams(); }

  $$('input[name="ktype"]').forEach((r) => r.addEventListener('change', () => setType(r.value)));
  $('#bits').addEventListener('input', () => {
    const v = parseInt($('#bits').value, 10);
    if (!Number.isNaN(v)) { state.bits[state.type] = v; savePrefs(); }
  });
  $$('.bits-preset').forEach((b) => b.addEventListener('click', () => {
    state.bits[state.type] = +b.dataset.bits;
    $('#bits').value = b.dataset.bits;
    savePrefs();
  }));
  $('#curve').addEventListener('change', () => { state.curve = $('#curve').value; savePrefs(); });
  $('#edcurve').addEventListener('change', () => { state.edcurve = $('#edcurve').value; savePrefs(); });
  $('#primes').addEventListener('change', () => { state.primes = $('#primes').value; savePrefs(); syncMenu(); });
  $('#strong').addEventListener('change', () => { state.strong = $('#strong').checked; savePrefs(); syncMenu(); });

  // ---------- Aksi ----------
  async function generate() {
    if (state.busy) return;
    const t = state.type;
    const args = { type: t, curve: t === 'eddsa' ? state.edcurve : state.curve, primes: state.primes, strong: state.strong };
    if (['rsa', 'dsa', 'rsa1'].includes(t)) {
      const bits = parseInt($('#bits').value, 10);
      if (Number.isNaN(bits) || bits < 256) {
        return message({ title: 'Jumlah bit tidak valid', text: 'PuTTYgen tidak akan membuat kunci yang lebih kecil dari 256 bit.', kind: 'error' });
      }
      if (bits < 2048) {
        const ok = await message({ title: 'Kunci terlalu pendek', kind: 'warning', cancel: true, okText: 'Tetap buat',
          text: `Kunci yang lebih pendek dari 2048 bit tidak disarankan.\nYakin ingin membuat kunci ${bits} bit?` });
        if (!ok) return;
      }
      args.bits = bits;
    }
    const label = { rsa: 'RSA', dsa: 'DSA', ecdsa: 'ECDSA', eddsa: 'EdDSA', rsa1: 'SSH-1 RSA' }[t];
    const slow = args.primes && args.primes !== 'probable' ? 'Proven primes bisa memakan waktu lama.' : '';
    setBusy(true, `Membuat kunci ${label}…`, slow);
    try {
      const r = await api('generate', args);
      setKey(r.key);
      toast('Kunci berhasil dibuat. Isi passphrase lalu simpan private key-nya.');
    } catch (e) {
      showError(e, 'Gagal membuat kunci');
    } finally {
      setBusy(false);
    }
  }

  const passModal = new bootstrap.Modal('#passModal');
  let passPending = null;

  async function load(title) {
    if (state.busy) return;
    try {
      const r = await api('pickKeyFile', { title });
      if (r.cancelled) return;
      await openFile(r.path);
    } catch (e) { showError(e); }
  }

  async function openFile(path, passphrase = '') {
    setBusy(true, 'Memuat kunci…');
    try {
      const r = await api('load', { path, passphrase });
      setBusy(false);
      passModal.hide();
      setKey(r.key, { passphrase });
      if (!r.native) {
        message({
          title: 'Kunci asing berhasil diimpor', kind: 'info',
          text: `Berhasil mengimpor kunci asing (${r.format}).\n\nUntuk memakai kunci ini dengan PuTTY, simpan dalam format PuTTY dengan tombol "Private key" (Simpan private key).`,
        });
      } else {
        toast(`Kunci ${r.name} berhasil dimuat.`, 'info');
      }
    } catch (e) {
      setBusy(false);
      if (e.code === 'needPassphrase') {
        passPending = path;
        $('#passKeyName').textContent = path.split('/').pop();
        $('#loadPass').classList.toggle('is-invalid', !!passphrase);
        $('#loadPass').value = '';
        passModal.show();
      } else {
        passModal.hide();
        showError(e, 'Gagal memuat kunci');
      }
    }
  }

  $('#passModal').addEventListener('shown.bs.modal', () => $('#loadPass').focus());
  $('#passForm').addEventListener('submit', (ev) => {
    ev.preventDefault();
    if (passPending) openFile(passPending, $('#loadPass').value);
  });

  function passphraseOK() {
    const p1 = $('#pass1').value, p2 = $('#pass2').value;
    if (p1 !== p2) {
      $('#pass2').classList.add('is-invalid');
      message({ title: 'Passphrase tidak cocok', text: 'Kedua passphrase yang dimasukkan tidak sama.', kind: 'error' });
      return null;
    }
    return p1;
  }

  function suggestName() {
    const c = ($('#comment').value || 'key').trim().replace(/[\/:\\]/g, '-');
    return c || 'key';
  }

  function ppkParam() {
    const p = state.ppk;
    if (+p.version === 2) return 'version=2';
    const t = p.mode === 'passes' ? `passes=${p.passes}` : `time=${p.time}`;
    return `version=3,kdf=${p.kdf},memory=${p.memory},${t},parallelism=${p.parallelism}`;
  }

  async function savePrivate(outType = 'private') {
    if (!state.key || state.busy) return;
    const pass = passphraseOK();
    if (pass === null) return;
    if (pass === '') {
      const ok = await message({
        title: 'Simpan tanpa passphrase?', kind: 'warning', cancel: true, okText: 'Ya, simpan',
        text: 'Yakin ingin menyimpan kunci ini tanpa passphrase untuk melindunginya?',
      });
      if (!ok) return;
    }
    try {
      const r = await api('savePrivate', {
        outType, comment: $('#comment').value, passphrase: pass, suggest: suggestName(), ppkParam: ppkParam(),
      });
      if (r.cancelled) return;
      const what = outType === 'private' ? 'Private key' : 'Kunci hasil export';
      toast(`${what} disimpan ke ${r.path.split('/').pop()}`, 'success', r.path);
    } catch (e) { showError(e, 'Gagal menyimpan'); }
  }

  async function savePublic() {
    if (!state.key || state.busy) return;
    try {
      const r = await api('savePublic', { comment: $('#comment').value, suggest: suggestName() });
      if (r.cancelled) return;
      toast(`Public key disimpan ke ${r.path.split('/').pop()}`, 'success', r.path);
    } catch (e) { showError(e, 'Gagal menyimpan'); }
  }

  async function addCert() {
    if (!state.key || state.key.isSSH1) return;
    try {
      const r = await api('addCert');
      if (r.cancelled) return;
      const keep = { comment: $('#comment').value, p1: $('#pass1').value, p2: $('#pass2').value };
      setKey(r.key, { passphrase: keep.p1 });
      $('#comment').value = keep.comment; $('#pass2').value = keep.p2;
      renderKey();
      toast('Sertifikat ditambahkan ke kunci.');
    } catch (e) { showError(e, 'Gagal menambahkan sertifikat'); }
  }

  async function removeCert() {
    if (!state.key || !state.key.hasCert) return;
    try {
      const r = await api('removeCert');
      const keep = { comment: $('#comment').value, p1: $('#pass1').value, p2: $('#pass2').value };
      setKey(r.key, { passphrase: keep.p1 });
      $('#comment').value = keep.comment; $('#pass2').value = keep.p2;
      renderKey();
      toast('Sertifikat dihapus dari kunci.');
    } catch (e) { showError(e); }
  }

  async function certInfo() {
    if (!state.key || !state.key.hasCert) return;
    try {
      const r = await api('certInfo');
      message({ title: 'Info sertifikat', pre: r.text.trim(), kind: 'info' });
    } catch (e) { showError(e); }
  }

  // ---------- Parameter file PPK ----------
  const paramsModal = new bootstrap.Modal('#paramsModal');
  function fillParams(p) {
    $(`#ppk${p.version}`).checked = true;
    $(`input[name="kdf"][value="${p.kdf}"]`).checked = true;
    $('#kdfMemory').value = p.memory;
    $('#kdfPar').value = p.parallelism;
    $(`#mode-${p.mode}`).checked = true;
    $('#kdfTimeVal').value = p.mode === 'passes' ? p.passes : p.time;
    $('#kdfFields').disabled = +p.version === 2;
  }
  function readParams() {
    const mode = $('input[name="kdfmode"]:checked').value;
    const val = Math.max(1, parseInt($('#kdfTimeVal').value, 10) || 1);
    const p = {
      version: +$('input[name="ppkver"]:checked').value,
      kdf: $('input[name="kdf"]:checked').value,
      memory: Math.max(1, parseInt($('#kdfMemory').value, 10) || PPK_DEFAULT.memory),
      parallelism: Math.max(1, parseInt($('#kdfPar').value, 10) || 1),
      mode, time: state.ppk.time, passes: state.ppk.passes,
    };
    p[mode] = val;
    return p;
  }
  function openParams() { fillParams(state.ppk); paramsModal.show(); }
  $$('input[name="ppkver"]').forEach((r) => r.addEventListener('change', () => { $('#kdfFields').disabled = r.value === '2'; }));
  $$('input[name="kdfmode"]').forEach((r) => r.addEventListener('change', () => {
    $('#kdfTimeVal').value = r.value === 'passes' ? state.ppk.passes : state.ppk.time;
  }));
  $('#paramsReset').addEventListener('click', () => fillParams(PPK_DEFAULT));
  $('#paramsForm').addEventListener('submit', (ev) => {
    ev.preventDefault();
    state.ppk = readParams();
    savePrefs();
    paramsModal.hide();
  });

  // ---------- Peristiwa ----------
  $('#btnGenerate').addEventListener('click', generate);
  $('#btnLoad').addEventListener('click', () => load('Muat private key'));
  $('#btnSavePub').addEventListener('click', savePublic);
  $('#btnSavePriv').addEventListener('click', () => savePrivate('private'));

  $('#comment').addEventListener('input', () => { $('#pubkey').value = publicText(); });
  $('#pass2').addEventListener('input', () => {
    $('#pass2').classList.toggle('is-invalid', $('#pass2').value !== '' && $('#pass1').value !== $('#pass2').value);
  });
  $('#pass1').addEventListener('input', () => {
    if ($('#pass2').classList.contains('is-invalid') || $('#pass1').value === $('#pass2').value) {
      $('#pass2').classList.toggle('is-invalid', $('#pass2').value !== '' && $('#pass1').value !== $('#pass2').value);
    }
  });
  $('#fpType').addEventListener('change', () => { state.fp = $('#fpType').value; savePrefs(); refreshFingerprint(); syncMenu(); });

  async function copy(text, what) {
    try { await navigator.clipboard.writeText(text); toast(`${what} disalin.`, 'info'); }
    catch (_) { showError(new Error('Tidak bisa menyalin ke clipboard.')); }
  }
  $('#copyPub').addEventListener('click', () => copy($('#pubkey').value, 'Public key'));
  $('#copyFp').addEventListener('click', () => copy($('#fingerprint').value, 'Fingerprint'));
  $('#pubkey').addEventListener('focus', () => $('#pubkey').select());

  $$('.toggle-pass').forEach((btn) => btn.addEventListener('click', () => {
    const ids = [btn.dataset.target, btn.dataset.target2].filter(Boolean);
    const show = $('#' + ids[0]).type === 'password';
    ids.forEach((id) => { $('#' + id).type = show ? 'text' : 'password'; });
    btn.innerHTML = `<i data-lucide="${show ? 'eye-off' : 'eye'}" class="icon-sm"></i>`;
    icons();
  }));

  document.addEventListener('click', (ev) => {
    const a = ev.target.closest('[data-action]');
    if (!a) return;
    ev.preventDefault();
    if (a.classList.contains('disabled')) return;
    onMenu(a.dataset.action);
  });

  // Mencegah browser membuka file yang di-drop di atas input; Swift yang menanganinya.
  ['dragover', 'drop'].forEach((t) => document.addEventListener(t, (ev) => {
    if (ev.dataTransfer && [...ev.dataTransfer.types].includes('Files') && t === 'dragover') ev.preventDefault();
  }));

  function onMenu(action) {
    if (state.busy && action !== 'about') return;
    const [kind, val] = action.split(':');
    switch (kind) {
      case 'type': return setType(val);
      case 'primes': state.primes = val; savePrefs(); return renderParams();
      case 'fp': state.fp = val; savePrefs(); $('#fpType').value = val; syncMenu(); return refreshFingerprint();
      case 'strong': state.strong = !state.strong; savePrefs(); return renderParams();
      case 'generate': return generate();
      case 'load': return load('Muat private key');
      case 'import': return load('Import key');
      case 'savePublic': return savePublic();
      case 'savePrivate': return savePrivate('private');
      case 'exportOpenSSH': return savePrivate('private-openssh');
      case 'exportOpenSSHNew': return savePrivate('private-openssh-new');
      case 'exportSshcom': return savePrivate('private-sshcom');
      case 'params': return openParams();
      case 'addCert': return addCert();
      case 'removeCert': return removeCert();
      case 'certInfo': return certInfo();
      case 'about': return bootstrap.Modal.getOrCreateInstance('#aboutModal').show();
    }
  }

  // ---------- Tema terang/gelap mengikuti macOS ----------
  const mq = matchMedia('(prefers-color-scheme: dark)');
  const applyTheme = () => {
    document.documentElement.dataset.bsTheme = mq.matches ? 'dark' : 'light';
    $('#versionBadge').className = 'badge rounded-pill border ' + (mq.matches ? 'text-bg-dark' : 'text-bg-light');
  };
  mq.addEventListener('change', applyTheme);

  // ---------- Mulai ----------
  window.app = {
    onMenu,
    openFile: (path) => { if (!state.busy) openFile(path); },
  };

  loadPrefs();
  applyTheme();
  renderParams();
  renderKey();
  api('init').then((r) => {
    if (!r.available) {
      $('#missingAlert').classList.remove('d-none');
      $('#versionBadge').textContent = 'puttygen tidak ada';
      $$('#btnGenerate, #btnLoad').forEach((b) => { b.disabled = true; });
      return;
    }
    $('#versionBadge').textContent = r.version || 'puttygen';
    $('#aboutVersion').textContent = r.version || '';
    $('#versionBadge').title = r.path;
  }).catch(() => {});

  // ---------- Mock untuk pratinjau di browser biasa (tanpa Swift) ----------
  async function mockApi(cmd, args) {
    await new Promise((r) => setTimeout(r, cmd === 'generate' ? 600 : 50));
    const key = {
      pubBody: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpVPN1z+jyAEpDrIsNtSG9mdCelFFrF9R3rrvBbJEjd',
      comment: 'ed25519-key-20261007', fingerprint: 'ssh-ed25519 255 SHA256:u+ROpW6hNDb2WvK/HLqr1HWgIKMuPuYW2neHU4yVKr0',
      algorithm: 'ssh-ed25519', bits: '255', isSSH1: false, hasCert: false,
    };
    switch (cmd) {
      case 'init': return { ok: true, available: true, version: 'Release 0.83 (pratinjau)', path: '' };
      case 'generate': return { ok: true, key };
      case 'pickKeyFile': return { ok: true, cancelled: true };
      case 'fingerprint': return { ok: true, fingerprint: key.fingerprint };
      default: return { ok: true, cancelled: true };
    }
  }
})();
