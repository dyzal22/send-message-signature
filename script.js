/* ===========================================================
   Hybrid Encryption + Digital Signature (RSA + AES)
   ===========================================================
   - Confidentiality  : AES-GCM (symmetric) + RSA-OAEP (asymmetric)
   - Integrity        : SHA-256 hash + RSA-PSS signature
   - Authentication   : Sender Public Key verification
   - Non-Repudiation  : Signature created by sender private key

   Semua proses dijalankan di sisi klien (browser) menggunakan
   WebCrypto API, tanpa mengirim kunci ke server.
   =========================================================== */

/* -----------------------------
   Fungsi UTILITAS UMUM
------------------------------*/

// Konversi string Base64 → ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// Konversi ArrayBuffer → Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// Konversi teks biasa → ArrayBuffer (UTF-8)
function strToArrayBuffer(str) { return new TextEncoder().encode(str); }

// Konversi ArrayBuffer → string (UTF-8)
function arrayBufferToStr(buf) { return new TextDecoder().decode(buf); }

// Hapus header/footer dari PEM dan ubah ke ArrayBuffer
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, '')
                 .replace(/-----END [^-]+-----/g, '')
                 .replace(/\s+/g, '');
  return base64ToArrayBuffer(b64);
}

/* -----------------------------
   Fungsi Import Key (RSA)
------------------------------*/

// Import Private Key (PKCS#8) untuk RSA
async function importPrivateKeyPKCS8(pem, algoName, usages) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('pkcs8', ab, { name: algoName, hash: 'SHA-256' }, false, usages);
}

// Import Public Key (SPKI)
async function importPublicKeySPKI(pem, algoName, usages) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('spki', ab, { name: algoName, hash: 'SHA-256' }, false, usages);
}

/* -----------------------------
   Fungsi AES-GCM (Symmetric)
------------------------------*/

// Generate kunci acak AES-256
async function generateAesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// Ekspor key AES ke bentuk raw bytes
async function exportAesRaw(key) { return crypto.subtle.exportKey('raw', key); }

// Import kembali raw bytes ke objek Key
async function importAesRaw(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Enkripsi data dengan AES-GCM
async function aesEncrypt(aesKey, iv, dataBuf) {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, dataBuf);
}

// Dekripsi data AES-GCM
async function aesDecrypt(aesKey, iv, cipherBuf) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipherBuf);
}

/* -----------------------------
   Operasi RSA (OAEP dan PSS)
------------------------------*/

// RSA-OAEP untuk mengenkripsi AES Key (Confidentiality)
async function rsaOaepEncrypt(spkiPem, dataBuf) {
  const pub = await importPublicKeySPKI(spkiPem, 'RSA-OAEP', ['encrypt']);
  return crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, dataBuf);
}

// RSA-OAEP untuk mendekripsi AES Key (Confidentiality)
async function rsaOaepDecrypt(pkcs8Pem, encBuf) {
  const priv = await importPrivateKeyPKCS8(pkcs8Pem, 'RSA-OAEP', ['decrypt']);
  return crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, encBuf);
}

// RSA-PSS untuk menandatangani hash pesan (Integrity + Non-Repudiation)
async function rsaPssSign(pkcs8Pem, dataBuf) {
  const priv = await importPrivateKeyPKCS8(pkcs8Pem, 'RSA-PSS', ['sign']);
  return crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, priv, dataBuf);
}

// RSA-PSS untuk memverifikasi tanda tangan (Integrity + Authentication)
async function rsaPssVerify(spkiPem, dataBuf, sigBuf) {
  const pub = await importPublicKeySPKI(spkiPem, 'RSA-PSS', ['verify']);
  return crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sigBuf, dataBuf);
}

/* -----------------------------
   ARMOR STYLE ENCODING
------------------------------*/
/**
 * Bentuk pesan terenkripsi dikemas seperti blok ASCII armor
 * agar mudah dikopi/ditransfer antar user (mirip OpenPGP).
 */
function buildArmor({ encKey_b64, iv_b64, cipher_b64, sig_b64, sender_pub_pem }) {
  return [
    '-----BEGIN ENCRYPTED MESSAGE-----',
    'Algo: AES-256-GCM + RSA-OAEP + RSA-PSS',
    'Version: 1.0',
    `Encrypted-Key: ${encKey_b64}`,
    `IV: ${iv_b64}`,
    `Signature: ${sig_b64}`,
    'Sender-Public-Key:',
    sender_pub_pem.trim(),
    '-----END HEADER-----',
    cipher_b64,
    '-----END ENCRYPTED MESSAGE-----'
  ].join('\n');
}

// Parser untuk membaca header & body dari armor block
function parseArmor(armorText) {
  const headerMatch = armorText.match(/-----BEGIN ENCRYPTED MESSAGE-----([\s\S]*?)-----END HEADER-----/);
  if (!headerMatch) throw new Error('Header armor tidak ditemukan.');
  const header = headerMatch[1];

  const encKeyM = header.match(/Encrypted-Key:\s*([A-Za-z0-9+/=]+)/);
  const ivM = header.match(/IV:\s*([A-Za-z0-9+/=]+)/);
  const sigM = header.match(/Signature:\s*([A-Za-z0-9+/=]+)/);
  const senderPubM = header.match(/(-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----)/);

  const bodyMatch = armorText.match(/-----END HEADER-----\s*([\s\S]*?)\s*-----END ENCRYPTED MESSAGE-----/);
  if (!bodyMatch) throw new Error('Body ciphertext tidak ditemukan.');

  return {
    encKey_b64: encKeyM[1],
    iv_b64: ivM[1],
    sig_b64: sigM[1],
    sender_pub_pem: senderPubM[1],
    cipher_b64: bodyMatch[1].trim()
  };
}

/* ===========================================================
   TAB 1 — ENKRIPSI & PENANDATANGANAN PESAN
   =========================================================== */
document.getElementById('encryptBtn').addEventListener('click', async () => {
  const msg = document.getElementById('messagePlain').value;
  const senderPrivPem = document.getElementById('senderPriv').value.trim();
  const senderPubPem = document.getElementById('senderPub').value.trim();
  const recipientPubPem = document.getElementById('recipientPub').value.trim();
  const armorOut = document.getElementById('armorOutput');

  if (!msg) return alert('Pesan kosong.');
  if (!senderPrivPem || !senderPubPem || !recipientPubPem)
    return alert('Pastikan semua key sudah dimasukkan.');

  try {
    /** 1️⃣ Generate AES Key (untuk kecepatan & efisiensi enkripsi data besar) */
    const aesKey = await generateAesKey();
    const iv = crypto.getRandomValues(new Uint8Array(12)); // inisialisasi vector

    /** 2️⃣ Encrypt plaintext dengan AES-GCM */
    const plainBuf = strToArrayBuffer(msg);
    const cipherBuf = await aesEncrypt(aesKey, iv, plainBuf);

    /** 3️⃣ Encrypt AES key dengan public key penerima (RSA-OAEP) */
    const rawAes = await exportAesRaw(aesKey);
    const encKeyBuf = await rsaOaepEncrypt(recipientPubPem, rawAes);

    /** 4️⃣ Hash pesan (SHA-256) → hasil dalam hex */
    const hashBuf = await crypto.subtle.digest('SHA-256', plainBuf);
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    /** 5️⃣ Sign hash dengan RSA-PSS dan private key pengirim */
    const sigBuf = await rsaPssSign(senderPrivPem, strToArrayBuffer(hashHex));

    /** 6️⃣ Ubah semua hasil ke Base64 untuk disimpan dalam armor */
    const encKey_b64 = arrayBufferToBase64(encKeyBuf);
    const iv_b64 = arrayBufferToBase64(iv.buffer);
    const cipher_b64 = arrayBufferToBase64(cipherBuf);
    const sig_b64 = arrayBufferToBase64(sigBuf);

    /** 7️⃣ Susun armor block berisi ciphertext, signature, dan public key pengirim */
    const armor = buildArmor({ encKey_b64, iv_b64, cipher_b64, sig_b64, sender_pub_pem: senderPubPem });

    /** 8️⃣ Tampilkan armor ke layar */
    armorOut.textContent = armor;
  } catch (err) {
    console.error(err);
    alert('Terjadi error saat encrypt/sign: ' + err.message);
  }
});

/* Tombol copy armor ke clipboard */
document.getElementById('copyArmor').addEventListener('click', async () => {
  const t = document.getElementById('armorOutput').textContent;
  if (!t) return alert('Tidak ada hasil untuk disalin.');
  await navigator.clipboard.writeText(t);
  alert('Armor berhasil disalin.');
});

/* Tombol download armor ke file .asc */
document.getElementById('downloadArmor').addEventListener('click', () => {
  const t = document.getElementById('armorOutput').textContent;
  if (!t) return alert('Tidak ada hasil untuk diunduh.');
  const blob = new Blob([t], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'message.asc';
  a.click();
});

/* ===========================================================
   TAB 2 — DEKRIPSI & VERIFIKASI
   =========================================================== */
document.getElementById('decryptBtn').addEventListener('click', async () => {
  const recipientPrivPem = document.getElementById('recipientPriv').value.trim();
  const armorText = document.getElementById('armorInput').value.trim();
  const plainOut = document.getElementById('plainOutput');
  const statusOut = document.getElementById('statusOutput');

  if (!recipientPrivPem || !armorText)
    return alert('Masukkan kunci private penerima dan blok armor.');

  try {
    /** 1️⃣ Parse armor block */
    const parsed = parseArmor(armorText);

    /** 2️⃣ Dekripsi AES key dengan RSA-OAEP (Private key penerima) */
    const encKeyBuf = base64ToArrayBuffer(parsed.encKey_b64);
    const rawAes = await rsaOaepDecrypt(recipientPrivPem, encKeyBuf);
    const aesKey = await importAesRaw(rawAes);

    /** 3️⃣ Dekripsi ciphertext dengan AES-GCM */
    const cipherBuf = base64ToArrayBuffer(parsed.cipher_b64);
    const ivBuf = base64ToArrayBuffer(parsed.iv_b64);
    const plainBuf = await aesDecrypt(aesKey, new Uint8Array(ivBuf), cipherBuf);
    const plainText = arrayBufferToStr(plainBuf);
    plainOut.textContent = plainText;

    /** 4️⃣ Hitung ulang hash pesan */
    const hashBuf = await crypto.subtle.digest('SHA-256', strToArrayBuffer(plainText));
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    /** 5️⃣ Verifikasi signature dengan public key pengirim (yang disertakan di armor) */
    const sigBuf = base64ToArrayBuffer(parsed.sig_b64);
    const valid = await rsaPssVerify(parsed.sender_pub_pem, strToArrayBuffer(hashHex), sigBuf);

    /** 6️⃣ Tampilkan hasil verifikasi */
    statusOut.textContent = valid
      ? '✅ Signature VALID — Integrity dan autentikasi terjamin.'
      : '❌ Signature INVALID — Pesan mungkin diubah atau key salah.';
  } catch (err) {
    console.error(err);
    alert('Error saat dekripsi/verifikasi: ' + err.message);
  }
});

/* ===========================================================
   NAVIGASI ANTAR TAB
   =========================================================== */
document.getElementById('tabEncrypt').addEventListener('click', () => {
  document.getElementById('contentEncrypt').style.display = 'block';
  document.getElementById('contentReceive').style.display = 'none';
  document.getElementById('tabEncrypt').classList.remove('inactive');
  document.getElementById('tabReceive').classList.add('inactive');
});

document.getElementById('tabReceive').addEventListener('click', () => {
  document.getElementById('contentEncrypt').style.display = 'none';
  document.getElementById('contentReceive').style.display = 'block';
  document.getElementById('tabEncrypt').classList.add('inactive');
  document.getElementById('tabReceive').classList.remove('inactive');
});
