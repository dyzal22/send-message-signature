/* ===========================================================
   script.js 
   -----------------------------------------------------------
   Proses per Bagian.

   PENGIRIM:
   1. Buat kunci AES-GCM dan IV (acak)
   2. Enkripsi pesan plaintext dengan AES-GCM
   3. Ekspor kunci AES mentah (raw) lalu enkripsi dengan kunci publik RSA penerima (RSA-OAEP)
   4. Tanda tangani (sign) hasil Encrypted-Key menggunakan kunci privat RSA-PSS pengirim
   5. Gabungkan semua hasil menjadi satu blok armor (Encrypted-Key, IV, Signature, Sender-Public-Key, Ciphertext)

   PENERIMA:
   1. Pisahkan armor menjadi bagian-bagian (Encrypted-Key, IV, Signature, Sender-Public-Key, Ciphertext)
   2. Verifikasi tanda tangan (signature) atas Encrypted-Key menggunakan kunci publik pengirim
   3. Jika signature VALID → lanjut dekripsi Encrypted-Key dengan kunci privat penerima (RSA-OAEP)
   4. Gunakan AES key hasil dekripsi untuk membuka ciphertext (AES-GCM)
   5. Tampilkan plaintext hanya jika semua valid

   💡 Tujuan keamanan:
   - Signature divalidasi **lebih dahulu** sebelum dekripsi → mencegah serangan MITM yang memanipulasi key/signature.
   =========================================================== */


/* ===========================================================
   Bagian 1 — Fungsi bantu konversi dasar
   =========================================================== */

/** Konversi base64 ke ArrayBuffer */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** Konversi ArrayBuffer ke base64 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/** Konversi string UTF-8 ke ArrayBuffer */
function strToArrayBuffer(str) { return new TextEncoder().encode(str); }

/** Konversi ArrayBuffer ke string UTF-8 */
function arrayBufferToStr(buf) { return new TextDecoder().decode(buf); }

/** Hapus header/footer PEM lalu ubah ke ArrayBuffer */
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, '')
                 .replace(/-----END [^-]+-----/g, '')
                 .replace(/\s+/g, '');
  return base64ToArrayBuffer(b64);
}


/* ===========================================================
   Bagian 2 — Import kunci (Private/Public) ke WebCrypto
   =========================================================== */

/** Import private key PKCS#8 */
async function importPrivateKeyPKCS8(pem, algoName, usages) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('pkcs8', ab, { name: algoName, hash: 'SHA-256' }, false, usages);
}

/** Import public key SPKI */
async function importPublicKeySPKI(pem, algoName, usages) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('spki', ab, { name: algoName, hash: 'SHA-256' }, false, usages);
}


/* ===========================================================
   Bagian 3 — Fungsi AES-GCM (enkripsi simetris)
   =========================================================== */

/** Generate key AES-GCM 256-bit */
async function generateAesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/** Ekspor kunci AES mentah (raw bytes) */
async function exportAesRaw(key) { return crypto.subtle.exportKey('raw', key); }

/** Import kunci AES mentah kembali ke CryptoKey */
async function importAesRaw(raw) { return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt','decrypt']); }

/** Enkripsi data menggunakan AES-GCM */
async function aesEncrypt(aesKey, iv, dataBuf) {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, dataBuf);
}

/** Dekripsi data menggunakan AES-GCM */
async function aesDecrypt(aesKey, iv, cipherBuf) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipherBuf);
}


/* ===========================================================
   Bagian 4 — Fungsi RSA (OAEP & PSS)
   =========================================================== */

/** Enkripsi RSA-OAEP (untuk membungkus kunci AES) */
async function rsaOaepEncrypt(spkiPem, dataBuf) {
  const pub = await importPublicKeySPKI(spkiPem, 'RSA-OAEP', ['encrypt']);
  return crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, dataBuf);
}

/** Dekripsi RSA-OAEP (membuka kunci AES) */
async function rsaOaepDecrypt(pkcs8Pem, encBuf) {
  const priv = await importPrivateKeyPKCS8(pkcs8Pem, 'RSA-OAEP', ['decrypt']);
  return crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, encBuf);
}

/** Tanda tangan RSA-PSS (menandatangani Encrypted-Key) */
async function rsaPssSign(pkcs8Pem, dataBuf) {
  const priv = await importPrivateKeyPKCS8(pkcs8Pem, 'RSA-PSS', ['sign']);
  return crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, priv, dataBuf);
}

/** Verifikasi tanda tangan RSA-PSS */
async function rsaPssVerify(spkiPem, dataBuf, sigBuf) {
  const pub = await importPublicKeySPKI(spkiPem, 'RSA-PSS', ['verify']);
  return crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sigBuf, dataBuf);
}


/* ===========================================================
   Bagian 5 — Format Armor (header + ciphertext)
   =========================================================== */

/** Membentuk blok armor berisi header dan ciphertext */
function buildArmor({ encKey_b64, iv_b64, cipher_b64, sig_b64, sender_pub_pem }) {
  return [
    '-----BEGIN ENCRYPTED MESSAGE-----',
    'Algoritma: AES-256-GCM + RSA-OAEP + RSA-PSS',
    'Versi: 1.0',
    `Encrypted-Key: ${encKey_b64}`,
    `IV: ${iv_b64}`,
    `Signature: ${sig_b64}`, // tanda tangan atas Encrypted-Key
    'Sender-Public-Key:',
    sender_pub_pem.trim(),
    '-----END HEADER-----',
    cipher_b64,
    '-----END ENCRYPTED MESSAGE-----'
  ].join('\n');
}

/** Parsing blok armor agar bisa diambil field-nya */
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
  if (!encKeyM || !ivM || !sigM || !senderPubM) throw new Error('Field penting hilang.');

  return {
    encKey_b64: encKeyM[1].trim(),
    iv_b64: ivM[1].trim(),
    sig_b64: sigM[1].trim(),
    sender_pub_pem: senderPubM[1].trim(),
    cipher_b64: bodyMatch[1].trim()
  };
}


/* ===========================================================
   Bagian 6 — Proses ENKRIPSI (Sisi Pengirim)
   =========================================================== */
document.getElementById('encryptBtn').addEventListener('click', async () => {
  const msg = document.getElementById('messagePlain').value || '';
  const senderPrivPem = document.getElementById('senderPriv').value.trim();
  const senderPubPem = document.getElementById('senderPub').value.trim();
  const recipientPubPem = document.getElementById('recipientPub').value.trim();
  const armorOut = document.getElementById('armorOutput');

  if (!msg) return alert('Pesan tidak boleh kosong.');
  if (!senderPrivPem || !senderPubPem || !recipientPubPem)
    return alert('Lengkapi semua kunci.');

  try {
    // 1️⃣ Buat key AES-GCM dan IV acak
    const aesKey = await generateAesKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 2️⃣ Enkripsi pesan plaintext dengan AES-GCM
    const plainBuf = strToArrayBuffer(msg);
    const cipherBuf = await aesEncrypt(aesKey, iv, plainBuf);

    // 3️⃣ Ekspor kunci AES mentah, lalu enkripsi dengan RSA-OAEP (kunci publik penerima)
    const rawAes = await exportAesRaw(aesKey);
    const encKeyBuf = await rsaOaepEncrypt(recipientPubPem, rawAes);

    // 4️⃣ Tanda tangani hasil Encrypted-Key menggunakan RSA-PSS (kunci privat pengirim)
    const sigBuf = await rsaPssSign(senderPrivPem, encKeyBuf);

    // 5️⃣ Konversi semua hasil menjadi Base64
    const encKey_b64 = arrayBufferToBase64(encKeyBuf);
    const iv_b64 = arrayBufferToBase64(iv.buffer);
    const cipher_b64 = arrayBufferToBase64(cipherBuf);
    const sig_b64 = arrayBufferToBase64(sigBuf);

    // 6️⃣ Bangun blok armor lengkap
    const armor = buildArmor({ encKey_b64, iv_b64, cipher_b64, sig_b64, sender_pub_pem: senderPubPem });

    // 7️⃣ Tampilkan hasil armor di textarea output
    armorOut.textContent = armor;

  } catch (err) {
    console.error(err);
    alert('Terjadi kesalahan saat enkripsi: ' + err.message);
  }
});


/* ===========================================================
   Bagian 7 — Tombol salin & unduh (opsional)
   =========================================================== */
document.getElementById('copyArmor').addEventListener('click', async () => {
  const t = document.getElementById('armorOutput').textContent;
  if (!t) return alert('Tidak ada armor untuk disalin.');
  try {
    await navigator.clipboard.writeText(t);
    alert('Armor berhasil disalin ke clipboard.');
  } catch (e) {
    alert('Gagal menyalin: ' + e.message);
  }
});

document.getElementById('downloadArmor').addEventListener('click', () => {
  const t = document.getElementById('armorOutput').textContent;
  if (!t) return alert('Tidak ada armor untuk diunduh.');
  const blob = new Blob([t], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'message.asc';
  a.click();
});


/* ===========================================================
   Bagian 8 — Proses DEKRIPSI (Sisi Penerima)
   =========================================================== */
document.getElementById('decryptBtn').addEventListener('click', async () => {
  const recipientPrivPem = document.getElementById('recipientPriv').value.trim();
  const armorText = document.getElementById('armorInput').value.trim();
  const plainOut = document.getElementById('plainOutput');
  const statusOut = document.getElementById('statusOutput');

  if (!recipientPrivPem || !armorText)
    return alert('Masukkan private key penerima dan armor pesan.');

  try {
    // 1️⃣ Parsing armor
    const parsed = parseArmor(armorText);

    // 2️⃣ Ambil Encrypted-Key & Signature dalam bentuk ArrayBuffer
    const encKeyBuf = base64ToArrayBuffer(parsed.encKey_b64);
    const sigBuf = base64ToArrayBuffer(parsed.sig_b64);

    // 3️⃣ Verifikasi signature terhadap Encrypted-Key
    const verified = await rsaPssVerify(parsed.sender_pub_pem, encKeyBuf, sigBuf);
    if (!verified) {
      statusOut.textContent = '❌ Signature TIDAK VALID — kemungkinan pesan diubah. Dekripsi dibatalkan.';
      statusOut.style.background = '#f7c5c5';
      plainOut.textContent = '';
      return;
    }

    // 4️⃣ Jika signature valid → lanjut dekripsi Encrypted-Key
    const rawAes = await rsaOaepDecrypt(recipientPrivPem, encKeyBuf);
    const aesKey = await importAesRaw(rawAes);

    // 5️⃣ Dekripsi ciphertext menggunakan AES-GCM
    const cipherBuf = base64ToArrayBuffer(parsed.cipher_b64);
    const ivBuf = base64ToArrayBuffer(parsed.iv_b64);
    const plainBuf = await aesDecrypt(aesKey, new Uint8Array(ivBuf), cipherBuf);
    const plainText = arrayBufferToStr(plainBuf);

    // 6️⃣ Tampilkan hasil dekripsi & status valid
    plainOut.textContent = plainText;
    statusOut.textContent = '✅ Signature VALID — pesan berhasil diverifikasi dan didekripsi.';
    statusOut.style.background = '#c8f7c5';

  } catch (err) {
    console.error(err);
    alert('Kesalahan saat dekripsi: ' + err.message);
  }
});


/* ===========================================================
   Bagian 9 — Navigasi tab (Encrypt / Decrypt)
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
