// script.js
// Combined: previous PDF sign/verify + new Armor-style hybrid encrypt/receive

/******************************
 * Helper functions (crypto & base64)
 ******************************/
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, '')
                 .replace(/-----END [^-]+-----/g, '')
                 .replace(/\s+/g, '');
  return base64ToArrayBuffer(b64);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function strToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}

function arrayBufferToStr(buf) {
  return new TextDecoder().decode(buf);
}

/******************************
 * RSA Key import helpers
 ******************************/
async function importRsaOaepPublicKey(pem) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'spki',
    ab,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
}

async function importRsaOaepPrivateKey(pem) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'pkcs8',
    ab,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  );
}

async function importRsaPssPublicKey(pem) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'spki',
    ab,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

async function importRsaPssPrivateKey(pem) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'pkcs8',
    ab,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

/******************************
 * AES-GCM helpers
 ******************************/
async function generateAesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function exportAesRaw(key) {
  return crypto.subtle.exportKey('raw', key);
}
async function importAesRaw(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
}
async function aesGcmEncrypt(aesKey, iv, dataBuffer) {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, dataBuffer);
}
async function aesGcmDecrypt(aesKey, iv, cipherBuffer) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipherBuffer);
}

/******************************
 * RSA-OAEP & RSA-PSS operations
 ******************************/
async function rsaOaepEncrypt(pubPem, dataBuffer) {
  const pub = await importRsaOaepPublicKey(pubPem);
  const enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, dataBuffer);
  return enc;
}
async function rsaOaepDecrypt(privPem, encBuffer) {
  const priv = await importRsaOaepPrivateKey(privPem);
  const dec = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, encBuffer);
  return dec;
}
async function rsaPssSign(privPem, dataBuffer) {
  const priv = await importRsaPssPrivateKey(privPem);
  const sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, priv, dataBuffer);
  return sig;
}
async function rsaPssVerify(pubPem, dataBuffer, sigBuffer) {
  const pub = await importRsaPssPublicKey(pubPem);
  const ok = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sigBuffer, dataBuffer);
  return ok;
}

/******************************
 * Basic utilities for files & hashing
 ******************************/
function fileToArrayBuffer(file) {
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onload = ()=> resolve(reader.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}
async function sha256Hex(buffer) {
  const hb = await crypto.subtle.digest('SHA-256', buffer);
  const arr = Array.from(new Uint8Array(hb));
  return arr.map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function sha256Raw(buffer) {
  return crypto.subtle.digest('SHA-256', buffer);
}

/******************************
 * --- Existing PDF sign/verify code (ke-1..3 tabs) ---
 * (keperluan: tetap dipertahankan)
 ******************************/
/* Utilities for signing PDF (we reuse earlier functions) */
async function importPrivateKeyForSign(pem) {
  return importRsaPssPrivateKey(pem);
}
async function importPublicKeyForVerify(pem) {
  return importRsaPssPublicKey(pem);
}

/* Tab 1: Sign PDF */
document.getElementById('signButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('pdfUploader');
  const privPem = document.getElementById('privateKey').value.trim();
  const loader = document.getElementById('loader');
  const results = document.getElementById('results');
  const hashResult = document.getElementById('hashResult');
  const sigResult = document.getElementById('sigResult');

  if (!fileInput.files.length || !privPem) {
    alert('Pilih PDF dan masukkan private key!');
    return;
  }

  loader.style.display = 'block';
  results.style.display = 'none';

  try {
    const file = fileInput.files[0];
    const arrayBuffer = await fileToArrayBuffer(file);

    // hash file
    const hashHex = await sha256Hex(arrayBuffer);

    // sign the hash (we sign the hash hex string)
    const sigBuf = await rsaPssSign(privPem, strToArrayBuffer(hashHex));
    const sigB64 = arrayBufferToBase64(sigBuf);

    // show results
    hashResult.textContent = hashHex;
    sigResult.textContent = sigB64;
    results.style.display = 'block';

    // embed into PDF (last page)
    const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    const { width } = lastPage.getSize();
    const text = `Digital Signature:\nHash (SHA-256): ${hashHex}\nSignature: ${sigB64}\nDate: ${new Date().toLocaleString()}`;
    lastPage.drawText(text, { x: 40, y: 80, size: 9, maxWidth: width - 80, lineHeight: 11 });

    const signedBytes = await pdfDoc.save();
    const blob = new Blob([signedBytes], { type: 'application/pdf' });

    const dl = document.getElementById('downloadBtn');
    dl.onclick = () => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `signed_${file.name}`;
      a.click();
      URL.revokeObjectURL(url);
    };

  } catch (err) {
    alert('Error: ' + err.message);
    console.error(err);
  } finally {
    loader.style.display = 'none';
  }
});

/* Tab 2: Verify Original */
document.getElementById('verifyButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('verifyPdf');
  const pubPem = document.getElementById('publicKey').value.trim();
  const sigB64 = document.getElementById('signatureInput').value.trim();
  const out = document.getElementById('verifyResult');

  if (!fileInput.files.length || !pubPem || !sigB64) {
    alert('Lengkapi data (PDF, public key, signature).');
    return;
  }

  try {
    const file = fileInput.files[0];
    const arr = await fileToArrayBuffer(file);
    const hashHex = await sha256Hex(arr);
    const sigBuf = base64ToArrayBuffer(sigB64);
    const ok = await rsaPssVerify(pubPem, strToArrayBuffer(hashHex), sigBuf);

    out.style.display = 'block';
    if (ok) {
      out.textContent = '✅ Signature VALID (original file).';
      out.style.background = '#c8f7c5';
    } else {
      out.textContent = '❌ Signature INVALID (original file).';
      out.style.background = '#f7c5c5';
    }
  } catch (err) {
    alert('Error: ' + err.message);
    console.error(err);
  }
});

/* Tab 3: Verify Signed PDF (extract embedded hash) */
async function extractTextFromPdfArrayBuffer(arrayBuffer) {
  const pdfjsLib = window['pdfjs-dist/build/pdf'];
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.16.105/pdf.worker.min.js";
  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  let text = '';
  for (let p = 1; p <= pdf.numPages; p++) {
    const page = await pdf.getPage(p);
    const content = await page.getTextContent();
    content.items.forEach(i => text += i.str + '\n');
  }
  return text;
}

document.getElementById('verifySignedButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('verifySignedPdf');
  const pubPem = document.getElementById('publicKey2').value.trim();
  const sigB64 = document.getElementById('signatureInput2').value.trim();
  const out = document.getElementById('verifySignedResult');

  if (!fileInput.files.length || !pubPem || !sigB64) {
    alert('Lengkapi data (signed PDF, public key, signature).');
    return;
  }

  try {
    const file = fileInput.files[0];
    const arr = await fileToArrayBuffer(file);
    const txt = await extractTextFromPdfArrayBuffer(arr);
    const m = txt.match(/Hash \(SHA-256\):\s*([A-Fa-f0-9]{64})/);
    if (!m) throw new Error('Embedded hash tidak ditemukan di PDF.');
    const embeddedHash = m[1];

    const sigBuf = base64ToArrayBuffer(sigB64);
    const ok = await rsaPssVerify(pubPem, strToArrayBuffer(embeddedHash), sigBuf);

    out.style.display = 'block';
    if (ok) { out.textContent = '✅ Signed PDF valid (embedded hash matches signature).'; out.style.background='#c8f7c5'; }
    else { out.textContent = '❌ Signed PDF tidak valid.'; out.style.background='#f7c5c5'; }
  } catch (err) {
    alert('Error: ' + err.message);
    console.error(err);
  }
});

/******************************
 * Tab 4: Encrypt & Armor (Hybrid)
 ******************************/
function buildArmor({ encKey_b64, iv_b64, cipher_b64, sig_b64, sender_pub_pem }) {
  const header = [
    '-----BEGIN ENCRYPTED MESSAGE-----',
    'Algo: AES-256-GCM + RSA-OAEP + RSA-PSS',
    'Version: 1.0',
    `Encrypted-Key: ${encKey_b64}`,
    `IV: ${iv_b64}`,
    `Signature: ${sig_b64}`,
    'Sender-Public-Key:',
    sender_pub_pem.trim(),
    '-----END HEADER-----'
  ].join('\n');

  const body = cipher_b64;
  const footer = '\n-----END ENCRYPTED MESSAGE-----';
  return header + '\n' + body + footer;
}

document.getElementById('encryptButton').addEventListener('click', async () => {
  const msg = document.getElementById('messagePlain').value;
  const senderPrivPem = document.getElementById('senderPriv').value.trim();
  const recipientPubPem = document.getElementById('recipientPub').value.trim();
  const out = document.getElementById('armorOutput');

  if (!msg || !senderPrivPem || !recipientPubPem) {
    alert('Lengkapi message, sender private key, dan recipient public key.');
    return;
  }

  try {
    // 1) generate AES key and IV
    const aesKey = await generateAesKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 2) encrypt message with AES-GCM
    const plainBuf = strToArrayBuffer(msg);
    const cipherBuf = await aesGcmEncrypt(aesKey, iv, plainBuf);
    const cipher_b64 = arrayBufferToBase64(cipherBuf);
    const iv_b64 = arrayBufferToBase64(iv.buffer);

    // 3) export aes raw and encrypt the raw key with recipient RSA-OAEP
    const rawAes = await exportAesRaw(aesKey);
    const encKeyBuf = await rsaOaepEncrypt(recipientPubPem, rawAes);
    const encKey_b64 = arrayBufferToBase64(encKeyBuf);

    // 4) compute hash of plaintext and sign using RSA-PSS (sender)
    const hashRaw = await sha256Raw(plainBuf); // raw digest
    const hashHex = Array.from(new Uint8Array(hashRaw)).map(b=>b.toString(16).padStart(2,'0')).join('');
    const sigBuf = await rsaPssSign(senderPrivPem, strToArrayBuffer(hashHex));
    const sig_b64 = arrayBufferToBase64(sigBuf);

    // 5) build armor and output
    // include sender public key (we need a way to get it from private; easiest: require sender to paste its public key also)
    // but to keep UX easier: derive public from private is non-trivial; ask sender to paste public in recipientPub? No.
    // We'll ask user to paste sender public in same textarea as private? Simpler: derive from private not possible in WebCrypto directly.
    // So we will ask the sender to include his public key as well. But for simplicity here, require sender to paste his public separately in UI?
    // To avoid changing UI now, we'll extract public by re-exporting from private key if allowed.
    // WebCrypto cannot export public key from private key directly. So require sender to paste sender public key into the top of senderPriv area:
    // We'll accept that senderPriv may contain both private and public; but most users will paste both. For now, attempt to parse public inside senderPriv value.
    let senderPubPem = '';
    // try to find a PEM public key inside the senderPriv value (user might paste both)
    const possible = (senderPrivPem.match(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/));
    if (possible) senderPubPem = possible[0];
    else {
      // fallback: try to ask user to supply sender public key in a prompt
      senderPubPem = prompt('Public key of sender not found in private key box. Please paste sender PUBLIC KEY PEM (-----BEGIN PUBLIC KEY-----...). If you don\\'t have it, paste it now:');
      if (!senderPubPem) throw new Error('Sender public key diperlukan untuk menyertakan di armor header.');
    }

    const armor = buildArmor({ encKey_b64, iv_b64, cipher_b64, sig_b64, sender_pub_pem: senderPubPem });
    out.textContent = armor;
    document.getElementById('copyArmor').onclick = async () => {
      await navigator.clipboard.writeText(armor);
      alert('Armor copied to clipboard.');
    };
    document.getElementById('downloadArmor').onclick = () => {
      const blob = new Blob([armor], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'message.asc';
      a.click();
      URL.revokeObjectURL(a.href);
    };
  } catch (err) {
    alert('Error: ' + err.message);
    console.error(err);
  }
});

/******************************
 * Tab 5: Receive & Verify (parse armor)
 ******************************/
function parseArmor(armorText) {
  // very permissive parser
  const headerMatch = armorText.match(/-----BEGIN ENCRYPTED MESSAGE-----([\s\S]*?)-----END HEADER-----/);
  if (!headerMatch) throw new Error('Header armor tidak ditemukan atau format salah.');
  const header = headerMatch[1];

  const encKeyMatch = header.match(/Encrypted-Key:\s*([A-Za-z0-9+/=]+)/);
  const ivMatch = header.match(/IV:\s*([A-Za-z0-9+/=]+)/);
  const sigMatch = header.match(/Signature:\s*([A-Za-z0-9+/=]+)/);
  const senderPubMatch = header.match(/(-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----)/);

  if (!encKeyMatch || !ivMatch || !sigMatch || !senderPubMatch) {
    throw new Error('Header field penting tidak ditemukan (Encrypted-Key, IV, Signature, Sender-Public-Key).');
  }

  // body: between END HEADER and END ENCRYPTED MESSAGE
  const bodyMatch = armorText.match(/-----END HEADER-----\s*([\s\S]*?)\s*-----END ENCRYPTED MESSAGE-----/);
  if (!bodyMatch) throw new Error('Body ciphertext tidak ditemukan.');
  const cipher_b64 = bodyMatch[1].trim();

  return {
    encKey_b64: encKeyMatch[1].trim(),
    iv_b64: ivMatch[1].trim(),
    sig_b64: sigMatch[1].trim(),
    senderPubPem: senderPubMatch[1].trim(),
    cipher_b64
  };
}

document.getElementById('decryptButton').addEventListener('click', async () => {
  const privPem = document.getElementById('recipientPriv').value.trim();
  const armorText = document.getElementById('armorInput').value.trim();
  const resultDiv = document.getElementById('decryptResult');
  const outMsg = document.getElementById('decryptedMessage');
  const statusDiv = document.getElementById('decryptStatus');

  if (!privPem || !armorText) {
    alert('Masukkan recipient private key dan armor block.');
    return;
  }

  try {
    const parsed = parseArmor(armorText);
    // decrypt AES key
    const encKeyBuf = base64ToArrayBuffer(parsed.encKey_b64);
    const rawAes = await rsaOaepDecrypt(privPem, encKeyBuf);
    const aesKey = await importAesRaw(rawAes);

    const ivBuf = base64ToArrayBuffer(parsed.iv_b64);
    const cipherBuf = base64ToArrayBuffer(parsed.cipher_b64);

    // decrypt ciphertext
    const plainBuf = await aesGcmDecrypt(aesKey, new Uint8Array(ivBuf), cipherBuf);
    const plainText = arrayBufferToStr(plainBuf);

    // verify integrity: hash compare + signature verification
    const hashRaw = await sha256Raw(strToArrayBuffer(plainText));
    const hashHex = Array.from(new Uint8Array(hashRaw)).map(b=>b.toString(16).padStart(2,'0')).join('');

    const sigBuf = base64ToArrayBuffer(parsed.sig_b64);

    // verify using sender public key included in header
    const ok = await rsaPssVerify(parsed.senderPubPem, strToArrayBuffer(hashHex), sigBuf);

    // show results
    resultDiv.style.display = 'block';
    outMsg.textContent = plainText;
    if (ok) {
      statusDiv.innerHTML = '<div style="background:#c8f7c5;padding:8px;border-radius:6px">✅ Signature VALID. Integrity OK. Sender authenticated.</div>';
    } else {
      statusDiv.innerHTML = '<div style="background:#f7c5c5;padding:8px;border-radius:6px">❌ Signature INVALID or Integrity mismatch.</div>';
    }
  } catch (err) {
    alert('Error: ' + err.message);
    console.error(err);
  }
});

/******************************
 * Tab switching for all 5 tabs
 ******************************/
function showTab(tabId) {
  const tabs = document.querySelectorAll('.tab');
  const contents = document.querySelectorAll('.content');
  tabs.forEach(t=>t.classList.remove('active'));
  contents.forEach(c=>c.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  const contentMap = {
    'tab-signpdf':'content-signpdf',
    'tab-verifyorig':'content-verifyorig',
    'tab-verifysigned':'content-verifysigned',
    'tab-encrypt':'content-encrypt',
    'tab-receive':'content-receive'
  };
  document.getElementById(contentMap[tabId]).classList.add('active');
}

document.getElementById('tab-signpdf').addEventListener('click', ()=> showTab('tab-signpdf'));
document.getElementById('tab-verifyorig').addEventListener('click', ()=> showTab('tab-verifyorig'));
document.getElementById('tab-verifysigned').addEventListener('click', ()=> showTab('tab-verifysigned'));
document.getElementById('tab-encrypt').addEventListener('click', ()=> showTab('tab-encrypt'));
document.getElementById('tab-receive').addEventListener('click', ()=> showTab('tab-receive'));
