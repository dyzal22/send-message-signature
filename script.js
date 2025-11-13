// Tab navigation
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
});

// --- UTILITIES ---
async function importKey(pem, type, usage) {
  const b64 = pem.replace(/-----(BEGIN|END)[ A-Z]+-----/g, '').replace(/\s+/g, '');
  const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  if (type === 'private') {
    return crypto.subtle.importKey('pkcs8', bin.buffer, { name: 'RSA-PSS', hash: 'SHA-256' }, true, usage);
  } else {
    return crypto.subtle.importKey('spki', bin.buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, usage);
  }
}
function bufToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBuf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }

// --- ENCRYPT & SIGN ---
document.getElementById('encryptBtn').addEventListener('click', async () => {
  const msg = document.getElementById('messageInput').value;
  const senderPrivPem = document.getElementById('senderPrivKey').value;
  const receiverPubPem = document.getElementById('receiverPubKey').value;
  const output = document.getElementById('encryptedOutput');

  try {
    const senderPriv = await crypto.subtle.importKey('pkcs8', b64ToBuf(senderPrivPem.replace(/-----(BEGIN|END)[^]+?-----/g, '').replace(/\s+/g, '')), { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);
    const receiverPub = await crypto.subtle.importKey('spki', b64ToBuf(receiverPubPem.replace(/-----(BEGIN|END)[^]+?-----/g, '').replace(/\s+/g, '')), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);

    // 1. Generate AES key
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 2. Encrypt message with AES-GCM
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(msg));

    // 3. Encrypt AES key with RSA-OAEP
    const aesRaw = await crypto.subtle.exportKey('raw', aesKey);
    const encKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, receiverPub, aesRaw);

    // 4. Sign plaintext with sender private key
    const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, senderPriv, enc.encode(msg));

    // 5. Create armor-style message
    const armor = [
      "-----BEGIN ENCRYPTED MESSAGE-----",
      "Algo: AES-256-GCM + RSA-OAEP + RSA-PSS",
      `IV: ${bufToB64(iv)}`,
      `Encrypted-Key: ${bufToB64(encKey)}`,
      `Signature: ${bufToB64(signature)}`,
      "-----END HEADER-----",
      bufToB64(ciphertext),
      "-----END ENCRYPTED MESSAGE-----"
    ].join("\n");

    output.textContent = armor;
  } catch (e) {
    output.textContent = "Error: " + e.message;
  }
});

// --- DECRYPT & VERIFY ---
document.getElementById('decryptBtn').addEventListener('click', async () => {
  const receiverPrivPem = document.getElementById('receiverPrivKey').value;
  const armorText = document.getElementById('encryptedInput').value.trim();
  const output = document.getElementById('decryptedOutput');
  const verify = document.getElementById('verifyOutput');

  try {
    const ivMatch = armorText.match(/IV: ([A-Za-z0-9+/=]+)/);
    const keyMatch = armorText.match(/Encrypted-Key: ([A-Za-z0-9+/=]+)/);
    const sigMatch = armorText.match(/Signature: ([A-Za-z0-9+/=]+)/);
    const cipherMatch = armorText.match(/-----END HEADER-----\n([\s\S]+)-----END ENCRYPTED MESSAGE-----/);

    if (!ivMatch || !keyMatch || !sigMatch || !cipherMatch) throw new Error("Invalid message format");

    const iv = b64ToBuf(ivMatch[1]);
    const encKey = b64ToBuf(keyMatch[1]);
    const signature = b64ToBuf(sigMatch[1]);
    const ciphertext = b64ToBuf(cipherMatch[1].trim());

    const receiverPriv = await crypto.subtle.importKey('pkcs8', b64ToBuf(receiverPrivPem.replace(/-----(BEGIN|END)[^]+?-----/g, '').replace(/\s+/g, '')), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);

    // 1. Decrypt AES key
    const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, receiverPriv, encKey);
    const aesKey = await crypto.subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['decrypt']);

    // 2. Decrypt ciphertext
    const plaintextBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
    const plaintext = new TextDecoder().decode(plaintextBuf);
    output.textContent = plaintext;

    // 3. Verify signature (we cannot verify without sender public key in this version)
    verify.textContent = "Signature field detected but sender public key not provided — cannot verify.\nIf sender public key included, use RSA-PSS verify with SHA-256.";
  } catch (e) {
    output.textContent = "Error: " + e.message;
    verify.textContent = "";
  }
});
