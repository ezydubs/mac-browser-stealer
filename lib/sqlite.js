'use strict';
/*
 * Minimal pure-JS SQLite file reader (read-only, zero dependencies).
 *
 * Browser databases (Chrome/Edge/Firefox Cookies + Login Data) are SQLite
 * files. Rather than link a native SQLite library (which would break pkg
 * single-binary compilation and require a specific Node version), we parse the
 * raw file format directly.
 *
 * Two pieces:
 *   readSchema(buf)  — scan the file for sqlite_master rows to recover each
 *                       table's name, columns and affinities.
 *   scanRecords(buf, colTypes, validator) — walk the whole file and return every
 *                       record whose column count and serial types match a table,
 *                       optionally filtered by a validator.
 *
 * We scan the whole file (instead of walking the B-tree) because some builds
 * store the schema and data on pages whose type bytes are not the canonical
 * 0x05/0x02, so a B-tree walk is unreliable. A record is kept only if its
 * header is exactly consumed and its column count matches, then validated.
 */

const fs = require('fs');

function readUInt16BE(buf, off) { return (buf[off] << 8) | buf[off + 1]; }
function readUInt32BE(buf, off) {
  return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
}

function readVarint(buf, offset) {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    if (offset + i >= buf.length) return [result, offset + i];
    const byte = buf[offset + i];
    if (byte < 0x80) {
      result = (result << 7) | byte;
      return [result, offset + i + 1];
    }
    result = (result << 7) | (byte & 0x7f);
  }
  if (offset + 8 < buf.length) {
    result = (result << 8) | buf[offset + 8];
    return [result, offset + 9];
  }
  return [result, offset + 8];
}

function readInt8(buf, o) { const v = buf[o]; return v > 0x7f ? v - 0x100 : v; }
function readInt16BE(buf, o) { const v = readUInt16BE(buf, o); return v > 0x7fff ? v - 0x10000 : v; }
function readInt32BE(buf, o) { return readUInt32BE(buf, o) | 0; }
function readInt48BE(buf, o) {
  let v = 0;
  for (let i = 0; i < 6; i++) v = (v << 8) | buf[o + i];
  if (v >= (1 << 47)) v -= (1 << 48);
  return v;
}
function readInt64BE(buf, o) {
  const hi = readUInt32BE(buf, o);
  const lo = readUInt32BE(buf, o + 4);
  return hi * 0x100000000 + lo; // exact up to 2^53; browser timestamps fit
}
function readFloat64BE(buf, o) {
  const b = Buffer.alloc(8);
  buf.copy(b, 0, o, o + 8);
  return b.readDoubleBE(0);
}

function serialSize(st) {
  if (st >= 1 && st <= 6) return [1, 2, 3, 4, 6, 8][st - 1];
  if (st === 7) return 8;
  if (st === 8 || st === 9) return 0;
  if (st >= 12) return st % 2 === 0 ? (st - 12) / 2 : (st - 13) / 2;
  return 0;
}

function decodeValue(buf, vo, st) {
  switch (st) {
    case 0: return null;
    case 1: return readInt8(buf, vo);
    case 2: return readInt16BE(buf, vo);
    case 3: return readInt48BE(buf, vo);
    case 4: return readInt32BE(buf, vo);
    case 5: return readInt48BE(buf, vo);
    case 6: return readInt64BE(buf, vo);
    case 7: return readFloat64BE(buf, vo);
    case 8: return Buffer.alloc(0);
    case 9: return '';
    default: {
      if (st >= 12 && st % 2 === 0) return buf.slice(vo, vo + (st - 12) / 2);
      return buf.toString('utf8', vo, vo + (st - 13) / 2);
    }
  }
}

// Loose affinity compatibility (pre-filter only; the validator does the real work).
// Some browser DBs store INTEGER columns as empty blob (8) / empty string (9),
// so we accept a wide range here.
function looseCompatible(st, colType) {
  if (st >= 0 && st <= 9) return true;
  if (st >= 12) return true; // blob or text
  return false;
}

// Strict per-type affinity compatibility. Much more selective than loose
// (accepts only the serial types actually used for each column type, plus
// null/empty for any type), which cuts the pre-filter candidate count on large
// files by ~10x and keeps the scan's GC pressure low. The validator still does
// the real filtering; this is just a cheaper pre-filter.
function strictCompatible(st, colType) {
  // null (0) and empty blob/string (8, 9) are valid for any column type.
  if (st === 0 || st === 8 || st === 9) return true;
  switch (colType) {
    case 'INTEGER': return st >= 1 && st <= 6; // integer serial types
    case 'TEXT': return st >= 13 && st % 2 === 1; // text serial types
    case 'BLOB': return st >= 12 && st % 2 === 0; // blob serial types
    case 'REAL': return st === 7; // float
    default: return true; // NUMERIC / OTHER: keep loose
  }
}

// Read a varint starting at `offset`, writing the result and the end offset
// into the shared `out` object (no per-call allocation). Used by the hot
// scanRecords loop, where allocating a fresh array per varint would drown the
// GC on large files.
function readVarintInto(buf, offset, out) {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    if (offset + i >= buf.length) { out.value = result; out.end = offset + i; return out; }
    const byte = buf[offset + i];
    if (byte < 0x80) {
      out.value = (result << 7) | byte;
      out.end = offset + i + 1;
      return out;
    }
    result = (result << 7) | (byte & 0x7f);
  }
  if (offset + 8 < buf.length) {
    out.value = (result << 8) | buf[offset + 8];
    out.end = offset + 9;
  } else {
    out.value = result;
    out.end = offset + 8;
  }
  return out;
}

// Scan the whole file for records matching `colTypes` (by count + loose affinity),
// optionally filtered by `validator(values, serialTypes) -> boolean`.
// `maxRows` bounds memory on huge tables (e.g. a 173 MB History DB whose
// `visits` table has millions of rows): once the cap is reached, new rows
// overwrite the buffer in a ring, so the result holds the LAST maxRows rows.
//
// The loop is written to be allocation-free (shared varint out-objects, a
// reused serial-type array, and value arrays allocated only for rows that pass
// the pre-filter) so that scanning a 173 MB file does not drown the GC and
// exhaust the heap.
// Scratch state for the getCol decoder (reused across candidates; no per-candidate
// allocation). getCol(i) decodes column i of the current candidate on demand.
const _scratch = { buf: null, valueStart: 0, sts: null, n: 0 };
function getCol(i) {
  const { buf, valueStart, sts, n } = _scratch;
  if (i < 0 || i >= n) return undefined;
  let vo = valueStart;
  for (let j = 0; j < i; j++) vo += serialSize(sts[j]);
  return decodeValue(buf, vo, sts[i]);
}

// Core scan loop. `compat` is the affinity pre-filter (strict or loose).
// `validator(getCol, serialTypes) -> boolean` decodes columns on demand via
// getCol(i) — validators typically touch only 1-2 columns, so no per-candidate
// array is allocated (the main source of GC pressure on wide tables like an
// 18-column `visits` with hundreds of thousands of rows).
function _scan(buf, colTypes, validator, maxRows, compat) {
  const n = colTypes.length;
  const results = [];
  if (n === 0) return results;
  let ring = 0;
  const _hs = { value: 0, end: 0 };
  const _st = { value: 0, end: 0 };
  const sts = new Array(n);
  const len = buf.length;
  _scratch.buf = buf;
  _scratch.sts = sts;
  _scratch.n = n;
  for (let off = 0; off < len - 4; off++) {
    readVarintInto(buf, off, _hs);
    const hs = _hs.value;
    if (hs < 3 || hs > 5000) continue;
    const he = off + hs;
    if (he > len) continue; // header must fit in the file
    const ah = _hs.end;
    let si = 0;
    let so = ah;
    while (so < he && so < len && si < n) {
      readVarintInto(buf, so, _st);
      sts[si++] = _st.value;
      so = _st.end;
      if (so > he) break;
    }
    if (so !== he || si !== n) continue;
    let ok = true;
    for (let i = 0; i < n; i++) {
      if (!compat(sts[i], colTypes[i])) { ok = false; break; }
    }
    if (!ok) continue;
    const valueStart = off + hs;
    // Check the whole value area fits in the file before decoding.
    let vo = valueStart;
    let fits = true;
    for (let i = 0; i < n; i++) {
      vo += serialSize(sts[i]);
      if (vo > len) { fits = false; break; }
    }
    if (!fits) continue;
    _scratch.valueStart = valueStart;
    if (validator && !validator(getCol, sts)) continue;
    // Retain a materialized copy (decode every column) so it survives the
    // reused scratch state.
    const vals = new Array(n);
    for (let i = 0; i < n; i++) vals[i] = getCol(i);
    if (maxRows) {
      if (results.length < maxRows) results.push(vals);
      else results[ring++ % maxRows] = vals;
    } else {
      results.push(vals);
    }
  }
  return results;
}

// Scan the whole file for records matching `colTypes`, optionally filtered by
// `validator(values, serialTypes) -> boolean`. `maxRows` bounds memory on huge
// tables: once the cap is reached, new rows overwrite the buffer in a ring, so
// the result holds the LAST maxRows rows.
//
// The pre-filter uses strict per-type affinity (cheap, selective) to keep the
// candidate count — and thus the scan's GC pressure — low on large files. If
// the strict pass finds no rows (a non-standard DB that stores columns with
// unexpected serial types), it falls back to the loose affinity pre-filter.
function scanRecords(buf, colTypes, validator, maxRows) {
  const results = _scan(buf, colTypes, validator, maxRows, strictCompatible);
  if (results.length > 0) return results;
  return _scan(buf, colTypes, validator, maxRows, looseCompatible);
}

// Parse column names from a CREATE TABLE statement.
function parseColumns(sql) {
  if (!sql) return [];
  const start = sql.indexOf('(');
  if (start === -1) return [];
  let depth = 0, end = -1;
  for (let i = start; i < sql.length; i++) {
    if (sql[i] === '(') depth++;
    else if (sql[i] === ')') { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end === -1) return [];
  const inner = sql.slice(start + 1, end);
  const parts = [];
  let depth2 = 0, cur = '';
  for (const ch of inner) {
    if (ch === '(') depth2++;
    else if (ch === ')') depth2--;
    if (ch === ',' && depth2 === 0) { parts.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  // Drop table-level constraints that are not columns (UNIQUE(...), PRIMARY
  // KEY(...), CHECK(...), FOREIGN KEY(...), CONSTRAINT ...).
  const CONSTRAINTS = new Set(['UNIQUE', 'PRIMARY', 'CHECK', 'FOREIGN', 'CONSTRAINT']);
  return parts
    .filter((c) => {
      const first = c.trim().split(/\s/)[0].toUpperCase();
      return !CONSTRAINTS.has(first);
    })
    .map((c) => {
      const m = c.match(/^["'\[]?([A-Za-z_][A-Za-z0-9_]*)["'\]]?/);
      return m ? m[1] : c.split(/\s/)[0];
    });
}

// Parse the affinity type of each column from a CREATE TABLE statement.
function parseColumnTypes(sql) {
  const start = sql.indexOf('(');
  if (start === -1) return [];
  let depth = 0, end = -1;
  for (let i = start; i < sql.length; i++) {
    if (sql[i] === '(') depth++;
    else if (sql[i] === ')') { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end === -1) return [];
  const inner = sql.slice(start + 1, end);
  const defs = [];
  let depth2 = 0, cur = '';
  for (const ch of inner) {
    if (ch === '(') depth2++;
    else if (ch === ')') depth2--;
    if (ch === ',' && depth2 === 0) { defs.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  if (cur.trim()) defs.push(cur.trim());
  const CONSTRAINTS = new Set(['UNIQUE', 'PRIMARY', 'CHECK', 'FOREIGN', 'CONSTRAINT']);
  return defs
    .filter((d) => !CONSTRAINTS.has(d.trim().split(/\s/)[0].toUpperCase()))
    .map((d) => {
      const t = d.split(/\s+/).slice(1).join(' ').toUpperCase();
      if (/INT/.test(t)) return 'INTEGER';
      if (/CHAR|CLOB|TEXT/.test(t)) return 'TEXT';
      if (/BLOB/.test(t)) return 'BLOB';
      if (/REAL|FLOA|DOUB/.test(t)) return 'REAL';
      if (/NUMERIC|DECIMAL/.test(t)) return 'NUMERIC';
      return t === '' ? 'BLOB' : 'OTHER';
    });
}

// Scan the file for sqlite_master rows to recover the schema.
function readSchema(buf) {
  const tables = [];
  if (buf.length < 100 || buf.toString('ascii', 0, 15) !== 'SQLite format 3') return tables;
  const pageSize = readUInt16BE(buf, 16) || 4096;
  const numPages = Math.floor(buf.length / pageSize);
  const schemaMap = new Map();
  for (let page = 1; page <= numPages; page++) {
    const pageStart = (page - 1) * pageSize;
    const headerStart = page === 1 ? 100 : pageStart;
    if (headerStart + 8 > buf.length) break;
    const t = buf[headerStart];
    if (t !== 0x05 && t !== 0x0d) continue;
    const numCells = readUInt16BE(buf, headerStart + 3);
    const cellPtrStart = headerStart + 8;
    for (let i = 0; i < numCells; i++) {
      const cp = readUInt16BE(buf, cellPtrStart + i * 2);
      const abs = pageStart + cp;
      if (abs + 2 > buf.length) continue;
      const [, after] = readVarint(buf, abs);
      const [, after2] = readVarint(buf, after);
      let row;
      try { row = decodeRecord(buf, after2); } catch (e) { continue; }
      if (row.length >= 5 && (row[0] === 'table' || row[0] === 'index')
        && typeof row[4] === 'string' && /^CREATE\s+(TABLE|INDEX)/i.test(row[4])) {
        schemaMap.set(row[1], { type: row[0], name: row[1], rootpage: row[3], sql: row[4] });
      }
    }
  }
  for (const info of schemaMap.values()) {
    if (info.type !== 'table' || info.name.startsWith('sqlite_')) continue;
    tables.push({
      name: info.name,
      rootpage: info.rootpage,
      sql: info.sql,
      columns: parseColumns(info.sql),
      colTypes: parseColumnTypes(info.sql),
    });
  }
  return tables;
}

function decodeRecord(buf, offset) {
  const [headerSize, afterHdrSize] = readVarint(buf, offset);
  if (headerSize < 1 || headerSize > 100000) return [];
  const dataStart = offset + headerSize;
  const serialTypes = [];
  let so = afterHdrSize;
  const headerEnd = offset + headerSize;
  while (so < headerEnd) {
    const [st, so2] = readVarint(buf, so);
    serialTypes.push(st);
    so = so2;
  }
  let vo = dataStart;
  const values = [];
  for (const st of serialTypes) {
    const sz = serialSize(st);
    values.push(decodeValue(buf, vo, st));
    vo += sz;
  }
  return values;
}

module.exports = { readSchema, scanRecords, parseColumns, parseColumnTypes, readVarint, decodeValue, decodeRecord };
