'use strict';

/**
 * Aegis signature engine (no external dependencies — Node builtins only).
 *
 * Public API:
 *   load(signaturesDir)              -> {version, sha256:Map, rules:[], source, skipped}
 *   checkFile(filePath, db)          -> {name, kind:'sha256'|'yara'} | null   (synchronous)
 *   checkBuffer(buffer, db)          -> {name, kind:'sha256'|'yara'} | null   (synchronous)
 *   parseYara(text)                  -> [rule]  (broken rules are skipped, never thrown)
 *   addLocalSignature(db, sha256, name)
 *
 * Notes:
 * - checkFile()/checkBuffer() are synchronous on purpose: results may be used
 *   directly or awaited (`await checkFile(...)` works either way).
 * - The EICAR test string is intentionally NOT present in this file (anti-virus
 *   products delete sources that embed it). Tests use AEGIS-TEST-MARKER-V1.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ------------------------------------------------------------------ *
 * Tunables
 * ------------------------------------------------------------------ */

// String scanning window: files bigger than this are scanned head + tail only.
const STRING_SCAN_LIMIT = 2 * 1024 * 1024; // 2 MB head
const TAIL_SCAN_SIZE = 256 * 1024; // 256 KB tail
// Files above this size are never hashed (string scan only).
const MAX_HASH_SIZE = 1024 * 1024 * 1024; // 1 GB
// Hashing reads the whole file in chunks (bounded memory).
const HASH_CHUNK_SIZE = 1024 * 1024; // 1 MB

const DEFAULT_SIGNATURES_DIR = path.join(__dirname, '..', 'signatures');
const DB_FILE = 'db.json';
const RULES_FILE = 'rules.yar';

const SECTION_WORDS = new Set(['strings', 'condition', 'meta']);
const HEX_CHAR_RE = /^[0-9a-fA-F]$/;

/* ------------------------------------------------------------------ *
 * Errors
 * ------------------------------------------------------------------ */

// Thrown internally while parsing; always caught per-rule (never escapes).
class ParseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ParseError';
  }
}

/* ------------------------------------------------------------------ *
 * Tokenizer (tolerant: comments, unterminated strings, junk are fine)
 * ------------------------------------------------------------------ */

function tokenize(text) {
  const tokens = [];
  const n = text.length;
  let i = 0;

  while (i < n) {
    const c = text[i];

    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      i += 1;
      continue;
    }

    // Line comments: // ... (Turkish or English, anything goes)
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i += 1;
      continue;
    }
    // Block comments: /* ... */
    if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }

    // String literal "..."
    if (c === '"') {
      let j = i + 1;
      let value = '';
      while (j < n) {
        const ch = text[j];
        if (ch === '\\' && j + 1 < n) {
          value += text[j + 1];
          j += 2;
          continue;
        }
        if (ch === '"' || ch === '\n') break;
        value += ch;
        j += 1;
      }
      tokens.push({ t: 'str', v: value });
      i = text[j] === '"' ? j + 1 : j;
      continue;
    }

    // Hex block { AA BB ?? CC } — captured raw, but only where a value is
    // expected (`$a = { ... }`), so rule bodies keep structural braces.
    // Captured with brace depth awareness (tolerates nested braces).
    if (c === '{') {
      const prev = tokens[tokens.length - 1];
      const isValue = Boolean(prev) && prev.t === 'punct' && prev.v === '=';
      if (!isValue) {
        tokens.push({ t: 'punct', v: c });
        i += 1;
        continue;
      }
      let depth = 1;
      let j = i + 1;
      while (j < n && depth > 0) {
        if (text[j] === '{') depth += 1;
        else if (text[j] === '}') depth -= 1;
        if (depth === 0) break;
        j += 1;
      }
      tokens.push({ t: 'hex', v: text.slice(i + 1, j) });
      i = j < n ? j + 1 : n;
      continue;
    }

    // $ident (string reference) and #ident (match count)
    if (c === '$' || c === '#') {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(text[j])) j += 1;
      if (j === i + 1) {
        tokens.push({ t: 'punct', v: c });
        i += 1;
        continue;
      }
      tokens.push({ t: c === '$' ? 'var' : 'count', v: text.slice(i + 1, j) });
      i = j;
      continue;
    }

    // Keywords / identifiers
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(text[j])) j += 1;
      tokens.push({ t: 'word', v: text.slice(i, j) });
      i = j;
      continue;
    }

    // Numbers (decimal or 0x hex)
    if (/[0-9]/.test(c)) {
      let j = i;
      if (c === '0' && (text[i + 1] === 'x' || text[i + 1] === 'X')) {
        j = i + 2;
        while (j < n && HEX_CHAR_RE.test(text[j])) j += 1;
        tokens.push({ t: 'num', v: parseInt(text.slice(i, j), 16) });
      } else {
        while (j < n && /[0-9]/.test(text[j])) j += 1;
        tokens.push({ t: 'num', v: parseInt(text.slice(i, j), 10) });
      }
      i = j;
      continue;
    }

    tokens.push({ t: 'punct', v: c });
    i += 1;
  }

  return tokens;
}

function describeToken(tok) {
  if (!tok) return 'end of input';
  switch (tok.t) {
    case 'word':
      return `word "${tok.v}"`;
    case 'str':
      return `string "${tok.v}"`;
    case 'hex':
      return 'hex block';
    case 'var':
      return `string identifier "$${tok.v}"`;
    case 'count':
      return `count identifier "#${tok.v}"`;
    case 'num':
      return `number ${tok.v}`;
    default:
      return `symbol "${tok.v}"`;
  }
}

function isPunct(tok, v) {
  return Boolean(tok) && tok.t === 'punct' && tok.v === v;
}

function isWord(tok, v) {
  return Boolean(tok) && tok.t === 'word' && tok.v === v;
}

/* ------------------------------------------------------------------ *
 * Pattern compilation
 * ------------------------------------------------------------------ */

function asciiLower(buf) {
  const out = Buffer.from(buf);
  for (let i = 0; i < out.length; i += 1) {
    const c = out[i];
    if (c >= 0x41 && c <= 0x5a) out[i] = c + 0x20;
  }
  return out;
}

function makeTextPattern(id, value) {
  if (value.length === 0) {
    throw new ParseError(`string $${id}: empty text patterns are not supported`);
  }
  const bytes = Buffer.from(value, 'utf8');
  return {
    id,
    kind: 'text',
    bytes,
    mask: null,
    nocase: false,
    lowerBytes: asciiLower(bytes)
  };
}

function makeHexPattern(id, raw) {
  const compact = raw.replace(/\s+/g, '');
  if (compact.length === 0 || compact.length % 2 !== 0) {
    throw new ParseError(`string $${id}: malformed hex pattern`);
  }
  const n = compact.length / 2;
  const bytes = Buffer.alloc(n);
  const mask = Buffer.alloc(n);
  for (let i = 0; i < n; i += 1) {
    let value = 0;
    let maskByte = 0;
    for (let half = 0; half < 2; half += 1) {
      const ch = compact[i * 2 + half];
      if (ch === '?') continue;
      if (!HEX_CHAR_RE.test(ch)) {
        throw new ParseError(`string $${id}: invalid hex character "${ch}"`);
      }
      const nibble = parseInt(ch, 16);
      value |= nibble << (half === 0 ? 4 : 0);
      maskByte |= half === 0 ? 0xf0 : 0x0f;
    }
    bytes[i] = value;
    mask[i] = maskByte;
  }
  const exact = mask.every((m) => m === 0xff);
  return {
    id,
    kind: 'hex',
    bytes,
    mask: exact ? null : mask, // fully exact hex strings take the fast path
    nocase: false,
    lowerBytes: bytes
  };
}

/* ------------------------------------------------------------------ *
 * Condition parsing (recursive descent, limited to the rule body)
 * ------------------------------------------------------------------ */

function parseConditionExpr(tokens, pos, limit) {
  return parseOrExpr(tokens, pos, limit);
}

function parseOrExpr(tokens, pos, limit) {
  let left = parseAndExpr(tokens, pos, limit);
  while (pos < limit && isWord(tokens[left.pos], 'or')) {
    const right = parseAndExpr(tokens, left.pos + 1, limit);
    left = { node: { type: 'or', left: left.node, right: right.node }, pos: right.pos };
  }
  return left;
}

function parseAndExpr(tokens, pos, limit) {
  let left = parseNotExpr(tokens, pos, limit);
  while (pos < limit && isWord(tokens[left.pos], 'and')) {
    const right = parseNotExpr(tokens, left.pos + 1, limit);
    left = { node: { type: 'and', left: left.node, right: right.node }, pos: right.pos };
  }
  return left;
}

function parseNotExpr(tokens, pos, limit) {
  if (pos < limit && isWord(tokens[pos], 'not')) {
    const inner = parseNotExpr(tokens, pos + 1, limit);
    return { node: { type: 'not', operand: inner.node }, pos: inner.pos };
  }
  return parsePrimaryExpr(tokens, pos, limit);
}

function parsePrimaryExpr(tokens, pos, limit) {
  const tok = tokens[pos];
  if (pos >= limit || !tok) throw new ParseError('condition ended unexpectedly');

  // Parentheses
  if (isPunct(tok, '(')) {
    const inner = parseOrExpr(tokens, pos + 1, limit);
    if (!isPunct(tokens[inner.pos], ')')) throw new ParseError('expected ")" in condition');
    return { node: inner.node, pos: inner.pos + 1 };
  }

  // $a
  if (tok.t === 'var') {
    if (isWord(tokens[pos + 1], 'of')) {
      throw new ParseError(`unsupported construct "$${tok.v} of ..."`);
    }
    return { node: { type: 'string', id: tok.v }, pos: pos + 1 };
  }

  // #a == N
  if (tok.t === 'count') return parseCountExpr(tokens, pos, limit);

  if (tok.t === 'word') {
    // any of them / all of them
    if (tok.v === 'any' || tok.v === 'all') {
      if (!isWord(tokens[pos + 1], 'of') || !isWord(tokens[pos + 2], 'them')) {
        throw new ParseError(`unsupported quantifier (only "any of them" / "all of them")`);
      }
      return { node: { type: 'quant', q: tok.v }, pos: pos + 3 };
    }
    if (tok.v === 'true' || tok.v === 'false') {
      return { node: { type: 'const', value: tok.v === 'true' }, pos: pos + 1 };
    }
    throw new ParseError(`unsupported condition atom "${tok.v}"`);
  }

  throw new ParseError(`unexpected ${describeToken(tok)} in condition`);
}

function parseCountExpr(tokens, pos, limit) {
  const id = tokens[pos].v;
  const a = tokens[pos + 1];
  const b = tokens[pos + 2];
  let op = null;
  let next = -1;

  if (a && a.t === 'punct') {
    if (a.v === '=') {
      op = '==';
      next = isPunct(b, '=') ? pos + 3 : pos + 2;
    } else if (a.v === '!' && isPunct(b, '=')) {
      op = '!=';
      next = pos + 3;
    } else if (a.v === '<') {
      op = isPunct(b, '=') ? '<=' : '<';
      next = isPunct(b, '=') ? pos + 3 : pos + 2;
    } else if (a.v === '>') {
      op = isPunct(b, '=') ? '>=' : '>';
      next = isPunct(b, '=') ? pos + 3 : pos + 2;
    }
  }
  if (!op) throw new ParseError(`#${id}: expected a comparison operator`);

  const numTok = tokens[next];
  if (next >= limit || !numTok || numTok.t !== 'num') {
    throw new ParseError(`#${id}: expected a number after "${op}"`);
  }
  return { node: { type: 'count', id, op, value: numTok.v }, pos: next + 1 };
}

/* ------------------------------------------------------------------ *
 * Rule assembly
 * ------------------------------------------------------------------ */

function parseStringDecls(tokens, pos, to, rule) {
  const seen = new Set(rule.strings.map((s) => s.id));
  while (pos < to) {
    const tok = tokens[pos];
    if (tok.t === 'word' && SECTION_WORDS.has(tok.v)) break;
    if (tok.t !== 'var') {
      throw new ParseError(`expected a $string declaration, found ${describeToken(tok)}`);
    }
    const id = tok.v;
    if (seen.has(id)) throw new ParseError(`duplicate string identifier $${id}`);
    if (!isPunct(tokens[pos + 1], '=')) throw new ParseError(`expected "=" after $${id}`);

    const valueTok = tokens[pos + 2];
    if (!valueTok || (valueTok.t !== 'str' && valueTok.t !== 'hex')) {
      throw new ParseError(`unsupported value for $${id}`);
    }
    const pattern =
      valueTok.t === 'str' ? makeTextPattern(id, valueTok.v) : makeHexPattern(id, valueTok.v);
    pos += 3;

    // Modifiers: nocase is honoured, everything else (wide, ascii, xor(...),
    // fullword, base64, ...) is tolerated and ignored.
    while (pos < to) {
      const mod = tokens[pos];
      if (mod.t !== 'word' || SECTION_WORDS.has(mod.v)) break;
      if (mod.v.toLowerCase() === 'nocase') {
        pattern.nocase = true;
        pos += 1;
        continue;
      }
      if (mod.v.toLowerCase() === 'xor') {
        pos += 1;
        if (isPunct(tokens[pos], '(')) {
          let depth = 0;
          while (pos < to) {
            if (isPunct(tokens[pos], '(')) depth += 1;
            else if (isPunct(tokens[pos], ')')) {
              depth -= 1;
              if (depth === 0) {
                pos += 1;
                break;
              }
            }
            pos += 1;
          }
        }
        continue;
      }
      pos += 1; // any other (known or unknown) modifier: ignore
    }

    rule.strings.push(pattern);
    seen.add(id);
  }
  return pos;
}

function skipMeta(tokens, pos, to) {
  while (pos < to) {
    const tok = tokens[pos];
    if (tok.t === 'word' && SECTION_WORDS.has(tok.v)) break;
    pos += 1;
  }
  return pos;
}

function parseSections(tokens, from, to, rule) {
  let pos = from;
  let condition = null;

  while (pos < to) {
    const tok = tokens[pos];
    if (tok.t === 'word' && SECTION_WORDS.has(tok.v)) {
      const keyword = tok.v;
      if (!isPunct(tokens[pos + 1], ':')) throw new ParseError(`expected ":" after "${keyword}"`);
      if (keyword === 'strings') {
        pos = parseStringDecls(tokens, pos + 2, to, rule);
      } else if (keyword === 'condition') {
        const parsed = parseConditionExpr(tokens, pos + 2, to);
        condition = parsed.node;
        pos = parsed.pos;
      } else {
        pos = skipMeta(tokens, pos + 2, to);
      }
      continue;
    }
    throw new ParseError(`unexpected ${describeToken(tok)} in rule body`);
  }

  if (!condition) throw new ParseError('rule has no condition section');
  rule.condition = condition;
}

function analyzeCondition(node) {
  const ids = new Set();
  const countIds = new Set();
  let usesThem = false;

  const walk = (n) => {
    if (!n) return;
    switch (n.type) {
      case 'string':
        ids.add(n.id);
        break;
      case 'count':
        ids.add(n.id);
        countIds.add(n.id);
        break;
      case 'quant':
        usesThem = true;
        break;
      case 'not':
        walk(n.operand);
        break;
      case 'and':
      case 'or':
        walk(n.left);
        walk(n.right);
        break;
      default:
        break;
    }
  };
  walk(node);
  return { ids, countIds, usesThem };
}

function findRuleEnd(tokens, from) {
  for (let i = from; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if (isPunct(tok, '}')) return i;
    if (tok.t === 'word' && tok.v === 'rule') return -1; // unterminated rule body
  }
  return -1;
}

function parseRule(tokens, start) {
  let pos = start + 1;

  const nameTok = tokens[pos];
  if (!nameTok || nameTok.t !== 'word') throw new ParseError('rule name is missing');
  const name = nameTok.v;
  pos += 1;

  // Optional tags: `rule Foo : tag1 tag2 {`
  if (isPunct(tokens[pos], ':')) {
    pos += 1;
    while (pos < tokens.length && tokens[pos].t === 'word') pos += 1;
  }
  if (!isPunct(tokens[pos], '{')) {
    throw new ParseError(`rule "${name}": expected "{" after rule header`);
  }

  const end = findRuleEnd(tokens, pos + 1);
  if (end === -1) throw new ParseError(`rule "${name}": missing closing "}"`);

  const rule = { name, strings: [], condition: null };
  parseSections(tokens, pos + 1, end, rule);
  rule.analysis = analyzeCondition(rule.condition);

  // Every referenced $identifier must be declared in the strings section.
  const declared = new Set(rule.strings.map((s) => s.id));
  for (const id of rule.analysis.ids) {
    if (!declared.has(id)) throw new ParseError(`rule "${name}": undeclared string $${id}`);
  }

  return { rule, end: end + 1 };
}

function guessRuleName(tokens, start) {
  const tok = tokens[start + 1];
  return tok && tok.t === 'word' ? tok.v : null;
}

/**
 * Parse a YARA-subset rules file.
 * Returns an array of rules. Broken/unsupported rules are skipped and
 * recorded on `rules.skipped` as {rule, error} — parseYara never throws.
 */
function parseYara(text) {
  const rules = [];
  rules.skipped = [];
  if (typeof text !== 'string' || text.length === 0) return rules;

  let tokens;
  try {
    tokens = tokenize(text);
  } catch (err) {
    rules.skipped.push({ rule: null, error: String(err.message || err) });
    return rules;
  }

  let i = 0;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (tok.t === 'word' && tok.v === 'rule') {
      try {
        const parsed = parseRule(tokens, i);
        rules.push(parsed.rule);
        i = parsed.end;
      } catch (err) {
        rules.skipped.push({
          rule: guessRuleName(tokens, i),
          error: String(err.message || err)
        });
        i += 1; // resync: scan forward for the next `rule` keyword
      }
      continue;
    }
    i += 1; // top-level `import "..."`, `include "..."` and junk are ignored
  }

  return rules;
}

/* ------------------------------------------------------------------ *
 * Matching
 * ------------------------------------------------------------------ */

function countIndexOf(haystack, needle, limit) {
  if (needle.length === 0 || needle.length > haystack.length) return 0;
  let count = 0;
  let start = 0;
  while (count < limit) {
    const idx = haystack.indexOf(needle, start);
    if (idx === -1) break;
    count += 1;
    start = idx + needle.length; // non-overlapping occurrences
  }
  return count;
}

function countMasked(haystack, bytes, mask, limit) {
  const len = bytes.length;
  if (len === 0 || len > haystack.length) return 0;
  const last = haystack.length - len;
  let count = 0;
  let i = 0;
  while (i <= last && count < limit) {
    let j = 0;
    while (j < len && (haystack[i + j] & mask[j]) === bytes[j]) j += 1;
    if (j === len) {
      count += 1;
      i += len;
    } else {
      i += 1;
    }
  }
  return count;
}

function countMatches(haystack, pattern, lowerHaystack, limit) {
  if (pattern.mask) return countMasked(haystack, pattern.bytes, pattern.mask, limit);
  if (pattern.nocase) {
    if (!lowerHaystack) return 0;
    return countIndexOf(lowerHaystack, pattern.lowerBytes, limit);
  }
  return countIndexOf(haystack, pattern.bytes, limit);
}

function compareCount(actual, op, expected) {
  switch (op) {
    case '==':
      return actual === expected;
    case '!=':
      return actual !== expected;
    case '<':
      return actual < expected;
    case '<=':
      return actual <= expected;
    case '>':
      return actual > expected;
    case '>=':
      return actual >= expected;
    default:
      return false;
  }
}

function evaluateCondition(node, counts) {
  switch (node.type) {
    case 'const':
      return node.value;
    case 'string':
      return (counts.get(node.id) || 0) > 0;
    case 'not':
      return !evaluateCondition(node.operand, counts);
    case 'and':
      return evaluateCondition(node.left, counts) && evaluateCondition(node.right, counts);
    case 'or':
      return evaluateCondition(node.left, counts) || evaluateCondition(node.right, counts);
    case 'quant': {
      if (counts.size === 0) return false; // no strings -> never match
      for (const value of counts.values()) {
        if (node.q === 'any' && value > 0) return true;
        if (node.q === 'all' && value === 0) return false;
      }
      return node.q === 'all';
    }
    case 'count':
      return compareCount(counts.get(node.id) || 0, node.op, node.value);
    default:
      return false;
  }
}

function ruleMatches(rule, buffer) {
  const analysis = rule.analysis || analyzeCondition(rule.condition);

  // Scan only what the condition needs (all strings when `... of them` is used).
  const scan = analysis.usesThem ? rule.strings : rule.strings.filter((s) => analysis.ids.has(s.id));
  const needsLower = scan.some((p) => p.nocase && !p.mask);
  const lowerBuffer = needsLower ? asciiLower(buffer) : null;

  const counts = new Map(rule.strings.map((s) => [s.id, 0]));
  for (const pattern of scan) {
    const limit = analysis.countIds.has(pattern.id) ? Infinity : 1;
    counts.set(pattern.id, countMatches(buffer, pattern, lowerBuffer, limit));
  }
  return evaluateCondition(rule.condition, counts);
}

function matchRules(buffer, rules) {
  if (!Array.isArray(rules) || rules.length === 0 || buffer.length === 0) return null;
  for (const rule of rules) {
    if (!rule || !Array.isArray(rule.strings) || !rule.condition) continue;
    try {
      if (ruleMatches(rule, buffer)) return { name: rule.name, kind: 'yara' };
    } catch {
      // A broken compiled rule must never break scanning.
    }
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * SHA-256 helpers (Map or plain object are both accepted)
 * ------------------------------------------------------------------ */

function shaMapSize(map) {
  if (!map) return 0;
  if (typeof map.size === 'number') return map.size;
  return typeof map === 'object' ? Object.keys(map).length : 0;
}

function shaLookup(map, hash) {
  if (!map) return null;
  if (typeof map.get === 'function') {
    const name = map.get(hash);
    return typeof name === 'string' ? name : null;
  }
  if (typeof map === 'object' && Object.prototype.hasOwnProperty.call(map, hash)) {
    const name = map[hash];
    return typeof name === 'string' ? name : null;
  }
  return null;
}

// Synchronous full-file hashing in 1MB chunks (bounded memory).
function hashFileSync(filePath) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  try {
    const chunk = Buffer.allocUnsafe(HASH_CHUNK_SIZE);
    let position = 0;
    for (;;) {
      const bytesRead = fs.readSync(fd, chunk, 0, HASH_CHUNK_SIZE, position);
      if (bytesRead <= 0) break;
      hash.update(chunk.subarray(0, bytesRead));
      position += bytesRead;
      if (bytesRead < HASH_CHUNK_SIZE) break;
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

function readRangeSync(filePath, start, length) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.alloc(length);
    let offset = 0;
    while (offset < length) {
      const bytesRead = fs.readSync(fd, buffer, offset, length - offset, start + offset);
      if (bytesRead <= 0) break;
      offset += bytesRead;
    }
    return offset === length ? buffer : buffer.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
}

// Head (2MB) for big files, plus tail (256KB) so recent payloads are covered.
function readScanWindow(filePath, size) {
  if (size <= STRING_SCAN_LIMIT) return fs.readFileSync(filePath);
  const head = readRangeSync(filePath, 0, STRING_SCAN_LIMIT);
  const tail = readRangeSync(filePath, size - TAIL_SCAN_SIZE, TAIL_SCAN_SIZE);
  return Buffer.concat([head, tail]);
}

/* ------------------------------------------------------------------ *
 * Public API
 * ------------------------------------------------------------------ */

/**
 * Load `db.json` + `rules.yar` from a signatures directory.
 * Missing/broken files are tolerated (recorded on `result.skipped`).
 *
 * @returns {{version: string, updated: number, sha256: Map<string,string>,
 *            rules: Array, source: object, skipped: Array}}
 */
function load(signaturesDir) {
  const dir = signaturesDir || DEFAULT_SIGNATURES_DIR;
  const dbPath = path.join(dir, DB_FILE);
  const rulesPath = path.join(dir, RULES_FILE);

  const result = {
    version: '0',
    updated: 0,
    sha256: new Map(),
    rules: [],
    source: { dir, dbFile: null, rulesFile: null, loadedAt: Date.now() },
    skipped: []
  };

  try {
    const json = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    if (json && typeof json === 'object') {
      if (json.version !== undefined && json.version !== null) {
        result.version = String(json.version);
      }
      if (Number.isFinite(json.updated)) result.updated = json.updated;
      if (json.sha256 && typeof json.sha256 === 'object') {
        for (const [key, value] of Object.entries(json.sha256)) {
          if (typeof key === 'string' && typeof value === 'string') {
            result.sha256.set(key.trim().toLowerCase(), value);
          }
        }
      }
      result.source.dbFile = dbPath;
    }
  } catch (err) {
    if (err && err.code !== 'ENOENT') {
      result.skipped.push({ file: DB_FILE, error: String(err.message || err) });
    }
  }

  try {
    const text = fs.readFileSync(rulesPath, 'utf8');
    const rules = parseYara(text);
    result.rules = rules;
    result.source.rulesFile = rulesPath;
    for (const skipped of rules.skipped || []) {
      result.skipped.push({ file: RULES_FILE, rule: skipped.rule, error: skipped.error });
    }
  } catch (err) {
    if (err && err.code !== 'ENOENT') {
      result.skipped.push({ file: RULES_FILE, error: String(err.message || err) });
    }
  }

  return result;
}

/**
 * Scan a file. String scan uses the first 2MB (plus the last 256KB for big
 * files); SHA-256 always covers the whole file unless it is bigger than 1GB.
 *
 * @returns {{name: string, kind: 'sha256'|'yara'} | null} (synchronous)
 */
function checkFile(filePath, db) {
  if (!db || typeof filePath !== 'string') return null;

  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return null;
  }
  if (!stat.isFile()) return null;

  try {
    let hash = null;
    if (stat.size <= MAX_HASH_SIZE && shaMapSize(db.sha256) > 0) {
      hash = hashFileSync(filePath);
      const shaName = shaLookup(db.sha256, hash);
      if (shaName) return { name: shaName, kind: 'sha256' };
    }
    return matchRules(readScanWindow(filePath, stat.size), db.rules);
  } catch {
    return null; // unreadable/vanished file: nothing to report
  }
}

/**
 * Scan an in-memory buffer (same rules as checkFile, no windowing needed).
 *
 * @returns {{name: string, kind: 'sha256'|'yara'} | null} (synchronous)
 */
function checkBuffer(buffer, db) {
  if (!db || buffer === null || buffer === undefined) return null;
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);

  if (shaMapSize(db.sha256) > 0) {
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const shaName = shaLookup(db.sha256, hash);
    if (shaName) return { name: shaName, kind: 'sha256' };
  }
  return matchRules(buf, db.rules);
}

/**
 * Register an extra SHA-256 signature on a loaded db (used by tests/UI).
 * Returns the same db object for chaining.
 */
function addLocalSignature(db, sha256, name) {
  if (!db || typeof sha256 !== 'string') return db || null;
  if (!db.sha256 || typeof db.sha256 !== 'object') db.sha256 = new Map();
  const key = sha256.trim().toLowerCase();
  const label = typeof name === 'string' && name ? name : 'Local.Signature';
  if (typeof db.sha256.set === 'function') db.sha256.set(key, label);
  else db.sha256[key] = label;
  return db;
}

/**
 * String/yara taraması (hash hesaplamadan) — hash önbelleği kullanan
 * tarama motorunun tekrar hesap yapmaması için.
 */
function checkStrings(filePath, db) {
  if (!db || typeof filePath !== 'string' || !db.rules || db.rules.length === 0) return null;
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;
    return matchRules(readScanWindow(filePath, stat.size), db.rules);
  } catch {
    return null;
  }
}

module.exports = {
  load,
  checkFile,
  checkBuffer,
  checkStrings,
  parseYara,
  addLocalSignature
};
