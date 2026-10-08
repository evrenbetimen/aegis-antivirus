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
        let value = parseInt(text.slice(i, j), 10);
        // Size suffixes: 200KB, 2MB
        if (/^[KM]B/.test(text.slice(j, j + 2)) && !/[A-Za-z0-9_]/.test(text[j + 2] || '')) {
          value *= text[j] === 'K' ? 1024 : 1024 * 1024;
          j += 2;
        }
        tokens.push({ t: 'num', v: value });
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
  return {
    id,
    kind: 'text',
    text: value,
    nocase: false,
    ascii: false,
    wide: false,
    fullword: false,
    variants: null
  };
}

// Applied once all modifiers are known: ascii/wide decide which byte forms
// are searched (YARA default is ascii only; `wide` alone means UTF-16LE only).
function finalizeTextPattern(p) {
  const forms = [];
  if (!p.wide || p.ascii) forms.push({ bytes: Buffer.from(p.text, 'utf8'), step: 1 });
  if (p.wide) forms.push({ bytes: Buffer.from(p.text, 'utf16le'), step: 2 });
  p.variants = forms.map((f) => ({ bytes: f.bytes, lowerBytes: asciiLower(f.bytes), step: f.step }));
  return p;
}

function hexByteRe(v) {
  return '\\x' + v.toString(16).padStart(2, '0');
}

// One hex byte token ("AA", "A?", "?A", "??") → regex atom over a latin1 string.
function hexAtom(id, hi, lo) {
  const okHi = hi === '?' || HEX_CHAR_RE.test(hi);
  const okLo = lo === '?' || HEX_CHAR_RE.test(lo);
  if (!okHi || !okLo) throw new ParseError(`string $${id}: invalid hex character "${okHi ? lo : hi}"`);
  if (hi === '?' && lo === '?') return { re: '[\\s\\S]', exact: null };
  if (hi !== '?' && lo !== '?') {
    const v = parseInt(hi + lo, 16);
    return { re: hexByteRe(v), exact: v };
  }
  if (lo === '?') {
    const base = parseInt(hi, 16) << 4;
    return { re: `[${hexByteRe(base)}-${hexByteRe(base + 15)}]`, exact: null };
  }
  const low = parseInt(lo, 16);
  let cls = '';
  for (let h = 0; h < 16; h += 1) cls += hexByteRe((h << 4) | low);
  return { re: `[${cls}]`, exact: null };
}

/**
 * Hex strings: bytes, ?? / nibble wildcards, ~XX, jumps [n] [n-m] [n-] [-]
 * and alternatives ( AA | BB CC ). Fully exact strings keep a byte buffer
 * (indexOf fast path); everything else compiles to a RegExp over latin1.
 */
function makeHexPattern(id, raw) {
  const src = raw.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, ' ').replace(/\s+/g, '');
  if (src.length === 0) throw new ParseError(`string $${id}: malformed hex pattern`);

  let re = '';
  const exactBytes = [];
  let allExact = true;
  let depth = 0;
  let atoms = 0;
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '[') {
      const close = src.indexOf(']', i);
      if (close === -1) throw new ParseError(`string $${id}: malformed hex pattern`);
      const m = /^(\d*)(-?)(\d*)$/.exec(src.slice(i + 1, close));
      if (!m || (!m[2] && !m[1])) throw new ParseError(`string $${id}: invalid jump`);
      const lo = m[1] ? Number(m[1]) : 0;
      if (!m[2]) re += `[\\s\\S]{${lo}}`;
      else if (m[3]) {
        const hi = Number(m[3]);
        if (hi < lo) throw new ParseError(`string $${id}: invalid jump`);
        re += `[\\s\\S]{${lo},${hi}}?`;
      } else re += `[\\s\\S]{${lo},}?`;
      allExact = false;
      i = close + 1;
      continue;
    }
    if (c === '(') {
      re += '(?:';
      depth += 1;
      allExact = false;
      i += 1;
      continue;
    }
    if (c === '|') {
      if (depth === 0) throw new ParseError(`string $${id}: "|" outside of an alternative`);
      re += '|';
      i += 1;
      continue;
    }
    if (c === ')') {
      if (depth === 0) throw new ParseError(`string $${id}: malformed hex pattern`);
      re += ')';
      depth -= 1;
      i += 1;
      continue;
    }
    if (c === '~') {
      if (i + 2 >= src.length) throw new ParseError(`string $${id}: malformed hex pattern`);
      const a = hexAtom(id, src[i + 1], src[i + 2]);
      if (a.exact === null) throw new ParseError(`string $${id}: unsupported "~" with wildcard`);
      re += `[^${hexByteRe(a.exact)}]`;
      allExact = false;
      atoms += 1;
      i += 3;
      continue;
    }
    if (i + 1 >= src.length) throw new ParseError(`string $${id}: malformed hex pattern`);
    const a = hexAtom(id, c, src[i + 1]);
    re += a.re;
    if (a.exact === null) allExact = false;
    else exactBytes.push(a.exact);
    atoms += 1;
    i += 2;
  }
  if (depth !== 0 || atoms === 0) throw new ParseError(`string $${id}: malformed hex pattern`);

  if (allExact) {
    return { id, kind: 'hex', bytes: Buffer.from(exactBytes), regex: null, nocase: false };
  }
  let regex;
  try {
    regex = new RegExp(re, 'g');
  } catch {
    throw new ParseError(`string $${id}: malformed hex pattern`);
  }
  return { id, kind: 'hex', bytes: null, regex, nocase: false };
}

/* ------------------------------------------------------------------ *
 * Condition parsing (recursive descent, limited to the rule body)
 *
 * Booleans: and, or, not, ( ), true, false, $a, $a at <expr>
 * Numbers:  literals (0x.., KB/MB), filesize, #a, uint8/16/32[be](<expr>),
 *           int8/16/32[be](<expr>), + - * \ % & | ^ << >>, unary - ~
 * Compare:  == != < <= > >=
 * Sets:     any|all|none|<n> of them | ( $a, $b*, $* )
 * Anything else (modules, regex, `in`, `for`, rule references) is rejected so
 * the rule is skipped instead of being mis-evaluated.
 * ------------------------------------------------------------------ */

const INT_FUNCS = new Map([
  ['uint8', { size: 1, signed: false, be: false }],
  ['uint16', { size: 2, signed: false, be: false }],
  ['uint32', { size: 4, signed: false, be: false }],
  ['uint8be', { size: 1, signed: false, be: true }],
  ['uint16be', { size: 2, signed: false, be: true }],
  ['uint32be', { size: 4, signed: false, be: true }],
  ['int8', { size: 1, signed: true, be: false }],
  ['int16', { size: 2, signed: true, be: false }],
  ['int32', { size: 4, signed: true, be: false }],
  ['int8be', { size: 1, signed: true, be: true }],
  ['int16be', { size: 2, signed: true, be: true }],
  ['int32be', { size: 4, signed: true, be: true }]
]);

function parseConditionExpr(tokens, pos, limit) {
  return parseOrExpr(tokens, pos, limit);
}

function parseOrExpr(tokens, pos, limit) {
  let left = parseAndExpr(tokens, pos, limit);
  while (left.pos < limit && isWord(tokens[left.pos], 'or')) {
    const right = parseAndExpr(tokens, left.pos + 1, limit);
    left = { node: { type: 'or', left: left.node, right: right.node }, pos: right.pos };
  }
  return left;
}

function parseAndExpr(tokens, pos, limit) {
  let left = parseNotExpr(tokens, pos, limit);
  while (left.pos < limit && isWord(tokens[left.pos], 'and')) {
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
  return parseCompareExpr(tokens, pos, limit);
}

// Reads a comparison operator at pos (single-char punct tokens), or null.
function readCompareOp(tokens, pos, limit) {
  if (pos >= limit) return null;
  const a = tokens[pos];
  const b = tokens[pos + 1];
  if (!a || a.t !== 'punct') return null;
  if (a.v === '=') return isPunct(b, '=') ? { op: '==', next: pos + 2 } : { op: '==', next: pos + 1 };
  if (a.v === '!' && isPunct(b, '=')) return { op: '!=', next: pos + 2 };
  if (a.v === '<' && !isPunct(b, '<')) {
    return isPunct(b, '=') ? { op: '<=', next: pos + 2 } : { op: '<', next: pos + 1 };
  }
  if (a.v === '>' && !isPunct(b, '>')) {
    return isPunct(b, '=') ? { op: '>=', next: pos + 2 } : { op: '>', next: pos + 1 };
  }
  return null;
}

function parseCompareExpr(tokens, pos, limit) {
  const left = parseBitExpr(tokens, pos, limit);
  const op = readCompareOp(tokens, left.pos, limit);
  if (!op) return left;
  const right = parseBitExpr(tokens, op.next, limit);
  return { node: { type: 'cmp', op: op.op, left: left.node, right: right.node }, pos: right.pos };
}

function parseBitExpr(tokens, pos, limit) {
  let left = parseShiftExpr(tokens, pos, limit);
  for (;;) {
    const tok = tokens[left.pos];
    if (left.pos >= limit || !tok || tok.t !== 'punct' || !['&', '|', '^'].includes(tok.v)) return left;
    const right = parseShiftExpr(tokens, left.pos + 1, limit);
    left = { node: { type: 'bin', op: tok.v, left: left.node, right: right.node }, pos: right.pos };
  }
}

function parseShiftExpr(tokens, pos, limit) {
  let left = parseAddExpr(tokens, pos, limit);
  for (;;) {
    const a = tokens[left.pos];
    const b = tokens[left.pos + 1];
    if (left.pos + 1 >= limit || !a || a.t !== 'punct' || !b || b.t !== 'punct') return left;
    let op = null;
    if (a.v === '<' && b.v === '<') op = '<<';
    else if (a.v === '>' && b.v === '>') op = '>>';
    if (!op) return left;
    const right = parseAddExpr(tokens, left.pos + 2, limit);
    left = { node: { type: 'bin', op, left: left.node, right: right.node }, pos: right.pos };
  }
}

function parseAddExpr(tokens, pos, limit) {
  let left = parseMulExpr(tokens, pos, limit);
  for (;;) {
    const tok = tokens[left.pos];
    if (left.pos >= limit || !tok || tok.t !== 'punct' || (tok.v !== '+' && tok.v !== '-')) return left;
    const right = parseMulExpr(tokens, left.pos + 1, limit);
    left = { node: { type: 'bin', op: tok.v, left: left.node, right: right.node }, pos: right.pos };
  }
}

function parseMulExpr(tokens, pos, limit) {
  let left = parseUnaryExpr(tokens, pos, limit);
  for (;;) {
    const tok = tokens[left.pos];
    if (left.pos >= limit || !tok || tok.t !== 'punct' || !['*', '\\', '%'].includes(tok.v)) return left;
    const right = parseUnaryExpr(tokens, left.pos + 1, limit);
    left = { node: { type: 'bin', op: tok.v, left: left.node, right: right.node }, pos: right.pos };
  }
}

function parseUnaryExpr(tokens, pos, limit) {
  const tok = tokens[pos];
  if (pos < limit && tok && tok.t === 'punct' && (tok.v === '-' || tok.v === '~')) {
    const inner = parseUnaryExpr(tokens, pos + 1, limit);
    return { node: { type: 'neg', op: tok.v, operand: inner.node }, pos: inner.pos };
  }
  return parsePrimaryExpr(tokens, pos, limit);
}

// `of them` | `of ( $a, $b*, $* )` → { ids: null (them) | [{id, prefix}] , pos }
function parseStringSet(tokens, pos, limit) {
  if (isWord(tokens[pos], 'them')) return { set: null, pos: pos + 1 };
  if (!isPunct(tokens[pos], '(')) throw new ParseError('expected "them" or a string set after "of"');
  const set = [];
  let p = pos + 1;
  for (;;) {
    const tok = tokens[p];
    if (p >= limit || !tok) throw new ParseError('unterminated string set');
    if (tok.t === 'var') {
      if (isPunct(tokens[p + 1], '*')) {
        set.push({ id: tok.v, prefix: true });
        p += 2;
      } else {
        set.push({ id: tok.v, prefix: false });
        p += 1;
      }
    } else if (isPunct(tok, '$') && isPunct(tokens[p + 1], '*')) {
      set.push({ id: '', prefix: true });
      p += 2;
    } else {
      throw new ParseError(`unexpected ${describeToken(tok)} in string set`);
    }
    if (isPunct(tokens[p], ',')) {
      p += 1;
      continue;
    }
    if (isPunct(tokens[p], ')')) return { set, pos: p + 1 };
    throw new ParseError('expected "," or ")" in string set');
  }
}

function parseQuantifier(q, tokens, pos, limit) {
  // pos points at "of"
  const parsed = parseStringSet(tokens, pos + 1, limit);
  const next = tokens[parsed.pos];
  if (isWord(next, 'in') || isWord(next, 'at')) {
    throw new ParseError(`unsupported construct "of ... ${next.v}"`);
  }
  return { node: { type: 'quant', q, set: parsed.set, ids: null }, pos: parsed.pos };
}

function parsePrimaryExpr(tokens, pos, limit) {
  const tok = tokens[pos];
  if (pos >= limit || !tok) throw new ParseError('condition ended unexpectedly');

  // Parentheses (boolean or numeric)
  if (isPunct(tok, '(')) {
    const inner = parseOrExpr(tokens, pos + 1, limit);
    if (!isPunct(tokens[inner.pos], ')')) throw new ParseError('expected ")" in condition');
    return { node: inner.node, pos: inner.pos + 1 };
  }

  // $a / $a at <expr>
  if (tok.t === 'var') {
    const next = tokens[pos + 1];
    if (isWord(next, 'of')) throw new ParseError(`unsupported construct "$${tok.v} of ..."`);
    if (isWord(next, 'in')) throw new ParseError(`unsupported construct "$${tok.v} in ..."`);
    if (isWord(next, 'at')) {
      const off = parseAddExpr(tokens, pos + 2, limit);
      return { node: { type: 'at', id: tok.v, offset: off.node }, pos: off.pos };
    }
    return { node: { type: 'string', id: tok.v }, pos: pos + 1 };
  }

  // #a (match count, numeric)
  if (tok.t === 'count') {
    if (isWord(tokens[pos + 1], 'in')) throw new ParseError(`unsupported construct "#${tok.v} in ..."`);
    return { node: { type: 'count', id: tok.v }, pos: pos + 1 };
  }

  if (tok.t === 'num') {
    if (isWord(tokens[pos + 1], 'of')) {
      return parseQuantifier({ type: 'num', value: tok.v }, tokens, pos + 1, limit);
    }
    return { node: { type: 'num', value: tok.v }, pos: pos + 1 };
  }

  if (tok.t === 'word') {
    if ((tok.v === 'any' || tok.v === 'all' || tok.v === 'none') && isWord(tokens[pos + 1], 'of')) {
      return parseQuantifier(tok.v, tokens, pos + 1, limit);
    }
    if (tok.v === 'true' || tok.v === 'false') {
      return { node: { type: 'const', value: tok.v === 'true' }, pos: pos + 1 };
    }
    if (tok.v === 'filesize') return { node: { type: 'filesize' }, pos: pos + 1 };
    const fn = INT_FUNCS.get(tok.v);
    if (fn && isPunct(tokens[pos + 1], '(')) {
      const arg = parseBitExpr(tokens, pos + 2, limit);
      if (!isPunct(tokens[arg.pos], ')')) throw new ParseError(`expected ")" after ${tok.v}(...)`);
      return { node: { type: 'int', fn, offset: arg.node }, pos: arg.pos + 1 };
    }
    throw new ParseError(`unsupported condition atom "${tok.v}"`);
  }

  throw new ParseError(`unexpected ${describeToken(tok)} in condition`);
}

/* ------------------------------------------------------------------ *
 * Rule assembly
 * ------------------------------------------------------------------ */

function skipParenArgs(tokens, pos, to) {
  if (!isPunct(tokens[pos], '(')) return pos;
  let depth = 0;
  while (pos < to) {
    if (isPunct(tokens[pos], '(')) depth += 1;
    else if (isPunct(tokens[pos], ')')) {
      depth -= 1;
      if (depth === 0) return pos + 1;
    }
    pos += 1;
  }
  return pos;
}

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

    // Modifiers: nocase, ascii, wide and fullword are honoured on text strings.
    // xor/base64/base64wide/private are tolerated and ignored (the plain form
    // is still searched: fewer detections, never false ones).
    while (pos < to) {
      const mod = tokens[pos];
      if (mod.t !== 'word' || SECTION_WORDS.has(mod.v)) break;
      const name = mod.v.toLowerCase();
      pos += 1;
      if (pattern.kind === 'text' && ['nocase', 'ascii', 'wide', 'fullword'].includes(name)) {
        pattern[name] = true;
        continue;
      }
      if (name === 'xor' || name === 'base64' || name === 'base64wide') pos = skipParenArgs(tokens, pos, to);
      // any other (known or unknown) modifier: ignore
    }

    if (pattern.kind === 'text') finalizeTextPattern(pattern);
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

/** Validates string references and expands quantifier sets to concrete ids. */
function resolveCondition(rule) {
  const declared = rule.strings.map((s) => s.id);
  const declaredSet = new Set(declared);
  const walk = (n) => {
    if (!n || typeof n !== 'object') return;
    switch (n.type) {
      case 'string':
      case 'at':
      case 'count':
        if (!declaredSet.has(n.id)) throw new ParseError(`rule "${rule.name}": undeclared string $${n.id}`);
        if (n.offset) walk(n.offset);
        break;
      case 'quant': {
        if (n.set === null) {
          n.ids = declared.slice();
        } else {
          const ids = new Set();
          for (const item of n.set) {
            const matches = item.prefix ? declared.filter((d) => d.startsWith(item.id)) : [item.id];
            if (matches.length === 0 || (!item.prefix && !declaredSet.has(item.id))) {
              throw new ParseError(`rule "${rule.name}": undeclared string $${item.id}${item.prefix ? '*' : ''}`);
            }
            matches.forEach((m) => ids.add(m));
          }
          n.ids = Array.from(ids);
        }
        if (typeof n.q === 'object') walk(n.q);
        break;
      }
      default:
        for (const k of ['left', 'right', 'operand', 'offset']) if (n[k]) walk(n[k]);
    }
  };
  walk(rule.condition);
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
  resolveCondition(rule);
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
 * Matching (lazy: a string is only searched when the condition needs it,
 * so cheap checks like `uint16(0) == 0x5A4D` short-circuit whole rules)
 * ------------------------------------------------------------------ */

function isWordByte(b) {
  return (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
}

function fullwordOk(hay, idx, len, step) {
  const before = idx - step;
  const after = idx + len;
  if (before >= 0 && isWordByte(hay[before])) return false;
  if (after < hay.length && isWordByte(hay[after])) return false;
  return true;
}

function countText(ctx, pattern, limit) {
  let total = 0;
  for (const v of pattern.variants) {
    const hay = pattern.nocase ? ctx.lower() : ctx.buffer;
    const needle = pattern.nocase ? v.lowerBytes : v.bytes;
    if (needle.length > hay.length) continue;
    let start = 0;
    while (total < limit) {
      const idx = hay.indexOf(needle, start);
      if (idx === -1) break;
      if (!pattern.fullword || fullwordOk(hay, idx, needle.length, v.step)) {
        total += 1;
        start = idx + needle.length; // non-overlapping occurrences
      } else {
        start = idx + 1;
      }
    }
    if (total >= limit) break;
  }
  return total;
}

function countHex(ctx, pattern, limit) {
  if (pattern.bytes) {
    const hay = ctx.buffer;
    const needle = pattern.bytes;
    if (needle.length > hay.length) return 0;
    let count = 0;
    let start = 0;
    while (count < limit) {
      const idx = hay.indexOf(needle, start);
      if (idx === -1) break;
      count += 1;
      start = idx + needle.length;
    }
    return count;
  }
  const str = ctx.latin1();
  const re = pattern.regex;
  re.lastIndex = 0;
  let count = 0;
  while (count < limit) {
    const m = re.exec(str);
    if (!m) break;
    count += 1;
    if (m[0].length === 0) re.lastIndex += 1;
  }
  re.lastIndex = 0;
  return count;
}

function matchAt(ctx, pattern, offset) {
  if (!Number.isInteger(offset) || offset < 0 || offset >= ctx.headLength) return false;
  const hay = ctx.buffer;
  if (pattern.kind === 'text') {
    const src = pattern.nocase ? ctx.lower() : hay;
    return pattern.variants.some((v) => {
      const needle = pattern.nocase ? v.lowerBytes : v.bytes;
      if (offset + needle.length > hay.length) return false;
      if (src.compare(needle, 0, needle.length, offset, offset + needle.length) !== 0) return false;
      return !pattern.fullword || fullwordOk(hay, offset, needle.length, v.step);
    });
  }
  if (pattern.bytes) {
    const n = pattern.bytes.length;
    return offset + n <= hay.length && hay.compare(pattern.bytes, 0, n, offset, offset + n) === 0;
  }
  const sticky = pattern.sticky || (pattern.sticky = new RegExp(pattern.regex.source, 'y'));
  sticky.lastIndex = offset;
  const ok = sticky.test(ctx.latin1());
  sticky.lastIndex = 0;
  return ok;
}

function makeMatchContext(buffer, opts) {
  const o = opts || {};
  let lower = null;
  let latin = null;
  return {
    buffer,
    filesize: Number.isFinite(o.filesize) ? o.filesize : buffer.length,
    // Bytes at offsets >= headLength are not at their real file offset
    // (big files are scanned as head + tail): offset-based checks stop there.
    headLength: Number.isFinite(o.headLength) ? Math.min(o.headLength, buffer.length) : buffer.length,
    lower: () => lower || (lower = asciiLower(buffer)),
    latin1: () => latin || (latin = buffer.toString('latin1')),
    counts: null
  };
}

function stringCount(ctx, rule, id, limit) {
  const cached = ctx.counts.get(id);
  if (cached && (cached.exact || cached.n >= limit)) return cached.n;
  const pattern = rule.byId.get(id);
  const n = pattern.kind === 'text' ? countText(ctx, pattern, limit) : countHex(ctx, pattern, limit);
  ctx.counts.set(id, { n, exact: n < limit });
  return n;
}

function readInt(ctx, fn, offset) {
  if (!Number.isInteger(offset) || offset < 0 || offset + fn.size > ctx.headLength) return undefined;
  const b = ctx.buffer;
  switch (fn.size) {
    case 1:
      return fn.signed ? b.readInt8(offset) : b.readUInt8(offset);
    case 2:
      if (fn.signed) return fn.be ? b.readInt16BE(offset) : b.readInt16LE(offset);
      return fn.be ? b.readUInt16BE(offset) : b.readUInt16LE(offset);
    default:
      if (fn.signed) return fn.be ? b.readInt32BE(offset) : b.readInt32LE(offset);
      return fn.be ? b.readUInt32BE(offset) : b.readUInt32LE(offset);
  }
}

function truthy(v) {
  return v === true || (typeof v === 'number' && v !== 0);
}

function evalBin(op, a, b) {
  if (typeof a !== 'number' || typeof b !== 'number') return undefined;
  switch (op) {
    case '+':
      return a + b;
    case '-':
      return a - b;
    case '*':
      return a * b;
    case '\\':
      return b === 0 ? undefined : Math.trunc(a / b);
    case '%':
      return b === 0 ? undefined : a % b;
    default: {
      // Bitwise on 64-bit integers (JS bit ops are 32-bit signed)
      if (!Number.isInteger(a) || !Number.isInteger(b)) return undefined;
      const x = BigInt(a);
      const y = BigInt(b);
      let r;
      if (op === '&') r = x & y;
      else if (op === '|') r = x | y;
      else if (op === '^') r = x ^ y;
      else if (op === '<<') r = b >= 64 ? 0n : BigInt.asIntN(64, x << y);
      else if (op === '>>') r = b >= 64 ? 0n : x >> y;
      else return undefined;
      return Number(r);
    }
  }
}

function evaluateNode(node, ctx, rule) {
  switch (node.type) {
    case 'const':
      return node.value;
    case 'num':
      return node.value;
    case 'filesize':
      return ctx.filesize;
    case 'string':
      return stringCount(ctx, rule, node.id, 1) > 0;
    case 'count':
      return stringCount(ctx, rule, node.id, Infinity);
    case 'at': {
      const off = evaluateNode(node.offset, ctx, rule);
      return typeof off === 'number' && matchAt(ctx, rule.byId.get(node.id), off);
    }
    case 'int':
      return readInt(ctx, node.fn, evaluateNode(node.offset, ctx, rule));
    case 'neg': {
      const v = evaluateNode(node.operand, ctx, rule);
      if (typeof v !== 'number') return undefined;
      return node.op === '-' ? -v : Number(~BigInt(v));
    }
    case 'bin':
      return evalBin(node.op, evaluateNode(node.left, ctx, rule), evaluateNode(node.right, ctx, rule));
    case 'cmp': {
      const a = evaluateNode(node.left, ctx, rule);
      const b = evaluateNode(node.right, ctx, rule);
      if (a === undefined || b === undefined) return false;
      const x = typeof a === 'boolean' ? Number(a) : a;
      const y = typeof b === 'boolean' ? Number(b) : b;
      switch (node.op) {
        case '==':
          return x === y;
        case '!=':
          return x !== y;
        case '<':
          return x < y;
        case '<=':
          return x <= y;
        case '>':
          return x > y;
        default:
          return x >= y;
      }
    }
    case 'not': {
      const v = evaluateNode(node.operand, ctx, rule);
      return v === undefined ? false : !truthy(v);
    }
    case 'and':
      return truthy(evaluateNode(node.left, ctx, rule)) && truthy(evaluateNode(node.right, ctx, rule));
    case 'or':
      return truthy(evaluateNode(node.left, ctx, rule)) || truthy(evaluateNode(node.right, ctx, rule));
    case 'quant': {
      const ids = node.ids || [];
      if (ids.length === 0) return false; // no strings -> never match
      let need;
      if (node.q === 'any') need = 1;
      else if (node.q === 'all') need = ids.length;
      else if (node.q === 'none') need = 0;
      else {
        const v = evaluateNode(node.q, ctx, rule);
        if (typeof v !== 'number') return false;
        need = v;
      }
      if (node.q === 'none') return ids.every((id) => stringCount(ctx, rule, id, 1) === 0);
      if (need <= 0) return true;
      let hits = 0;
      for (let i = 0; i < ids.length; i += 1) {
        if (stringCount(ctx, rule, ids[i], 1) > 0) hits += 1;
        if (hits >= need) return true;
        if (hits + (ids.length - i - 1) < need) return false;
      }
      return false;
    }
    default:
      return undefined;
  }
}

function ruleMatches(rule, ctx) {
  if (!rule.byId) rule.byId = new Map(rule.strings.map((s) => [s.id, s]));
  ctx.counts = new Map(); // per-rule string counts (ids are rule-local)
  return truthy(evaluateNode(rule.condition, ctx, rule));
}

/**
 * @param {Buffer} buffer scan window
 * @param {Array} rules
 * @param {{filesize?:number, headLength?:number}} [opts] real file size and
 *   how many leading bytes sit at their real file offset
 */
function matchRules(buffer, rules, opts) {
  if (!Array.isArray(rules) || rules.length === 0 || buffer.length === 0) return null;
  const ctx = makeMatchContext(buffer, opts);
  for (const rule of rules) {
    if (!rule || !Array.isArray(rule.strings) || !rule.condition) continue;
    try {
      if (ruleMatches(rule, ctx)) return { name: rule.name, kind: 'yara' };
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

function windowInfo(size) {
  return { filesize: size, headLength: size <= STRING_SCAN_LIMIT ? size : STRING_SCAN_LIMIT };
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
      // Yayınlanan DB, YARA kurallarını da imzalı db.json içinde taşır
      if (typeof json.yara === 'string' && json.yara) {
        const embedded = parseYara(json.yara);
        result.rules.push(...embedded);
        for (const skipped of embedded.skipped || []) {
          result.skipped.push({ file: DB_FILE, rule: skipped.rule, error: skipped.error });
        }
      }
    }
  } catch (err) {
    if (err && err.code !== 'ENOENT') {
      result.skipped.push({ file: DB_FILE, error: String(err.message || err) });
    }
  }

  try {
    const text = fs.readFileSync(rulesPath, 'utf8');
    const rules = parseYara(text);
    result.rules = rules.concat(result.rules); // yerel kurallar önce
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
    return matchRules(readScanWindow(filePath, stat.size), db.rules, windowInfo(stat.size));
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
    return matchRules(readScanWindow(filePath, stat.size), db.rules, windowInfo(stat.size));
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
