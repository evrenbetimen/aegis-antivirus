// YARA alt kümesi derleyicisi: belirteçleyici + özyinelemeli iniş ayrıştırıcı.
// src/signatures.js içindeki parseYara() ile aynı kabul/ret kurallarını izler.

#include <cmath>
#include <cstdlib>
#include <set>
#include <stdexcept>
#include <unordered_set>

#include "yara.h"

namespace aegis {
namespace yara {
namespace {

/* ------------------------------------------------------------------ *
 * UTF-8 yardımcıları
 * ------------------------------------------------------------------ */

// WHATWG UTF-8 çözücüsü: geçersiz dizinin en uzun geçerli öneki tek bir
// U+FFFD olur (Node'un Buffer → string dönüşümüyle aynı).
uint32_t DecodeOne(const std::string& s, size_t* pos) {
  size_t i = *pos;
  uint8_t b = static_cast<uint8_t>(s[i]);
  if (b < 0x80) {
    *pos = i + 1;
    return b;
  }
  int need;
  uint32_t cp;
  uint8_t lo = 0x80, hi = 0xbf;
  if (b >= 0xc2 && b <= 0xdf) {
    need = 1;
    cp = b & 0x1f;
  } else if (b >= 0xe0 && b <= 0xef) {
    need = 2;
    cp = b & 0x0f;
    if (b == 0xe0) lo = 0xa0;
    if (b == 0xed) hi = 0x9f;
  } else if (b >= 0xf0 && b <= 0xf4) {
    need = 3;
    cp = b & 0x07;
    if (b == 0xf0) lo = 0x90;
    if (b == 0xf4) hi = 0x8f;
  } else {
    *pos = i + 1;
    return 0xfffd;
  }
  size_t j = i + 1;
  for (int k = 0; k < need; ++k) {
    if (j >= s.size()) {
      *pos = j;
      return 0xfffd;
    }
    uint8_t c = static_cast<uint8_t>(s[j]);
    if (c < lo || c > hi) {
      *pos = j;
      return 0xfffd;
    }
    lo = 0x80;
    hi = 0xbf;
    cp = (cp << 6) | (c & 0x3f);
    ++j;
  }
  *pos = j;
  return cp;
}

void AppendUtf8(std::string* out, uint32_t cp) {
  if (cp < 0x80) {
    out->push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out->push_back(static_cast<char>(0xc0 | (cp >> 6)));
    out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else if (cp < 0x10000) {
    out->push_back(static_cast<char>(0xe0 | (cp >> 12)));
    out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else {
    out->push_back(static_cast<char>(0xf0 | (cp >> 18)));
    out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
    out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  }
}

std::string Utf8ToUtf16Le(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 2);
  size_t i = 0;
  auto unit = [&out](uint32_t u) {
    out.push_back(static_cast<char>(u & 0xff));
    out.push_back(static_cast<char>((u >> 8) & 0xff));
  };
  while (i < s.size()) {
    uint32_t cp = DecodeOne(s, &i);
    if (cp >= 0x10000) {
      cp -= 0x10000;
      unit(0xd800 | (cp >> 10));
      unit(0xdc00 | (cp & 0x3ff));
    } else {
      unit(cp);
    }
  }
  return out;
}

std::string AsciiLower(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 0x20);
  }
  return out;
}

// JavaScript'in \s sınıfı (ECMAScript WhiteSpace + LineTerminator).
bool IsJsSpace(uint32_t cp) {
  switch (cp) {
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x20:
    case 0xa0:
    case 0x1680:
    case 0x2028:
    case 0x2029:
    case 0x202f:
    case 0x205f:
    case 0x3000:
    case 0xfeff:
      return true;
    default:
      return cp >= 0x2000 && cp <= 0x200a;
  }
}

bool IsIdentChar(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}
bool IsIdentStart(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'; }
bool IsDigit(char c) { return c >= '0' && c <= '9'; }
bool IsHexChar(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c - 'A' + 10;
}

std::string NumToString(double v) {
  if (std::isnan(v)) return "NaN";
  if (std::isinf(v)) return v > 0 ? "Infinity" : "-Infinity";
  if (v == std::floor(v) && std::fabs(v) < 1e21) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.0f", v);
    return buf;
  }
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%.17g", v);
  return buf;
}

/* ------------------------------------------------------------------ *
 * Belirteçleyici
 * ------------------------------------------------------------------ */

struct Token {
  enum Type { kWord, kStr, kHex, kVar, kCount, kNum, kPunct };
  Type t;
  std::string v;  // kNum dışında değer
  double num = 0;
};

class ParseError : public std::runtime_error {
 public:
  explicit ParseError(const std::string& m) : std::runtime_error(m) {}
};

std::vector<Token> Tokenize(const std::string& text) {
  std::vector<Token> tokens;
  const size_t n = text.size();
  size_t i = 0;
  while (i < n) {
    const char c = text[i];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      ++i;
      continue;
    }
    if (c == '/' && i + 1 < n && text[i + 1] == '/') {
      while (i < n && text[i] != '\n') ++i;
      continue;
    }
    if (c == '/' && i + 1 < n && text[i + 1] == '*') {
      size_t end = text.find("*/", i + 2);
      i = end == std::string::npos ? n : end + 2;
      continue;
    }
    if (c == '"') {
      size_t j = i + 1;
      std::string value;
      while (j < n) {
        const char ch = text[j];
        if (ch == '\\' && j + 1 < n) {
          value.push_back(text[j + 1]);
          j += 2;
          continue;
        }
        if (ch == '"' || ch == '\n') break;
        value.push_back(ch);
        ++j;
      }
      tokens.push_back({Token::kStr, value});
      i = (j < n && text[j] == '"') ? j + 1 : j;
      continue;
    }
    if (c == '{') {
      const bool is_value =
          !tokens.empty() && tokens.back().t == Token::kPunct && tokens.back().v == "=";
      if (!is_value) {
        tokens.push_back({Token::kPunct, "{"});
        ++i;
        continue;
      }
      int depth = 1;
      size_t j = i + 1;
      while (j < n && depth > 0) {
        if (text[j] == '{') {
          ++depth;
        } else if (text[j] == '}') {
          --depth;
        }
        if (depth == 0) break;
        ++j;
      }
      tokens.push_back({Token::kHex, text.substr(i + 1, j - (i + 1))});
      i = j < n ? j + 1 : n;
      continue;
    }
    if (c == '$' || c == '#') {
      size_t j = i + 1;
      while (j < n && IsIdentChar(text[j])) ++j;
      if (j == i + 1) {
        tokens.push_back({Token::kPunct, std::string(1, c)});
        ++i;
        continue;
      }
      tokens.push_back({c == '$' ? Token::kVar : Token::kCount, text.substr(i + 1, j - i - 1)});
      i = j;
      continue;
    }
    if (IsIdentStart(c)) {
      size_t j = i;
      while (j < n && IsIdentChar(text[j])) ++j;
      tokens.push_back({Token::kWord, text.substr(i, j - i)});
      i = j;
      continue;
    }
    if (IsDigit(c)) {
      size_t j = i;
      Token tok{Token::kNum, ""};
      if (c == '0' && i + 1 < n && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
        j = i + 2;
        while (j < n && IsHexChar(text[j])) ++j;
        if (j == i + 2) {
          tok.num = std::nan("");
        } else {
          std::string lit = "0x" + text.substr(i + 2, j - i - 2);
          tok.num = std::strtod(lit.c_str(), nullptr);
        }
      } else {
        while (j < n && IsDigit(text[j])) ++j;
        double value = std::strtod(text.substr(i, j - i).c_str(), nullptr);
        if (j + 1 < n && (text[j] == 'K' || text[j] == 'M') && text[j + 1] == 'B' &&
            !(j + 2 < n && IsIdentChar(text[j + 2]))) {
          value *= text[j] == 'K' ? 1024.0 : 1024.0 * 1024.0;
          j += 2;
        }
        tok.num = value;
      }
      tokens.push_back(tok);
      i = j;
      continue;
    }
    tokens.push_back({Token::kPunct, std::string(1, c)});
    ++i;
  }
  return tokens;
}

std::string Describe(const Token* tok) {
  if (!tok) return "end of input";
  switch (tok->t) {
    case Token::kWord:
      return "word \"" + tok->v + "\"";
    case Token::kStr:
      return "string \"" + tok->v + "\"";
    case Token::kHex:
      return "hex block";
    case Token::kVar:
      return "string identifier \"$" + tok->v + "\"";
    case Token::kCount:
      return "count identifier \"#" + tok->v + "\"";
    case Token::kNum:
      return "number " + NumToString(tok->num);
    default:
      return "symbol \"" + tok->v + "\"";
  }
}

/* ------------------------------------------------------------------ *
 * Desen derleme
 * ------------------------------------------------------------------ */

void FinalizeText(Pattern* p) {
  p->variants.clear();
  if (!p->wide || p->ascii) p->variants.push_back({p->text, AsciiLower(p->text), 1});
  if (p->wide) {
    std::string w = Utf8ToUtf16Le(p->text);
    p->variants.push_back({w, AsciiLower(w), 2});
  }
}

// Yorumları ve JS \s boşluklarını atar (signatures.js makeHexPattern ile aynı).
std::string CleanHexSource(const std::string& raw) {
  std::string no_comments;
  size_t i = 0;
  while (i < raw.size()) {
    if (raw[i] == '/' && i + 1 < raw.size() && raw[i + 1] == '/') {
      while (i < raw.size() && raw[i] != '\n') ++i;
      no_comments.push_back(' ');
      continue;
    }
    if (raw[i] == '/' && i + 1 < raw.size() && raw[i + 1] == '*') {
      size_t end = raw.find("*/", i + 2);
      if (end != std::string::npos) {
        i = end + 2;
        no_comments.push_back(' ');
        continue;
      }
    }
    no_comments.push_back(raw[i]);
    ++i;
  }
  std::string out;
  size_t p = 0;
  while (p < no_comments.size()) {
    size_t start = p;
    uint32_t cp = DecodeOne(no_comments, &p);
    if (IsJsSpace(cp)) continue;
    out.append(no_comments, start, p - start);
  }
  return out;
}

bool HexOk(char c) { return c == '?' || IsHexChar(c); }

// Tek bayt belirteci ("AA", "A?", "?A", "??").
HexNode HexAtom(const std::string& id, char hi, char lo, bool* exact) {
  const bool ok_hi = HexOk(hi);
  const bool ok_lo = HexOk(lo);
  if (!ok_hi || !ok_lo) {
    throw ParseError("string $" + id + ": invalid hex character \"" + std::string(1, ok_hi ? lo : hi) +
                     "\"");
  }
  HexNode node;
  node.kind = HexNode::kByte;
  *exact = false;
  if (hi == '?' && lo == '?') {
    node.mask = 0;
    node.value = 0;
  } else if (hi != '?' && lo != '?') {
    node.mask = 0xff;
    node.value = static_cast<uint8_t>((HexValue(hi) << 4) | HexValue(lo));
    *exact = true;
  } else if (lo == '?') {
    node.mask = 0xf0;
    node.value = static_cast<uint8_t>(HexValue(hi) << 4);
  } else {
    node.mask = 0x0f;
    node.value = static_cast<uint8_t>(HexValue(lo));
  }
  return node;
}

bool AllDigits(const std::string& s) {
  for (char c : s) {
    if (!IsDigit(c)) return false;
  }
  return true;
}

Pattern MakeHexPattern(const std::string& id, const std::string& raw) {
  const std::string src = CleanHexSource(raw);
  const std::string malformed = "string $" + id + ": malformed hex pattern";
  if (src.empty()) throw ParseError(malformed);

  // Her açık grup için: (o grubun alternatifleri, şu an doldurulan dizi)
  std::vector<HexNode> root;
  struct Frame {
    std::vector<std::vector<HexNode>> alts;
  };
  std::vector<Frame> stack;
  auto current = [&]() -> std::vector<HexNode>& {
    return stack.empty() ? root : stack.back().alts.back();
  };

  std::string exact_bytes;
  bool all_exact = true;
  int atoms = 0;
  size_t i = 0;
  while (i < src.size()) {
    const char c = src[i];
    if (c == '[') {
      size_t close = src.find(']', i);
      if (close == std::string::npos) throw ParseError(malformed);
      const std::string body = src.substr(i + 1, close - i - 1);
      size_t dash = body.find('-');
      std::string a = dash == std::string::npos ? body : body.substr(0, dash);
      std::string b = dash == std::string::npos ? "" : body.substr(dash + 1);
      const bool has_dash = dash != std::string::npos;
      if (!AllDigits(a) || !AllDigits(b) || (!has_dash && a.empty())) {
        throw ParseError("string $" + id + ": invalid jump");
      }
      HexNode node;
      node.kind = HexNode::kJump;
      node.lo = a.empty() ? 0 : std::strtod(a.c_str(), nullptr);
      if (!has_dash) {
        node.hi = node.lo;
      } else if (!b.empty()) {
        node.hi = std::strtod(b.c_str(), nullptr);
        if (node.hi < node.lo) throw ParseError("string $" + id + ": invalid jump");
      } else {
        node.unbounded = true;
      }
      current().push_back(std::move(node));
      all_exact = false;
      i = close + 1;
      continue;
    }
    if (c == '(') {
      stack.push_back(Frame());
      stack.back().alts.emplace_back();
      all_exact = false;
      ++i;
      continue;
    }
    if (c == '|') {
      if (stack.empty()) throw ParseError("string $" + id + ": \"|\" outside of an alternative");
      stack.back().alts.emplace_back();
      ++i;
      continue;
    }
    if (c == ')') {
      if (stack.empty()) throw ParseError(malformed);
      HexNode node;
      node.kind = HexNode::kAlt;
      node.alts = std::move(stack.back().alts);
      stack.pop_back();
      current().push_back(std::move(node));
      ++i;
      continue;
    }
    if (c == '~') {
      if (i + 2 >= src.size()) throw ParseError(malformed);
      bool exact = false;
      HexNode a = HexAtom(id, src[i + 1], src[i + 2], &exact);
      if (!exact) throw ParseError("string $" + id + ": unsupported \"~\" with wildcard");
      a.kind = HexNode::kNotByte;
      current().push_back(a);
      all_exact = false;
      ++atoms;
      i += 3;
      continue;
    }
    if (i + 1 >= src.size()) throw ParseError(malformed);
    bool exact = false;
    HexNode a = HexAtom(id, c, src[i + 1], &exact);
    if (!exact) {
      all_exact = false;
    } else {
      exact_bytes.push_back(static_cast<char>(a.value));
    }
    current().push_back(a);
    ++atoms;
    i += 2;
  }
  if (!stack.empty() || atoms == 0) throw ParseError(malformed);

  Pattern p;
  p.id = id;
  p.is_text = false;
  if (all_exact) {
    p.exact = true;
    p.exact_bytes = exact_bytes;
  } else {
    p.seq = std::move(root);
  }
  return p;
}

/* ------------------------------------------------------------------ *
 * Koşul ayrıştırıcı
 * ------------------------------------------------------------------ */

struct IntFnEntry {
  const char* name;
  IntFn fn;
};
const IntFnEntry kIntFuncs[] = {
    {"uint8", {1, false, false}},   {"uint16", {2, false, false}},  {"uint32", {4, false, false}},
    {"uint8be", {1, false, true}},  {"uint16be", {2, false, true}}, {"uint32be", {4, false, true}},
    {"int8", {1, true, false}},     {"int16", {2, true, false}},    {"int32", {4, true, false}},
    {"int8be", {1, true, true}},    {"int16be", {2, true, true}},   {"int32be", {4, true, true}},
};

const IntFn* FindIntFn(const std::string& name) {
  for (const auto& e : kIntFuncs) {
    if (name == e.name) return &e.fn;
  }
  return nullptr;
}

bool IsSectionWord(const Token& t) {
  return t.t == Token::kWord && (t.v == "strings" || t.v == "condition" || t.v == "meta");
}

using NodePtr = std::unique_ptr<Node>;

struct Parsed {
  NodePtr node;
  size_t pos;
};

class Parser {
 public:
  explicit Parser(const std::vector<Token>& tokens) : toks_(tokens) {}

  const Token* At(size_t pos) const { return pos < toks_.size() ? &toks_[pos] : nullptr; }
  bool IsPunct(size_t pos, const char* v) const {
    const Token* t = At(pos);
    return t && t->t == Token::kPunct && t->v == v;
  }
  bool IsWord(size_t pos, const char* v) const {
    const Token* t = At(pos);
    return t && t->t == Token::kWord && t->v == v;
  }

  static NodePtr MakeNode(Node::Type type) {
    NodePtr n(new Node());
    n->type = type;
    return n;
  }
  static NodePtr Binary(Node::Type type, const std::string& op, NodePtr a, NodePtr b) {
    NodePtr n = MakeNode(type);
    n->op = op;
    n->a = std::move(a);
    n->b = std::move(b);
    return n;
  }

  Parsed ParseOr(size_t pos, size_t limit) {
    Parsed left = ParseAnd(pos, limit);
    while (left.pos < limit && IsWord(left.pos, "or")) {
      Parsed right = ParseAnd(left.pos + 1, limit);
      left = {Binary(Node::kOr, "", std::move(left.node), std::move(right.node)), right.pos};
    }
    return left;
  }

  Parsed ParseAnd(size_t pos, size_t limit) {
    Parsed left = ParseNot(pos, limit);
    while (left.pos < limit && IsWord(left.pos, "and")) {
      Parsed right = ParseNot(left.pos + 1, limit);
      left = {Binary(Node::kAnd, "", std::move(left.node), std::move(right.node)), right.pos};
    }
    return left;
  }

  Parsed ParseNot(size_t pos, size_t limit) {
    if (pos < limit && IsWord(pos, "not")) {
      Parsed inner = ParseNot(pos + 1, limit);
      NodePtr n = MakeNode(Node::kNot);
      n->a = std::move(inner.node);
      return {std::move(n), inner.pos};
    }
    return ParseCompare(pos, limit);
  }

  bool ReadCompareOp(size_t pos, size_t limit, std::string* op, size_t* next) const {
    if (pos >= limit) return false;
    const Token* a = At(pos);
    if (!a || a->t != Token::kPunct) return false;
    if (a->v == "=") {
      *op = "==";
      *next = IsPunct(pos + 1, "=") ? pos + 2 : pos + 1;
      return true;
    }
    if (a->v == "!" && IsPunct(pos + 1, "=")) {
      *op = "!=";
      *next = pos + 2;
      return true;
    }
    if (a->v == "<" && !IsPunct(pos + 1, "<")) {
      if (IsPunct(pos + 1, "=")) {
        *op = "<=";
        *next = pos + 2;
      } else {
        *op = "<";
        *next = pos + 1;
      }
      return true;
    }
    if (a->v == ">" && !IsPunct(pos + 1, ">")) {
      if (IsPunct(pos + 1, "=")) {
        *op = ">=";
        *next = pos + 2;
      } else {
        *op = ">";
        *next = pos + 1;
      }
      return true;
    }
    return false;
  }

  Parsed ParseCompare(size_t pos, size_t limit) {
    Parsed left = ParseBit(pos, limit);
    std::string op;
    size_t next = 0;
    if (!ReadCompareOp(left.pos, limit, &op, &next)) return left;
    Parsed right = ParseBit(next, limit);
    return {Binary(Node::kCmp, op, std::move(left.node), std::move(right.node)), right.pos};
  }

  Parsed ParseBit(size_t pos, size_t limit) {
    Parsed left = ParseShift(pos, limit);
    for (;;) {
      const Token* tok = At(left.pos);
      if (left.pos >= limit || !tok || tok->t != Token::kPunct ||
          (tok->v != "&" && tok->v != "|" && tok->v != "^")) {
        return left;
      }
      Parsed right = ParseShift(left.pos + 1, limit);
      left = {Binary(Node::kBin, tok->v, std::move(left.node), std::move(right.node)), right.pos};
    }
  }

  Parsed ParseShift(size_t pos, size_t limit) {
    Parsed left = ParseAdd(pos, limit);
    for (;;) {
      const Token* a = At(left.pos);
      const Token* b = At(left.pos + 1);
      if (left.pos + 1 >= limit || !a || a->t != Token::kPunct || !b || b->t != Token::kPunct) {
        return left;
      }
      std::string op;
      if (a->v == "<" && b->v == "<") {
        op = "<<";
      } else if (a->v == ">" && b->v == ">") {
        op = ">>";
      } else {
        return left;
      }
      Parsed right = ParseAdd(left.pos + 2, limit);
      left = {Binary(Node::kBin, op, std::move(left.node), std::move(right.node)), right.pos};
    }
  }

  Parsed ParseAdd(size_t pos, size_t limit) {
    Parsed left = ParseMul(pos, limit);
    for (;;) {
      const Token* tok = At(left.pos);
      if (left.pos >= limit || !tok || tok->t != Token::kPunct || (tok->v != "+" && tok->v != "-")) {
        return left;
      }
      Parsed right = ParseMul(left.pos + 1, limit);
      left = {Binary(Node::kBin, tok->v, std::move(left.node), std::move(right.node)), right.pos};
    }
  }

  Parsed ParseMul(size_t pos, size_t limit) {
    Parsed left = ParseUnary(pos, limit);
    for (;;) {
      const Token* tok = At(left.pos);
      if (left.pos >= limit || !tok || tok->t != Token::kPunct ||
          (tok->v != "*" && tok->v != "\\" && tok->v != "%")) {
        return left;
      }
      Parsed right = ParseUnary(left.pos + 1, limit);
      left = {Binary(Node::kBin, tok->v, std::move(left.node), std::move(right.node)), right.pos};
    }
  }

  Parsed ParseUnary(size_t pos, size_t limit) {
    const Token* tok = At(pos);
    if (pos < limit && tok && tok->t == Token::kPunct && (tok->v == "-" || tok->v == "~")) {
      Parsed inner = ParseUnary(pos + 1, limit);
      NodePtr n = MakeNode(Node::kNeg);
      n->op = tok->v;
      n->a = std::move(inner.node);
      return {std::move(n), inner.pos};
    }
    return ParsePrimary(pos, limit);
  }

  size_t ParseStringSet(Node* quant, size_t pos, size_t limit) {
    if (IsWord(pos, "them")) {
      quant->set_them = true;
      return pos + 1;
    }
    if (!IsPunct(pos, "(")) throw ParseError("expected \"them\" or a string set after \"of\"");
    size_t p = pos + 1;
    for (;;) {
      const Token* tok = At(p);
      if (p >= limit || !tok) throw ParseError("unterminated string set");
      if (tok->t == Token::kVar) {
        if (IsPunct(p + 1, "*")) {
          quant->set.emplace_back(tok->v, true);
          p += 2;
        } else {
          quant->set.emplace_back(tok->v, false);
          p += 1;
        }
      } else if (tok->t == Token::kPunct && tok->v == "$" && IsPunct(p + 1, "*")) {
        quant->set.emplace_back("", true);
        p += 2;
      } else {
        throw ParseError("unexpected " + Describe(tok) + " in string set");
      }
      if (IsPunct(p, ",")) {
        ++p;
        continue;
      }
      if (IsPunct(p, ")")) return p + 1;
      throw ParseError("expected \",\" or \")\" in string set");
    }
  }

  Parsed ParseQuantifier(Node::QKind kind, NodePtr expr, size_t pos, size_t limit) {
    NodePtr n = MakeNode(Node::kQuant);
    n->q_kind = kind;
    n->q_expr = std::move(expr);
    size_t next = ParseStringSet(n.get(), pos + 1, limit);
    if (IsWord(next, "in") || IsWord(next, "at")) {
      throw ParseError("unsupported construct \"of ... " + At(next)->v + "\"");
    }
    return {std::move(n), next};
  }

  Parsed ParsePrimary(size_t pos, size_t limit) {
    const Token* tok = At(pos);
    if (pos >= limit || !tok) throw ParseError("condition ended unexpectedly");

    if (tok->t == Token::kPunct && tok->v == "(") {
      Parsed inner = ParseOr(pos + 1, limit);
      if (!IsPunct(inner.pos, ")")) throw ParseError("expected \")\" in condition");
      return {std::move(inner.node), inner.pos + 1};
    }

    if (tok->t == Token::kVar) {
      if (IsWord(pos + 1, "of")) throw ParseError("unsupported construct \"$" + tok->v + " of ...\"");
      if (IsWord(pos + 1, "in")) throw ParseError("unsupported construct \"$" + tok->v + " in ...\"");
      if (IsWord(pos + 1, "at")) {
        Parsed off = ParseAdd(pos + 2, limit);
        NodePtr n = MakeNode(Node::kAt);
        n->ref_id = tok->v;
        n->a = std::move(off.node);
        return {std::move(n), off.pos};
      }
      NodePtr n = MakeNode(Node::kString);
      n->ref_id = tok->v;
      return {std::move(n), pos + 1};
    }

    if (tok->t == Token::kCount) {
      if (IsWord(pos + 1, "in")) throw ParseError("unsupported construct \"#" + tok->v + " in ...\"");
      NodePtr n = MakeNode(Node::kCount);
      n->ref_id = tok->v;
      return {std::move(n), pos + 1};
    }

    if (tok->t == Token::kNum) {
      NodePtr n = MakeNode(Node::kNum);
      n->num = tok->num;
      if (IsWord(pos + 1, "of")) return ParseQuantifier(Node::kExpr, std::move(n), pos + 1, limit);
      return {std::move(n), pos + 1};
    }

    if (tok->t == Token::kWord) {
      const std::string& v = tok->v;
      if ((v == "any" || v == "all" || v == "none") && IsWord(pos + 1, "of")) {
        Node::QKind k = v == "any" ? Node::kAny : v == "all" ? Node::kAll : Node::kNone;
        return ParseQuantifier(k, nullptr, pos + 1, limit);
      }
      if (v == "true" || v == "false") {
        NodePtr n = MakeNode(Node::kConst);
        n->bval = v == "true";
        return {std::move(n), pos + 1};
      }
      if (v == "filesize") return {MakeNode(Node::kFilesize), pos + 1};
      const IntFn* fn = FindIntFn(v);
      if (fn && IsPunct(pos + 1, "(")) {
        Parsed arg = ParseBit(pos + 2, limit);
        if (!IsPunct(arg.pos, ")")) throw ParseError("expected \")\" after " + v + "(...)");
        NodePtr n = MakeNode(Node::kInt);
        n->fn = *fn;
        n->a = std::move(arg.node);
        return {std::move(n), arg.pos + 1};
      }
      throw ParseError("unsupported condition atom \"" + v + "\"");
    }

    throw ParseError("unexpected " + Describe(tok) + " in condition");
  }

  /* ---------------- kural derleme ---------------- */

  size_t SkipParenArgs(size_t pos, size_t to) const {
    if (!IsPunct(pos, "(")) return pos;
    int depth = 0;
    while (pos < to) {
      if (IsPunct(pos, "(")) {
        ++depth;
      } else if (IsPunct(pos, ")")) {
        --depth;
        if (depth == 0) return pos + 1;
      }
      ++pos;
    }
    return pos;
  }

  size_t ParseStringDecls(size_t pos, size_t to, Rule* rule) {
    std::unordered_set<std::string> seen;
    for (const auto& s : rule->strings) seen.insert(s.id);
    while (pos < to) {
      const Token& tok = toks_[pos];
      if (IsSectionWord(tok)) break;
      if (tok.t != Token::kVar) {
        throw ParseError("expected a $string declaration, found " + Describe(&tok));
      }
      const std::string id = tok.v;
      if (seen.count(id)) throw ParseError("duplicate string identifier $" + id);
      if (!IsPunct(pos + 1, "=")) throw ParseError("expected \"=\" after $" + id);
      const Token* value = At(pos + 2);
      if (!value || (value->t != Token::kStr && value->t != Token::kHex)) {
        throw ParseError("unsupported value for $" + id);
      }
      Pattern pattern;
      if (value->t == Token::kStr) {
        if (value->v.empty()) throw ParseError("string $" + id + ": empty text patterns are not supported");
        pattern.id = id;
        pattern.is_text = true;
        pattern.text = value->v;
      } else {
        pattern = MakeHexPattern(id, value->v);
      }
      pos += 3;

      while (pos < to) {
        const Token& mod = toks_[pos];
        if (mod.t != Token::kWord || IsSectionWord(mod)) break;
        const std::string name = AsciiLower(mod.v);
        ++pos;
        if (pattern.is_text) {
          if (name == "nocase") {
            pattern.nocase = true;
            continue;
          }
          if (name == "ascii") {
            pattern.ascii = true;
            continue;
          }
          if (name == "wide") {
            pattern.wide = true;
            continue;
          }
          if (name == "fullword") {
            pattern.fullword = true;
            continue;
          }
        }
        if (name == "xor" || name == "base64" || name == "base64wide") pos = SkipParenArgs(pos, to);
      }

      if (pattern.is_text) FinalizeText(&pattern);
      rule->strings.push_back(std::move(pattern));
      seen.insert(id);
    }
    return pos;
  }

  size_t SkipMeta(size_t pos, size_t to) const {
    while (pos < to) {
      if (IsSectionWord(toks_[pos])) break;
      ++pos;
    }
    return pos;
  }

  void ParseSections(size_t from, size_t to, Rule* rule) {
    size_t pos = from;
    NodePtr condition;
    while (pos < to) {
      const Token& tok = toks_[pos];
      if (IsSectionWord(tok)) {
        const std::string keyword = tok.v;
        if (!IsPunct(pos + 1, ":")) throw ParseError("expected \":\" after \"" + keyword + "\"");
        if (keyword == "strings") {
          pos = ParseStringDecls(pos + 2, to, rule);
        } else if (keyword == "condition") {
          Parsed parsed = ParseOr(pos + 2, to);
          condition = std::move(parsed.node);
          pos = parsed.pos;
        } else {
          pos = SkipMeta(pos + 2, to);
        }
        continue;
      }
      throw ParseError("unexpected " + Describe(&tok) + " in rule body");
    }
    if (!condition) throw ParseError("rule has no condition section");
    rule->condition = std::move(condition);
  }

  static int IndexOf(const Rule& rule, const std::string& id) {
    for (size_t i = 0; i < rule.strings.size(); ++i) {
      if (rule.strings[i].id == id) return static_cast<int>(i);
    }
    return -1;
  }

  static void Resolve(Rule* rule, Node* n) {
    if (!n) return;
    switch (n->type) {
      case Node::kString:
      case Node::kAt:
      case Node::kCount:
        n->str_index = IndexOf(*rule, n->ref_id);
        if (n->str_index < 0) {
          throw ParseError("rule \"" + rule->name + "\": undeclared string $" + n->ref_id);
        }
        Resolve(rule, n->a.get());
        break;
      case Node::kQuant: {
        n->ids.clear();
        if (n->set_them) {
          for (size_t i = 0; i < rule->strings.size(); ++i) n->ids.push_back(static_cast<int>(i));
        } else {
          std::set<int> added;
          for (const auto& item : n->set) {
            std::vector<int> matches;
            if (item.second) {
              for (size_t i = 0; i < rule->strings.size(); ++i) {
                if (rule->strings[i].id.compare(0, item.first.size(), item.first) == 0) {
                  matches.push_back(static_cast<int>(i));
                }
              }
            } else {
              int idx = IndexOf(*rule, item.first);
              if (idx >= 0) matches.push_back(idx);
            }
            if (matches.empty()) {
              throw ParseError("rule \"" + rule->name + "\": undeclared string $" + item.first +
                               (item.second ? "*" : ""));
            }
            for (int m : matches) {
              if (added.insert(m).second) n->ids.push_back(m);
            }
          }
        }
        Resolve(rule, n->q_expr.get());
        break;
      }
      default:
        Resolve(rule, n->a.get());
        Resolve(rule, n->b.get());
    }
  }

  long FindRuleEnd(size_t from) const {
    for (size_t i = from; i < toks_.size(); ++i) {
      if (IsPunct(i, "}")) return static_cast<long>(i);
      if (toks_[i].t == Token::kWord && toks_[i].v == "rule") return -1;
    }
    return -1;
  }

  size_t ParseRule(size_t start, Rule* rule) {
    size_t pos = start + 1;
    const Token* name = At(pos);
    if (!name || name->t != Token::kWord) throw ParseError("rule name is missing");
    rule->name = name->v;
    ++pos;
    if (IsPunct(pos, ":")) {
      ++pos;
      while (pos < toks_.size() && toks_[pos].t == Token::kWord) ++pos;
    }
    if (!IsPunct(pos, "{")) throw ParseError("rule \"" + rule->name + "\": expected \"{\" after rule header");
    long end = FindRuleEnd(pos + 1);
    if (end < 0) throw ParseError("rule \"" + rule->name + "\": missing closing \"}\"");
    ParseSections(pos + 1, static_cast<size_t>(end), rule);
    Resolve(rule, rule->condition.get());
    return static_cast<size_t>(end) + 1;
  }

  CompileResult Run() {
    CompileResult out;
    size_t i = 0;
    while (i < toks_.size()) {
      const Token& tok = toks_[i];
      if (tok.t == Token::kWord && tok.v == "rule") {
        Rule rule;
        try {
          size_t end = ParseRule(i, &rule);
          out.rules.push_back(std::move(rule));
          i = end;
        } catch (const std::exception& err) {
          Skipped s;
          const Token* name = At(i + 1);
          if (name && name->t == Token::kWord) {
            s.has_name = true;
            s.rule = name->v;
          }
          s.error = err.what();
          out.skipped.push_back(std::move(s));
          ++i;
        }
        continue;
      }
      ++i;
    }
    return out;
  }

 private:
  const std::vector<Token>& toks_;
};

}  // namespace

std::string SanitizeUtf8(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  size_t i = 0;
  while (i < in.size()) AppendUtf8(&out, DecodeOne(in, &i));
  return out;
}

CompileResult Compile(const std::string& text) {
  if (text.empty()) return CompileResult();
  std::vector<Token> tokens = Tokenize(text);
  Parser parser(tokens);
  return parser.Run();
}

}  // namespace yara
}  // namespace aegis
