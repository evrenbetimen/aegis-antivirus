// YARA alt kümesi eşleştiricisi. Tembel değerlendirme: bir dizgi yalnızca
// koşul ona ihtiyaç duyduğunda aranır (signatures.js ile aynı).

#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>

#include "yara.h"

namespace aegis {
namespace yara {
namespace {

constexpr double kInf = std::numeric_limits<double>::infinity();

// Değerlendirme sırasında JS motorunda istisnaya yol açan durum (ör. ~ ile
// tam sayı olmayan değer). Kural "eşleşmedi" sayılır, tarama sürer.
struct EvalError {};

struct Value {
  enum Kind { kUndef, kBool, kNum };
  Kind kind = kUndef;
  bool b = false;
  double n = 0;
  static Value Undef() { return Value(); }
  static Value Bool(bool v) {
    Value x;
    x.kind = kBool;
    x.b = v;
    return x;
  }
  static Value Num(double v) {
    Value x;
    x.kind = kNum;
    x.n = v;
    return x;
  }
};

bool Truthy(const Value& v) {
  return (v.kind == Value::kBool && v.b) || (v.kind == Value::kNum && v.n != 0);
}

bool IsInteger(double v) { return std::isfinite(v) && v == std::trunc(v); }

const uint8_t* Find(const uint8_t* hay, size_t hay_len, size_t start, const std::string& needle) {
  if (start > hay_len || needle.size() > hay_len - start) return nullptr;
  const size_t n = needle.size();
  const uint8_t first = static_cast<uint8_t>(needle[0]);
  const uint8_t* p = hay + start;
  const uint8_t* end = hay + hay_len - n + 1;
  while (p < end) {
    p = static_cast<const uint8_t*>(std::memchr(p, first, static_cast<size_t>(end - p)));
    if (!p) return nullptr;
    if (std::memcmp(p, needle.data(), n) == 0) return p;
    ++p;
  }
  return nullptr;
}

bool IsWordByte(uint8_t b) {
  return (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
}

class Context {
 public:
  explicit Context(const ScanWindow& w) : w_(w) {}

  const ScanWindow& window() const { return w_; }

  const uint8_t* Lower() {
    if (!lower_ready_) {
      lower_.assign(reinterpret_cast<const char*>(w_.data), w_.len);
      for (char& c : lower_) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 0x20);
      }
      lower_ready_ = true;
    }
    return reinterpret_cast<const uint8_t*>(lower_.data());
  }

  void ResetCounts(size_t n) {
    counts_.assign(n, Count());
  }

  double StringCount(const Rule& rule, int idx, double limit) {
    Count& c = counts_[static_cast<size_t>(idx)];
    if (c.set && (c.exact || c.n >= limit)) return c.n;
    const Pattern& p = rule.strings[static_cast<size_t>(idx)];
    double n = p.is_text ? CountText(p, limit) : CountHex(p, limit);
    c.set = true;
    c.n = n;
    c.exact = n < limit;
    return n;
  }

  bool MatchAt(const Pattern& p, double offset) {
    if (!IsInteger(offset) || offset < 0 || offset >= static_cast<double>(w_.head_length)) return false;
    const size_t off = static_cast<size_t>(offset);
    const uint8_t* hay = w_.data;
    if (p.is_text) {
      const uint8_t* src = p.nocase ? Lower() : hay;
      for (const Variant& v : p.variants) {
        const std::string& needle = p.nocase ? v.lower : v.bytes;
        if (off + needle.size() > w_.len) continue;
        if (std::memcmp(src + off, needle.data(), needle.size()) != 0) continue;
        if (!p.fullword || FullwordOk(hay, off, needle.size(), v.step)) return true;
      }
      return false;
    }
    if (p.exact) {
      const size_t n = p.exact_bytes.size();
      return off + n <= w_.len && std::memcmp(hay + off, p.exact_bytes.data(), n) == 0;
    }
    size_t end = 0;
    return MatchSeq(p.seq, 0, off, nullptr, &end);
  }

  Value ReadInt(const IntFn& fn, const Value& offset) const {
    if (offset.kind != Value::kNum || !IsInteger(offset.n) || offset.n < 0 ||
        offset.n + fn.size > static_cast<double>(w_.head_length)) {
      return Value::Undef();
    }
    const uint8_t* b = w_.data + static_cast<size_t>(offset.n);
    uint32_t raw = 0;
    for (int i = 0; i < fn.size; ++i) {
      const int shift = fn.big_endian ? 8 * (fn.size - 1 - i) : 8 * i;
      raw |= uint32_t(b[i]) << shift;
    }
    if (!fn.is_signed) return Value::Num(static_cast<double>(raw));
    switch (fn.size) {
      case 1:
        return Value::Num(static_cast<double>(static_cast<int8_t>(raw)));
      case 2:
        return Value::Num(static_cast<double>(static_cast<int16_t>(raw)));
      default:
        return Value::Num(static_cast<double>(static_cast<int32_t>(raw)));
    }
  }

 private:
  struct Count {
    bool set = false;
    bool exact = false;
    double n = 0;
  };

  bool FullwordOk(const uint8_t* hay, size_t idx, size_t len, int step) const {
    if (idx >= static_cast<size_t>(step) && IsWordByte(hay[idx - step])) return false;
    const size_t after = idx + len;
    if (after < w_.len && IsWordByte(hay[after])) return false;
    return true;
  }

  double CountText(const Pattern& p, double limit) {
    double total = 0;
    for (const Variant& v : p.variants) {
      const uint8_t* hay = p.nocase ? Lower() : w_.data;
      const std::string& needle = p.nocase ? v.lower : v.bytes;
      if (needle.size() > w_.len) continue;
      size_t start = 0;
      while (total < limit) {
        const uint8_t* hit = Find(hay, w_.len, start, needle);
        if (!hit) break;
        const size_t idx = static_cast<size_t>(hit - hay);
        if (!p.fullword || FullwordOk(hay, idx, needle.size(), v.step)) {
          total += 1;
          start = idx + needle.size();  // örtüşmeyen eşleşmeler
        } else {
          start = idx + 1;
        }
      }
      if (total >= limit) break;
    }
    return total;
  }

  double CountHex(const Pattern& p, double limit) {
    double count = 0;
    if (p.exact) {
      if (p.exact_bytes.size() > w_.len) return 0;
      size_t start = 0;
      while (count < limit) {
        const uint8_t* hit = Find(w_.data, w_.len, start, p.exact_bytes);
        if (!hit) break;
        count += 1;
        start = static_cast<size_t>(hit - w_.data) + p.exact_bytes.size();
      }
      return count;
    }
    // Düzenli ifade semantiği: en soldaki eşleşme, öncelik sırasıyla ilk yol
    // (alternatifler soldan sağa, aralıklı atlamalar tembel).
    size_t start = 0;
    const HexNode* first = p.seq.empty() ? nullptr : &p.seq[0];
    const bool first_exact = first && first->kind == HexNode::kByte && first->mask == 0xff;
    while (count < limit && start <= w_.len) {
      bool found = false;
      size_t s = start;
      while (s <= w_.len) {
        if (first_exact) {
          if (s >= w_.len) break;
          const void* hit = std::memchr(w_.data + s, first->value, w_.len - s);
          if (!hit) break;
          s = static_cast<size_t>(static_cast<const uint8_t*>(hit) - w_.data);
        }
        size_t end = 0;
        if (MatchSeq(p.seq, 0, s, nullptr, &end)) {
          count += 1;
          start = end == s ? s + 1 : end;
          found = true;
          break;
        }
        ++s;
      }
      if (!found) break;
    }
    return count;
  }

  struct Cont {
    const std::vector<HexNode>* seq;
    size_t i;
    const Cont* next;
  };

  bool MatchSeq(const std::vector<HexNode>& seq, size_t i, size_t pos, const Cont* k, size_t* end) const {
    for (;;) {
      if (i == seq.size()) {
        if (!k) {
          *end = pos;
          return true;
        }
        return MatchSeq(*k->seq, k->i, pos, k->next, end);
      }
      const HexNode& n = seq[i];
      switch (n.kind) {
        case HexNode::kByte:
          if (pos >= w_.len || (w_.data[pos] & n.mask) != n.value) return false;
          ++pos;
          ++i;
          continue;
        case HexNode::kNotByte:
          if (pos >= w_.len || w_.data[pos] == n.value) return false;
          ++pos;
          ++i;
          continue;
        case HexNode::kJump: {
          const double remaining = static_cast<double>(w_.len - pos);
          if (n.lo > remaining) return false;
          const double max = n.unbounded ? remaining : (n.hi < remaining ? n.hi : remaining);
          const size_t lo = static_cast<size_t>(n.lo);
          const size_t hi = static_cast<size_t>(max);
          if (lo == hi) {
            pos += lo;
            ++i;
            continue;
          }
          for (size_t step = lo; step <= hi; ++step) {
            if (MatchSeq(seq, i + 1, pos + step, k, end)) return true;
          }
          return false;
        }
        case HexNode::kAlt: {
          Cont c{&seq, i + 1, k};
          for (const auto& alt : n.alts) {
            if (MatchSeq(alt, 0, pos, &c, end)) return true;
          }
          return false;
        }
      }
      return false;
    }
  }

  const ScanWindow& w_;
  std::string lower_;
  bool lower_ready_ = false;
  std::vector<Count> counts_;
};

// İki tam sayı değeri 64 bit (sığmazsa 128 bit) üzerinde işler.
bool FitsInt64(double v) { return v >= -9223372036854775808.0 && v < 9223372036854775808.0; }
bool FitsInt128(double v) { return std::fabs(v) < 1.7014118346046923e38; }

__extension__ typedef __int128 Int128;

Int128 ToI128(double v) { return static_cast<Int128>(v); }

int64_t WrapInt64(double v) {
  // v mod 2^64 → iki tümleyenli 64 bit (BigInt.asIntN(64, ...))
  if (FitsInt64(v)) return static_cast<int64_t>(v);
  const double two64 = 18446744073709551616.0;
  double r = std::fmod(v, two64);
  if (r < 0) r += two64;
  if (r >= two64) r = 0;
  return static_cast<int64_t>(static_cast<uint64_t>(r));
}

Value EvalBin(const std::string& op, const Value& a, const Value& b) {
  if (a.kind != Value::kNum || b.kind != Value::kNum) return Value::Undef();
  const double x = a.n;
  const double y = b.n;
  if (op == "+") return Value::Num(x + y);
  if (op == "-") return Value::Num(x - y);
  if (op == "*") return Value::Num(x * y);
  if (op == "\\") return y == 0 ? Value::Undef() : Value::Num(std::trunc(x / y));
  if (op == "%") return y == 0 ? Value::Undef() : Value::Num(std::fmod(x, y));
  if (!IsInteger(x) || !IsInteger(y)) return Value::Undef();
  if (op == "&" || op == "|" || op == "^") {
    if (FitsInt64(x) && FitsInt64(y)) {
      const int64_t p = static_cast<int64_t>(x), q = static_cast<int64_t>(y);
      const int64_t r = op == "&" ? (p & q) : op == "|" ? (p | q) : (p ^ q);
      return Value::Num(static_cast<double>(r));
    }
    if (FitsInt128(x) && FitsInt128(y)) {
      const Int128 p = ToI128(x), q = ToI128(y);
      const Int128 r = op == "&" ? (p & q) : op == "|" ? (p | q) : (p ^ q);
      return Value::Num(static_cast<double>(r));
    }
    return Value::Undef();
  }
  if (op == "<<") {
    if (y >= 64) return Value::Num(0);
    if (y >= 0) {
      const uint64_t r = static_cast<uint64_t>(WrapInt64(x)) << static_cast<int>(y);
      return Value::Num(static_cast<double>(static_cast<int64_t>(r)));
    }
    // Negatif kaydırma = sağa kaydırma, sonra 64 bite sarma
    const double shift = -y;
    double shifted;
    if (shift > 1100) {
      shifted = x < 0 ? -1 : 0;  // tüm bitler kaydı: işaret kalır
    } else if (FitsInt64(x)) {
      shifted = shift >= 64 ? (x < 0 ? -1 : 0) : static_cast<double>(static_cast<int64_t>(x) >> static_cast<int>(shift));
    } else {
      shifted = std::floor(std::ldexp(x, -static_cast<int>(shift)));
    }
    return Value::Num(static_cast<double>(WrapInt64(shifted)));
  }
  if (op == ">>") {
    if (y >= 64) return Value::Num(0);
    if (y >= 0) return Value::Num(std::floor(std::ldexp(x, -static_cast<int>(y))));
    return Value::Num(std::ldexp(x, static_cast<int>(std::fmin(-y, 2000))));
  }
  return Value::Undef();
}

Value Evaluate(const Node* node, Context& ctx, const Rule& rule) {
  switch (node->type) {
    case Node::kConst:
      return Value::Bool(node->bval);
    case Node::kNum:
      return Value::Num(node->num);
    case Node::kFilesize:
      return Value::Num(ctx.window().filesize);
    case Node::kString:
      return Value::Bool(ctx.StringCount(rule, node->str_index, 1) > 0);
    case Node::kCount:
      return Value::Num(ctx.StringCount(rule, node->str_index, kInf));
    case Node::kAt: {
      Value off = Evaluate(node->a.get(), ctx, rule);
      return Value::Bool(off.kind == Value::kNum &&
                         ctx.MatchAt(rule.strings[static_cast<size_t>(node->str_index)], off.n));
    }
    case Node::kInt:
      return ctx.ReadInt(node->fn, Evaluate(node->a.get(), ctx, rule));
    case Node::kNeg: {
      Value v = Evaluate(node->a.get(), ctx, rule);
      if (v.kind != Value::kNum) return Value::Undef();
      if (node->op == "-") return Value::Num(-v.n);
      if (!IsInteger(v.n)) throw EvalError();  // BigInt(v) RangeError
      return Value::Num(-v.n - 1);
    }
    case Node::kBin:
      return EvalBin(node->op, Evaluate(node->a.get(), ctx, rule), Evaluate(node->b.get(), ctx, rule));
    case Node::kCmp: {
      Value a = Evaluate(node->a.get(), ctx, rule);
      Value b = Evaluate(node->b.get(), ctx, rule);
      if (a.kind == Value::kUndef || b.kind == Value::kUndef) return Value::Bool(false);
      const double x = a.kind == Value::kBool ? (a.b ? 1 : 0) : a.n;
      const double y = b.kind == Value::kBool ? (b.b ? 1 : 0) : b.n;
      const std::string& op = node->op;
      if (op == "==") return Value::Bool(x == y);
      if (op == "!=") return Value::Bool(x != y);
      if (op == "<") return Value::Bool(x < y);
      if (op == "<=") return Value::Bool(x <= y);
      if (op == ">") return Value::Bool(x > y);
      return Value::Bool(x >= y);
    }
    case Node::kNot: {
      Value v = Evaluate(node->a.get(), ctx, rule);
      return Value::Bool(v.kind == Value::kUndef ? false : !Truthy(v));
    }
    case Node::kAnd:
      return Value::Bool(Truthy(Evaluate(node->a.get(), ctx, rule)) && Truthy(Evaluate(node->b.get(), ctx, rule)));
    case Node::kOr:
      return Value::Bool(Truthy(Evaluate(node->a.get(), ctx, rule)) || Truthy(Evaluate(node->b.get(), ctx, rule)));
    case Node::kQuant: {
      const std::vector<int>& ids = node->ids;
      if (ids.empty()) return Value::Bool(false);
      double need;
      if (node->q_kind == Node::kAny) {
        need = 1;
      } else if (node->q_kind == Node::kAll) {
        need = static_cast<double>(ids.size());
      } else if (node->q_kind == Node::kNone) {
        need = 0;
      } else {
        Value v = Evaluate(node->q_expr.get(), ctx, rule);
        if (v.kind != Value::kNum) return Value::Bool(false);
        need = v.n;
      }
      if (node->q_kind == Node::kNone) {
        for (int id : ids) {
          if (ctx.StringCount(rule, id, 1) != 0) return Value::Bool(false);
        }
        return Value::Bool(true);
      }
      if (need <= 0) return Value::Bool(true);
      double hits = 0;
      for (size_t i = 0; i < ids.size(); ++i) {
        if (ctx.StringCount(rule, ids[i], 1) > 0) hits += 1;
        if (hits >= need) return Value::Bool(true);
        if (hits + static_cast<double>(ids.size() - i - 1) < need) return Value::Bool(false);
      }
      return Value::Bool(false);
    }
  }
  return Value::Undef();
}

}  // namespace

int MatchRules(const std::vector<Rule>& rules, const ScanWindow& window) {
  if (rules.empty() || window.len == 0) return -1;
  Context ctx(window);
  for (size_t i = 0; i < rules.size(); ++i) {
    const Rule& rule = rules[i];
    if (!rule.condition) continue;
    ctx.ResetCounts(rule.strings.size());
    try {
      if (Truthy(Evaluate(rule.condition.get(), ctx, rule))) return static_cast<int>(i);
    } catch (const EvalError&) {
      // Bozuk bir kural taramayı asla durdurmaz.
    }
  }
  return -1;
}

}  // namespace yara
}  // namespace aegis
