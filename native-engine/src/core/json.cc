#include "json.h"

#include <cstdlib>
#include <cstring>

namespace aegis {
namespace json {
namespace {

class Reader {
 public:
  explicit Reader(const std::string& t) : t_(t) {}

  bool Document(Value* out, std::string* err) {
    SkipWs();
    if (t_.compare(0, 3, "\xEF\xBB\xBF") == 0) i_ = 3;  // UTF-8 BOM
    SkipWs();
    if (!ParseValue(out, 0)) {
      *err = err_.empty() ? "invalid JSON" : err_;
      return false;
    }
    SkipWs();
    if (i_ != t_.size()) {
      *err = "unexpected data after JSON value at offset " + std::to_string(i_);
      return false;
    }
    return true;
  }

 private:
  bool Fail(const std::string& m) {
    if (err_.empty()) err_ = m + " at offset " + std::to_string(i_);
    return false;
  }

  void SkipWs() {
    while (i_ < t_.size() && (t_[i_] == ' ' || t_[i_] == '\t' || t_[i_] == '\n' || t_[i_] == '\r')) ++i_;
  }

  bool Literal(const char* word) {
    const size_t n = std::strlen(word);
    if (t_.compare(i_, n, word) != 0) return Fail("invalid literal");
    i_ += n;
    return true;
  }

  static void AppendUtf8(std::string* out, uint32_t cp) {
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

  bool Hex4(uint32_t* out) {
    if (i_ + 4 > t_.size()) return Fail("truncated \\u escape");
    uint32_t v = 0;
    for (int k = 0; k < 4; ++k) {
      const char c = t_[i_++];
      v <<= 4;
      if (c >= '0' && c <= '9') {
        v |= static_cast<uint32_t>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        v |= static_cast<uint32_t>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        v |= static_cast<uint32_t>(c - 'A' + 10);
      } else {
        return Fail("invalid \\u escape");
      }
    }
    *out = v;
    return true;
  }

  bool ParseString(std::string* out) {
    ++i_;  // "
    while (i_ < t_.size()) {
      const char c = t_[i_];
      if (c == '"') {
        ++i_;
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20) return Fail("control character in string");
      if (c != '\\') {
        out->push_back(c);
        ++i_;
        continue;
      }
      if (++i_ >= t_.size()) break;
      const char e = t_[i_++];
      switch (e) {
        case '"':
        case '\\':
        case '/':
          out->push_back(e);
          break;
        case 'b':
          out->push_back('\b');
          break;
        case 'f':
          out->push_back('\f');
          break;
        case 'n':
          out->push_back('\n');
          break;
        case 'r':
          out->push_back('\r');
          break;
        case 't':
          out->push_back('\t');
          break;
        case 'u': {
          uint32_t cp = 0;
          if (!Hex4(&cp)) return false;
          if (cp >= 0xd800 && cp <= 0xdbff && i_ + 1 < t_.size() && t_[i_] == '\\' && t_[i_ + 1] == 'u') {
            const size_t save = i_;
            i_ += 2;
            uint32_t lo = 0;
            if (!Hex4(&lo)) return false;
            if (lo >= 0xdc00 && lo <= 0xdfff) {
              cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            } else {
              i_ = save;
              cp = 0xfffd;
            }
          } else if (cp >= 0xd800 && cp <= 0xdfff) {
            cp = 0xfffd;  // eşlenmemiş vekil
          }
          AppendUtf8(out, cp);
          break;
        }
        default:
          return Fail("invalid escape");
      }
    }
    return Fail("unterminated string");
  }

  bool ParseNumber(Value* out) {
    const size_t start = i_;
    if (t_[i_] == '-') ++i_;
    while (i_ < t_.size() && ((t_[i_] >= '0' && t_[i_] <= '9') || t_[i_] == '.' || t_[i_] == 'e' ||
                              t_[i_] == 'E' || t_[i_] == '+' || t_[i_] == '-')) {
      ++i_;
    }
    const std::string lit = t_.substr(start, i_ - start);
    char* end = nullptr;
    out->type = Value::kNumber;
    out->n = std::strtod(lit.c_str(), &end);
    if (lit.empty() || !end || *end != '\0') return Fail("invalid number");
    return true;
  }

  bool ParseValue(Value* out, int depth) {
    if (depth > 64) return Fail("nesting too deep");
    SkipWs();
    if (i_ >= t_.size()) return Fail("unexpected end of input");
    const char c = t_[i_];
    if (c == '{') {
      out->type = Value::kObject;
      ++i_;
      SkipWs();
      if (i_ < t_.size() && t_[i_] == '}') {
        ++i_;
        return true;
      }
      for (;;) {
        SkipWs();
        if (i_ >= t_.size() || t_[i_] != '"') return Fail("expected object key");
        std::string key;
        if (!ParseString(&key)) return false;
        SkipWs();
        if (i_ >= t_.size() || t_[i_] != ':') return Fail("expected ':'");
        ++i_;
        Value v;
        if (!ParseValue(&v, depth + 1)) return false;
        out->members.emplace_back(std::move(key), std::move(v));
        SkipWs();
        if (i_ < t_.size() && t_[i_] == ',') {
          ++i_;
          continue;
        }
        if (i_ < t_.size() && t_[i_] == '}') {
          ++i_;
          return true;
        }
        return Fail("expected ',' or '}'");
      }
    }
    if (c == '[') {
      out->type = Value::kArray;
      ++i_;
      SkipWs();
      if (i_ < t_.size() && t_[i_] == ']') {
        ++i_;
        return true;
      }
      for (;;) {
        Value v;
        if (!ParseValue(&v, depth + 1)) return false;
        out->items.push_back(std::move(v));
        SkipWs();
        if (i_ < t_.size() && t_[i_] == ',') {
          ++i_;
          continue;
        }
        if (i_ < t_.size() && t_[i_] == ']') {
          ++i_;
          return true;
        }
        return Fail("expected ',' or ']'");
      }
    }
    if (c == '"') {
      out->type = Value::kString;
      return ParseString(&out->s);
    }
    if (c == 't') {
      out->type = Value::kBool;
      out->b = true;
      return Literal("true");
    }
    if (c == 'f') {
      out->type = Value::kBool;
      return Literal("false");
    }
    if (c == 'n') {
      out->type = Value::kNull;
      return Literal("null");
    }
    if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber(out);
    return Fail("unexpected character");
  }

  const std::string& t_;
  size_t i_ = 0;
  std::string err_;
};

}  // namespace

bool Parse(const std::string& text, Value* out, std::string* err) {
  Reader r(text);
  *out = Value();
  return r.Document(out, err);
}

}  // namespace json
}  // namespace aegis
