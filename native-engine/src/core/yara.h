// Aegis YARA alt kümesi: derleyici ve eşleştirici (C++17).
//
// Bu modül src/signatures.js içindeki referans motorla birebir aynı
// semantiği uygular; test/native-engine.test.js iki motoru aynı girdilerde
// karşılaştırır. Desteklenen yapılar:
//   - metin dizgileri ("..." + nocase, ascii, wide, fullword)
//   - hex dizgileri ({ AA ?? A? ~BB [2-4] [n-] [-] ( CC | DD EE ) })
//   - koşullar: and/or/not, parantez, $a, $a at <ifade>, #a, filesize,
//     KB/MB ekleri, uint8/16/32[be](), int8/16/32[be](), + - * \ % & | ^
//     << >>, tekli - ~, karşılaştırmalar, any/all/none/<n> of them|($a*)
// Desteklenmeyen yapılar (modüller, regex, in, for, kural referansları)
// kuralın atlanmasına yol açar; asla yanlış değerlendirilmez.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aegis {
namespace yara {

struct Variant {
  std::string bytes;  // aranan bayt dizisi (UTF-8 ya da UTF-16LE)
  std::string lower;  // ASCII küçük harfe çevrilmiş hali (nocase)
  int step;           // 1 = ascii, 2 = wide (fullword sınır denetimi)
};

struct HexNode {
  enum Kind { kByte, kNotByte, kJump, kAlt };
  Kind kind = kByte;
  uint8_t mask = 0xff;  // kByte: (b & mask) == value
  uint8_t value = 0;
  double lo = 0;  // kJump
  double hi = 0;
  bool unbounded = false;
  std::vector<std::vector<HexNode>> alts;  // kAlt
};

struct Pattern {
  std::string id;
  bool is_text = true;
  // Metin
  std::string text;
  bool nocase = false;
  bool ascii = false;
  bool wide = false;
  bool fullword = false;
  std::vector<Variant> variants;
  // Hex
  bool exact = false;        // tümü sabit bayt → doğrudan arama
  std::string exact_bytes;   // exact == true
  std::vector<HexNode> seq;  // exact == false → geri izlemeli eşleştirici
};

struct IntFn {
  int size = 1;
  bool is_signed = false;
  bool big_endian = false;
};

struct Node {
  enum Type {
    kConst,
    kNum,
    kFilesize,
    kString,
    kCount,
    kAt,
    kInt,
    kNeg,
    kBin,
    kCmp,
    kNot,
    kAnd,
    kOr,
    kQuant
  };
  Type type = kConst;
  bool bval = false;
  double num = 0;
  std::string op;      // kNeg, kBin, kCmp
  std::string ref_id;  // kString, kCount, kAt (çözümlemeden önce)
  int str_index = -1;  // çözümlenmiş desen indisi
  IntFn fn;            // kInt
  std::unique_ptr<Node> a;       // left / operand / offset
  std::unique_ptr<Node> b;       // right
  // kQuant
  enum QKind { kAny, kAll, kNone, kExpr };
  QKind q_kind = kAny;
  std::unique_ptr<Node> q_expr;
  bool set_them = false;
  std::vector<std::pair<std::string, bool>> set;  // (id, önek mi)
  std::vector<int> ids;                           // çözümlenmiş indisler
};

struct Rule {
  std::string name;
  std::vector<Pattern> strings;
  std::unique_ptr<Node> condition;
};

struct Skipped {
  bool has_name = false;
  std::string rule;
  std::string error;
};

struct CompileResult {
  std::vector<Rule> rules;
  std::vector<Skipped> skipped;
};

// Kural metnini derler. Hiçbir zaman istisna fırlatmaz: bozuk kurallar
// atlanır ve skipped listesine yazılır.
CompileResult Compile(const std::string& text);

struct ScanWindow {
  const uint8_t* data = nullptr;
  size_t len = 0;
  double filesize = 0;     // gerçek dosya boyutu
  size_t head_length = 0;  // gerçek ofsetinde duran ilk bayt sayısı
};

// İlk eşleşen kuralın indisini döndürür; eşleşme yoksa -1.
int MatchRules(const std::vector<Rule>& rules, const ScanWindow& window);

// Geçersiz UTF-8 dizilerini U+FFFD ile değiştirir (JS TextDecoder davranışı).
std::string SanitizeUtf8(const std::string& in);

}  // namespace yara
}  // namespace aegis
