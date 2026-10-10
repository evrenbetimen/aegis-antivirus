// Aegis C++ motoru birim testleri (bağımlılıksız). ctest ya da doğrudan çalıştırın.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include "json.h"
#include "scanner.h"
#include "sha256.h"
#include "yara.h"

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    ++g_checks;                                                         \
    if (!(cond)) {                                                      \
      ++g_failures;                                                     \
      std::fprintf(stderr, "%s:%d: CHECK başarısız: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                   \
  } while (0)

#define CHECK_EQ(a, b)                                                                         \
  do {                                                                                         \
    ++g_checks;                                                                                \
    const auto va = (a);                                                                       \
    const auto vb = (b);                                                                       \
    if (!(va == vb)) {                                                                         \
      ++g_failures;                                                                            \
      std::fprintf(stderr, "%s:%d: CHECK_EQ başarısız: %s != %s\n", __FILE__, __LINE__, #a, #b); \
    }                                                                                          \
  } while (0)

std::vector<std::pair<const char*, std::function<void()>>>& Registry() {
  static std::vector<std::pair<const char*, std::function<void()>>> r;
  return r;
}
struct Register {
  Register(const char* name, std::function<void()> fn) { Registry().emplace_back(name, std::move(fn)); }
};
#define TEST(name)                                \
  void name();                                    \
  const Register reg_##name(#name, name);         \
  void name()

std::string Bytes(std::initializer_list<int> v) {
  std::string s;
  for (int b : v) s.push_back(static_cast<char>(b));
  return s;
}

// Tek kurallı derle + eşleştir: kural adı ya da "" döner.
std::string Hit(const std::string& rules, const std::string& data, double filesize = -1, long head = -1) {
  aegis::yara::CompileResult r = aegis::yara::Compile(rules);
  aegis::yara::ScanWindow w;
  w.data = reinterpret_cast<const uint8_t*>(data.data());
  w.len = data.size();
  w.filesize = filesize < 0 ? static_cast<double>(data.size()) : filesize;
  w.head_length = head < 0 ? data.size() : static_cast<size_t>(head);
  const int idx = aegis::yara::MatchRules(r.rules, w);
  return idx < 0 ? "" : r.rules[static_cast<size_t>(idx)].name;
}

/* ---------------- SHA-256 (NIST FIPS 180-4 örnekleri) ---------------- */

TEST(Sha256Vectors) {
  CHECK_EQ(aegis::Sha256Hex(nullptr, 0), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  const std::string abc = "abc";
  CHECK_EQ(aegis::Sha256Hex(reinterpret_cast<const uint8_t*>(abc.data()), abc.size()),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  const std::string m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  CHECK_EQ(aegis::Sha256Hex(reinterpret_cast<const uint8_t*>(m.data()), m.size()),
           std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  aegis::Sha256 h;
  const std::string chunk(1000, 'a');
  for (int i = 0; i < 1000; ++i) h.Update(reinterpret_cast<const uint8_t*>(chunk.data()), chunk.size());
  CHECK_EQ(h.HexDigest(), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

/* ---------------- YARA ---------------- */

TEST(TextModifiers) {
  CHECK_EQ(Hit("rule A { strings: $a = \"Evil\" nocase condition: $a }", "xx eVIL yy"), std::string("A"));
  CHECK_EQ(Hit("rule A { strings: $a = \"Evil\" condition: $a }", "xx eVIL yy"), std::string(""));
  CHECK_EQ(Hit("rule W { strings: $a = \"ab\" wide condition: $a }", Bytes({'a', 0, 'b', 0})), std::string("W"));
  CHECK_EQ(Hit("rule W { strings: $a = \"ab\" wide condition: $a }", "ab"), std::string(""));
  CHECK_EQ(Hit("rule W { strings: $a = \"ab\" wide ascii condition: $a }", "ab"), std::string("W"));
  CHECK_EQ(Hit("rule F { strings: $a = \"tok\" fullword condition: $a }", "a tok."), std::string("F"));
  CHECK_EQ(Hit("rule F { strings: $a = \"tok\" fullword condition: $a }", "atoken"), std::string(""));
  CHECK_EQ(Hit("rule U { strings: $a = \"ü\" wide condition: $a }", Bytes({0xfc, 0x00})), std::string("U"));
}

TEST(HexPatterns) {
  const std::string r = "rule H { strings: $a = { 41 [2-4] 42 ( 43 | 44 45 ) 4? ~00 } condition: $a }";
  CHECK_EQ(Hit(r, Bytes({0x41, 1, 2, 0x42, 0x43, 0x4f, 0x01})), std::string("H"));
  CHECK_EQ(Hit(r, Bytes({0x41, 1, 2, 3, 4, 0x42, 0x44, 0x45, 0x40, 0x07})), std::string("H"));
  CHECK_EQ(Hit(r, Bytes({0x41, 1, 0x42, 0x43, 0x4f, 0x01})), std::string(""));
  CHECK_EQ(Hit(r, Bytes({0x41, 1, 2, 0x42, 0x43, 0x4f, 0x00})), std::string(""));
  CHECK_EQ(Hit(r, Bytes({0x41, 1, 2, 0x42, 0x43, 0x5f, 0x01})), std::string(""));
  const std::string j = "rule J { strings: $a = { AA [3] BB [2-] CC [-] DD } condition: $a }";
  CHECK_EQ(Hit(j, Bytes({0xaa, 0, 0, 0, 0xbb, 1, 2, 3, 0xcc, 0xdd})), std::string("J"));
  CHECK_EQ(Hit(j, Bytes({0xaa, 0, 0, 0xbb, 1, 2, 0xcc, 0xdd})), std::string(""));
}

TEST(Conditions) {
  std::string pe(0x100, '\0');
  pe[0] = 'M';
  pe[1] = 'Z';
  pe[0x3c] = static_cast<char>(0x80);
  pe.replace(0x80, 4, std::string("PE\0\0", 4));
  pe += "demo-pe-payload";
  const std::string rule =
      "rule P { strings: $m = \"demo-pe-payload\" condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == "
      "0x00004550 and $m }";
  CHECK_EQ(Hit(rule, pe), std::string("P"));
  CHECK_EQ(Hit(rule, "xx demo-pe-payload"), std::string(""));
  CHECK_EQ(Hit("rule F { strings: $a = \"tok\" condition: $a and filesize < 1KB and #a * 2 + 1 == 5 }", "tok tok"),
           std::string("F"));
  CHECK_EQ(Hit("rule F { strings: $a = \"tok\" condition: #a == 2 }", "tok tok tok"), std::string(""));
  CHECK_EQ(Hit("rule Q { strings: $a1 = \"x\" $a2 = \"y\" $b = \"z\" condition: 2 of ($a*) and none of ($b) }", "x y"),
           std::string("Q"));
  CHECK_EQ(Hit("rule Q { strings: $a = \"x\" $b = \"y\" condition: all of them }", "x"), std::string(""));
  CHECK_EQ(Hit("rule S { condition: (-1 << 3) == -8 and (0x10 >> 2) == 4 and (7 \\ 2) == 3 and (7 % 4) == 3 }", "a"),
           std::string("S"));
  CHECK_EQ(Hit("rule At { strings: $a = \"MZ\" condition: $a at 0 }", "MZxx"), std::string("At"));
  CHECK_EQ(Hit("rule At { strings: $a = \"MZ\" condition: $a at 0 }", "xMZx"), std::string(""));
  // Ofset denetimleri yalnızca gerçek ofsetteki baş bölgede geçerli
  CHECK_EQ(Hit("rule At { strings: $a = \"MZ\" condition: $a at 0 }", "MZxx", 10000, 0), std::string(""));
  CHECK_EQ(Hit("rule Big { condition: filesize >= 2MB }", "a", 3 * 1024 * 1024), std::string("Big"));
}

TEST(SkipsUnsupported) {
  aegis::yara::CompileResult r = aegis::yara::Compile(
      "import \"pe\"\n"
      "rule Ok { strings: $a = \"x\" condition: $a }\n"
      "rule Mod { condition: pe.is_pe }\n"
      "rule Rx { strings: $r = /abc/ condition: $r }\n"
      "rule Undecl { strings: $a = \"a\" condition: $b }\n"
      "rule Ok2 { condition: true }\n");
  CHECK_EQ(r.rules.size(), static_cast<size_t>(2));
  CHECK_EQ(r.skipped.size(), static_cast<size_t>(3));
  CHECK_EQ(r.rules[0].name, std::string("Ok"));
  CHECK_EQ(r.rules[1].name, std::string("Ok2"));
}

TEST(FirstMatchWins) {
  CHECK_EQ(Hit("rule A { strings: $a = \"x\" condition: $a } rule B { condition: true }", "x"), std::string("A"));
  CHECK_EQ(Hit("rule A { strings: $a = \"x\" condition: $a } rule B { condition: true }", "y"), std::string("B"));
  // ~ ile tam sayı olmayan değer: kural eşleşmez, sonraki kurallar değerlendirilir
  CHECK_EQ(Hit("rule E { condition: ~(1 \\ 0) == 0 or true } rule B { condition: true }", "y"), std::string("E"));
}

TEST(Utf8Sanitize) {
  CHECK_EQ(aegis::yara::SanitizeUtf8(Bytes({'a', 0xff, 'b'})), std::string("a\xEF\xBF\xBD" "b"));
  CHECK_EQ(aegis::yara::SanitizeUtf8("ğüş"), std::string("ğüş"));
}

/* ---------------- JSON ---------------- */

TEST(JsonParse) {
  aegis::json::Value v;
  std::string err;
  CHECK(aegis::json::Parse("{\"a\":[1,2.5,true,null],\"s\":\"x\\u00fc\\ud83d\\ude00\\n\"}", &v, &err));
  CHECK_EQ(v.Get("a")->items.size(), static_cast<size_t>(4));
  CHECK_EQ(v.Get("s")->s, std::string("xü\xF0\x9F\x98\x80\n"));
  CHECK(!aegis::json::Parse("{\"a\":}", &v, &err));
  CHECK(!aegis::json::Parse("[1,2] x", &v, &err));
  CHECK(aegis::json::Parse("{\"k\":1,\"k\":2}", &v, &err));
  CHECK_EQ(v.Get("k")->n, 2.0);
}

/* ---------------- dosya tarayıcı ---------------- */

TEST(ScannerEndToEnd) {
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / ("aegis-engine-test-" + std::to_string(std::rand()));
  fs::create_directories(dir / "sig");
  std::ofstream(dir / "sig" / "db.json")
      << "{\"version\":\"t1\",\"sha256\":{\"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD \":"
         "\"Test.Abc\"},\"yara\":\"rule Embedded { strings: $e = \\\"embedded-marker\\\" condition: $e }\"}";
  std::ofstream(dir / "sig" / "rules.yar") << "rule Local { strings: $l = \"local-marker\" condition: $l }";
  std::ofstream(dir / "abc.txt") << "abc";
  std::ofstream(dir / "local.txt") << "...local-marker...";
  std::ofstream(dir / "emb.txt") << "...embedded-marker...";
  std::ofstream(dir / "clean.txt") << "nothing here";

  const aegis::Database db = aegis::LoadDatabase((dir / "sig").string());
  CHECK_EQ(db.version, std::string("t1"));
  CHECK_EQ(db.rules.size(), static_cast<size_t>(2));
  CHECK_EQ(db.rules[0].name, std::string("Local"));  // yerel kurallar önce

  aegis::ScanResult r = aegis::ScanFile(db, (dir / "abc.txt").string());
  CHECK(r.infected);
  CHECK_EQ(r.threat, std::string("Test.Abc"));
  CHECK_EQ(r.kind, std::string("sha256"));
  r = aegis::ScanFile(db, (dir / "local.txt").string());
  CHECK_EQ(r.threat, std::string("Local"));
  r = aegis::ScanFile(db, (dir / "emb.txt").string());
  CHECK_EQ(r.threat, std::string("Embedded"));
  r = aegis::ScanFile(db, (dir / "clean.txt").string());
  CHECK(r.ok && !r.infected);
  r = aegis::ScanFile(db, (dir / "missing").string());
  CHECK(!r.ok);

  // Büyük dosya: kuyruktaki işaret bulunur, ortadaki bulunmaz
  {
    std::ofstream big(dir / "big.bin", std::ios::binary);
    std::string filler(aegis::kStringScanLimit + 100, 'x');
    filler.replace(aegis::kStringScanLimit + 10, 12, "local-marker");
    big << filler << std::string(aegis::kTailScanSize, 'y');
  }
  r = aegis::ScanFile(db, (dir / "big.bin").string());
  CHECK(r.ok && !r.infected);
  {
    std::ofstream big(dir / "big2.bin", std::ios::binary);
    big << std::string(aegis::kStringScanLimit + 5000, 'x') << "local-marker" << std::string(100, 'y');
  }
  r = aegis::ScanFile(db, (dir / "big2.bin").string());
  CHECK_EQ(r.threat, std::string("Local"));
  fs::remove_all(dir);
}

}  // namespace

int main() {
  for (const auto& t : Registry()) {
    const int before = g_failures;
    t.second();
    std::printf("%s  %s\n", g_failures == before ? "PASS" : "FAIL", t.first);
  }
  std::printf("\n%d denetim, %d hata\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
