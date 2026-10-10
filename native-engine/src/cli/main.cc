// aegis-scan — Aegis komut satırı tarayıcısı (C++17)
//
//   aegis-scan [--db DIZIN] [--json] [--quiet] [--no-recursive] YOL...
//
// Çıkış kodları (clamscan ile uyumlu):
//   0 tehdit yok · 1 en az bir tehdit bulundu · 2 hata (ör. imza DB'si yok)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "../core/scanner.h"

#ifndef AEGIS_ENGINE_VERSION
#define AEGIS_ENGINE_VERSION "1.0.0"
#endif

namespace fs = std::filesystem;

namespace {

struct Options {
  std::string db_dir;
  bool json = false;
  bool quiet = false;
  bool recursive = true;
  std::vector<std::string> paths;
};

struct Totals {
  unsigned long long files = 0;
  unsigned long long bytes = 0;
  unsigned long long infected = 0;
  unsigned long long errors = 0;
};

void Usage(FILE* out) {
  std::fprintf(out,
               "aegis-scan %s — Aegis C++ tarama motoru\n\n"
               "Kullanım: aegis-scan [seçenekler] YOL...\n\n"
               "  --db DIZIN        db.json ve rules.yar içeren imza dizini\n"
               "                    (varsayılan: $AEGIS_SIGNATURES ya da ./signatures)\n"
               "  --json            her dosya için bir JSON satırı yaz\n"
               "  --quiet           yalnızca tehditleri ve hataları yaz\n"
               "  --no-recursive    dizinlere inme\n"
               "  --version         sürümü yaz\n"
               "  -h, --help        bu yardımı göster\n\n"
               "Çıkış kodu: 0 temiz, 1 tehdit bulundu, 2 hata\n",
               AEGIS_ENGINE_VERSION);
}

std::string JsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (unsigned char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  return out;
}

void Report(const Options& opt, const std::string& path, const aegis::ScanResult& r, Totals* t) {
  if (!r.ok) {
    ++t->errors;
    if (opt.json) {
      std::printf("{\"path\":\"%s\",\"status\":\"error\",\"error\":\"%s\"}\n", JsonEscape(path).c_str(),
                  JsonEscape(r.error).c_str());
    } else {
      std::fprintf(stderr, "%s: HATA (%s)\n", path.c_str(), r.error.c_str());
    }
    return;
  }
  ++t->files;
  t->bytes += r.size;
  if (r.infected) ++t->infected;
  if (opt.json) {
    std::printf("{\"path\":\"%s\",\"status\":\"%s\",\"size\":%llu", JsonEscape(path).c_str(),
                r.infected ? "infected" : "clean", r.size);
    if (!r.sha256.empty()) std::printf(",\"sha256\":\"%s\"", r.sha256.c_str());
    if (r.infected) {
      std::printf(",\"threat\":\"%s\",\"kind\":\"%s\"", JsonEscape(r.threat).c_str(), r.kind.c_str());
    }
    std::printf("}\n");
  } else if (r.infected) {
    std::printf("%s: %s (%s) BULUNDU\n", path.c_str(), r.threat.c_str(), r.kind.c_str());
  } else if (!opt.quiet) {
    std::printf("%s: TEMİZ\n", path.c_str());
  }
}

void ScanPath(const Options& opt, const aegis::Database& db, const std::string& root, Totals* t) {
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(root, ec);
  if (ec) {
    aegis::ScanResult r;
    r.ok = false;
    r.error = ec.message();
    Report(opt, root, r, t);
    return;
  }
  if (fs::is_directory(st)) {
    if (!opt.recursive) {
      for (const auto& entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied, ec)) {
        std::error_code e2;
        if (entry.is_regular_file(e2) && !entry.is_symlink(e2)) Report(opt, entry.path().string(), aegis::ScanFile(db, entry.path().string()), t);
      }
    } else {
      fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
      const fs::recursive_directory_iterator end;
      while (!ec && it != end) {
        std::error_code e2;
        const std::string current = it->path().string();
        if (it->is_symlink(e2)) {
          // Bağlantıları izleme: döngü ve dizin dışına kaçışı önler
        } else if (it->is_regular_file(e2)) {
          Report(opt, current, aegis::ScanFile(db, current), t);
        }
        it.increment(ec);
        if (ec) {
          aegis::ScanResult r;
          r.ok = false;
          r.error = ec.message();
          Report(opt, current, r, t);
          ec.clear();
          break;
        }
      }
    }
    if (ec) {
      aegis::ScanResult r;
      r.ok = false;
      r.error = ec.message();
      Report(opt, root, r, t);
    }
    return;
  }
  Report(opt, root, aegis::ScanFile(db, root), t);
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      Usage(stdout);
      return 0;
    } else if (a == "--version") {
      std::printf("aegis-scan %s\n", AEGIS_ENGINE_VERSION);
      return 0;
    } else if (a == "--db") {
      if (++i >= argc) {
        std::fprintf(stderr, "--db bir dizin bekler\n");
        return 2;
      }
      opt.db_dir = argv[i];
    } else if (a == "--json") {
      opt.json = true;
    } else if (a == "--quiet") {
      opt.quiet = true;
    } else if (a == "--no-recursive") {
      opt.recursive = false;
    } else if (a == "--") {
      for (++i; i < argc; ++i) opt.paths.push_back(argv[i]);
    } else if (a.size() > 1 && a[0] == '-') {
      std::fprintf(stderr, "bilinmeyen seçenek: %s\n", a.c_str());
      Usage(stderr);
      return 2;
    } else {
      opt.paths.push_back(a);
    }
  }
  if (opt.paths.empty()) {
    Usage(stderr);
    return 2;
  }
  if (opt.db_dir.empty()) {
    const char* env = std::getenv("AEGIS_SIGNATURES");
    opt.db_dir = env && *env ? env : "signatures";
  }

  std::error_code ec;
  if (!fs::is_directory(opt.db_dir, ec)) {
    std::fprintf(stderr, "imza dizini bulunamadı: %s\n", opt.db_dir.c_str());
    return 2;
  }
  const aegis::Database db = aegis::LoadDatabase(opt.db_dir);
  for (const auto& s : db.skipped) std::fprintf(stderr, "uyarı: atlandı: %s\n", s.c_str());
  if (db.sha256.empty() && db.rules.empty()) {
    std::fprintf(stderr, "imza veritabanı boş: %s\n", opt.db_dir.c_str());
    return 2;
  }
  if (!opt.json && !opt.quiet) {
    std::fprintf(stderr, "Aegis C++ motoru %s · imza DB %s · %zu özet · %zu kural\n", AEGIS_ENGINE_VERSION,
                 db.version.c_str(), db.sha256.size(), db.rules.size());
  }

  Totals t;
  for (const auto& p : opt.paths) ScanPath(opt, db, p, &t);

  if (opt.json) {
    std::printf("{\"summary\":true,\"files\":%llu,\"bytes\":%llu,\"infected\":%llu,\"errors\":%llu}\n", t.files,
                t.bytes, t.infected, t.errors);
  } else {
    std::fprintf(stderr, "\n----------- TARAMA ÖZETİ -----------\nTaranan dosya: %llu\nBulunan tehdit: %llu\nHata: %llu\n",
                 t.files, t.infected, t.errors);
  }
  if (t.infected > 0) return 1;
  return t.errors > 0 && t.files == 0 ? 2 : 0;
}
