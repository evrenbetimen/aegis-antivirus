#include "scanner.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "json.h"
#include "sha256.h"

namespace aegis {
namespace {

bool ReadWhole(const std::string& path, std::string* out, int* err) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    *err = errno;
    return false;
  }
  std::string data;
  char buf[65536];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
  const bool failed = std::ferror(f) != 0;
  std::fclose(f);
  if (failed) {
    *err = EIO;
    return false;
  }
  *out = std::move(data);
  return true;
}

bool ReadRange(FILE* f, unsigned long long start, size_t length, std::string* out) {
#if defined(_WIN32)
  if (_fseeki64(f, static_cast<long long>(start), SEEK_SET) != 0) return false;
#else
  if (fseeko(f, static_cast<off_t>(start), SEEK_SET) != 0) return false;
#endif
  out->assign(length, '\0');
  size_t got = 0;
  while (got < length) {
    size_t n = std::fread(&(*out)[got], 1, length - got, f);
    if (n == 0) break;
    got += n;
  }
  out->resize(got);
  return true;
}

std::string Trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\n' || s[a] == '\r')) ++a;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\n' || s[b - 1] == '\r')) --b;
  return s.substr(a, b - a);
}

std::string Lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 0x20);
  }
  return s;
}

// EICAR test dizgisi kaynakta ham metin olarak bulunmaz (antivirüsler bu
// dosyayı silmesin diye): karakter kodlarından çalışma anında kurulur.
const std::string& Eicar() {
  static const std::string s = [] {
    const unsigned char codes[] = {88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53, 52,
                                   40, 80, 94, 41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45,
                                   83, 84, 65, 78, 68, 65, 82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85,
                                   83, 45, 84, 69, 83, 84, 45, 70, 73, 76, 69, 33, 36, 72, 43, 72, 42};
    return std::string(reinterpret_cast<const char*>(codes), sizeof(codes));
  }();
  return s;
}

std::string NumberToString(double v) {
  std::ostringstream os;
  os.precision(17);
  os << v;
  return os.str();
}

}  // namespace

void AddRules(Database* db, const std::string& text, const std::string& label) {
  yara::CompileResult r = yara::Compile(yara::SanitizeUtf8(text));
  for (auto& rule : r.rules) db->rules.push_back(std::move(rule));
  for (const auto& s : r.skipped) {
    db->skipped.push_back(label + ": " + (s.has_name ? s.rule : std::string("?")) + ": " + s.error);
  }
}

Database LoadDatabase(const std::string& dir) {
  Database db;
  const std::string sep = (!dir.empty() && dir.back() == '/') ? "" : "/";
  std::vector<yara::Rule> embedded;

  std::string text;
  int err = 0;
  if (ReadWhole(dir + sep + "db.json", &text, &err)) {
    json::Value root;
    std::string perr;
    if (!json::Parse(text, &root, &perr)) {
      db.skipped.push_back("db.json: " + perr);
    } else if (root.type == json::Value::kObject) {
      if (const json::Value* v = root.Get("version")) {
        if (v->type == json::Value::kString) {
          db.version = v->s;
        } else if (v->type == json::Value::kNumber) {
          db.version = NumberToString(v->n);
        } else if (v->type == json::Value::kBool) {
          db.version = v->b ? "true" : "false";
        }
      }
      if (const json::Value* sha = root.Get("sha256")) {
        for (const auto& m : sha->members) {
          if (m.second.type == json::Value::kString) db.sha256[Lower(Trim(m.first))] = m.second.s;
        }
      }
      if (const json::Value* y = root.Get("yara")) {
        if (y->type == json::Value::kString && !y->s.empty()) {
          Database tmp;
          AddRules(&tmp, y->s, "db.json");
          embedded = std::move(tmp.rules);
          db.skipped.insert(db.skipped.end(), tmp.skipped.begin(), tmp.skipped.end());
        }
      }
    }
  } else if (err != ENOENT) {
    db.skipped.push_back(std::string("db.json: ") + std::strerror(err));
  }

  if (ReadWhole(dir + sep + "rules.yar", &text, &err)) {
    AddRules(&db, text, "rules.yar");  // yerel kurallar önce
  } else if (err != ENOENT) {
    db.skipped.push_back(std::string("rules.yar: ") + std::strerror(err));
  }
  for (auto& rule : embedded) db.rules.push_back(std::move(rule));
  return db;
}

ScanResult ScanFile(const Database& db, const std::string& path) {
  ScanResult r;
  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    r.ok = false;
    r.error = std::strerror(errno);
    return r;
  }
  if (!S_ISREG(st.st_mode)) {
    r.ok = false;
    r.error = "not a regular file";
    return r;
  }
  r.size = static_cast<unsigned long long>(st.st_size);

  if (r.size <= kMaxHashSize && !db.sha256.empty()) {
    int err = 0;
    if (!Sha256File(path.c_str(), &r.sha256, &err)) {
      r.ok = false;
      r.error = std::strerror(err);
      return r;
    }
    auto it = db.sha256.find(r.sha256);
    if (it != db.sha256.end()) {
      r.infected = true;
      r.threat = it->second;
      r.kind = "sha256";
      return r;
    }
  }

  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    r.ok = false;
    r.error = std::strerror(errno);
    return r;
  }
  std::string window;
  bool read_ok;
  if (r.size <= kStringScanLimit) {
    read_ok = ReadRange(f, 0, static_cast<size_t>(r.size), &window);
  } else {
    std::string tail;
    read_ok = ReadRange(f, 0, kStringScanLimit, &window) && ReadRange(f, r.size - kTailScanSize, kTailScanSize, &tail);
    window += tail;
  }
  std::fclose(f);
  if (!read_ok) {
    r.ok = false;
    r.error = "read failed";
    return r;
  }

  if (!db.rules.empty() && !window.empty()) {
    yara::ScanWindow w;
    w.data = reinterpret_cast<const uint8_t*>(window.data());
    w.len = window.size();
    w.filesize = static_cast<double>(r.size);
    w.head_length = r.size <= kStringScanLimit ? window.size() : kStringScanLimit;
    if (w.head_length > w.len) w.head_length = w.len;
    const int idx = yara::MatchRules(db.rules, w);
    if (idx >= 0) {
      r.infected = true;
      r.threat = db.rules[static_cast<size_t>(idx)].name;
      r.kind = "yara";
      return r;
    }
  }

  if (r.size <= 2048 && window.find(Eicar()) != std::string::npos) {
    r.infected = true;
    r.threat = "EICAR-Test-File";
    r.kind = "eicar";
  }
  return r;
}

}  // namespace aegis
