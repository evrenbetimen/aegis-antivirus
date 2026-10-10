// Küçük, bağımlılıksız JSON okuyucu (yalnızca imza veritabanı için).
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace aegis {
namespace json {

struct Value {
  enum Type { kNull, kBool, kNumber, kString, kArray, kObject };
  Type type = kNull;
  bool b = false;
  double n = 0;
  std::string s;
  std::vector<Value> items;
  std::vector<std::pair<std::string, Value>> members;  // sıra korunur

  const Value* Get(const std::string& key) const {
    const Value* found = nullptr;
    for (const auto& m : members) {
      if (m.first == key) found = &m.second;  // JSON.parse: son anahtar kazanır
    }
    return found;
  }
};

// Başarısızlıkta false döner ve hata iletisini err'e yazar.
bool Parse(const std::string& text, Value* out, std::string* err);

}  // namespace json
}  // namespace aegis
