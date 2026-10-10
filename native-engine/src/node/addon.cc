// Node-API bağlaması: aegis_engine.node
//
//   version()                         -> "1.0.0"
//   new RuleSet(text)                 -> derlenmiş YARA kuralları
//     .count()                        -> kural sayısı
//     .names()                        -> [ad, ...]
//     .skipped()                      -> [{rule, error}, ...]
//     .match(buf, filesize, headLen)  -> ilk eşleşen kuralın indisi | -1
//   sha256(buf)                       -> onaltılık özet
//   sha256FileSync(path)              -> onaltılık özet (hata: err.code)
//   sha256File(path)                  -> Promise<onaltılık özet> (iş parçacığı havuzunda)
//   sha256Accelerated                 -> true: donanım hızlandırmalı (macOS CommonCrypto)
//
// Bağlam farkındalıklı (NAPI_MODULE_INIT): worker_threads içinde de yüklenir.

#define NAPI_VERSION 8
#include <node_api.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "../core/sha256.h"
#include "../core/yara.h"

#ifndef AEGIS_ENGINE_VERSION
#define AEGIS_ENGINE_VERSION "1.0.0"
#endif

namespace {

using aegis::yara::CompileResult;

#define NAPI_CALL(env, call)                                     \
  do {                                                           \
    if ((call) != napi_ok) {                                     \
      const napi_extended_error_info* info = nullptr;            \
      napi_get_last_error_info((env), &info);                    \
      bool pending = false;                                      \
      napi_is_exception_pending((env), &pending);                \
      if (!pending) {                                            \
        napi_throw_error((env), nullptr,                         \
                         info && info->error_message             \
                             ? info->error_message               \
                             : "aegis_engine: N-API çağrısı başarısız"); \
      }                                                          \
      return nullptr;                                            \
    }                                                            \
  } while (0)

napi_value MakeString(napi_env env, const std::string& s) {
  napi_value v;
  napi_create_string_utf8(env, s.data(), s.size(), &v);
  return v;
}

bool GetString(napi_env env, napi_value value, std::string* out) {
  size_t len = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &len) != napi_ok) return false;
  out->assign(len, '\0');
  size_t written = 0;
  if (napi_get_value_string_utf8(env, value, &(*out)[0], len + 1, &written) != napi_ok) return false;
  out->resize(written);
  return true;
}

// Buffer, TypedArray ya da ArrayBuffer'dan bayt görünümü.
bool GetBytes(napi_env env, napi_value value, const uint8_t** data, size_t* len) {
  bool is_buffer = false;
  napi_is_buffer(env, value, &is_buffer);
  if (is_buffer) {
    void* p = nullptr;
    if (napi_get_buffer_info(env, value, &p, len) != napi_ok) return false;
    *data = static_cast<const uint8_t*>(p);
    return true;
  }
  bool is_typed = false;
  napi_is_typedarray(env, value, &is_typed);
  if (is_typed) {
    napi_typedarray_type type;
    size_t length = 0;
    void* p = nullptr;
    napi_value ab;
    size_t offset = 0;
    if (napi_get_typedarray_info(env, value, &type, &length, &p, &ab, &offset) != napi_ok) return false;
    size_t elem = 1;
    switch (type) {
      case napi_int16_array:
      case napi_uint16_array:
        elem = 2;
        break;
      case napi_int32_array:
      case napi_uint32_array:
      case napi_float32_array:
        elem = 4;
        break;
      case napi_float64_array:
      case napi_bigint64_array:
      case napi_biguint64_array:
        elem = 8;
        break;
      default:
        break;
    }
    *data = static_cast<const uint8_t*>(p);
    *len = length * elem;
    return true;
  }
  bool is_ab = false;
  napi_is_arraybuffer(env, value, &is_ab);
  if (is_ab) {
    void* p = nullptr;
    if (napi_get_arraybuffer_info(env, value, &p, len) != napi_ok) return false;
    *data = static_cast<const uint8_t*>(p);
    return true;
  }
  return false;
}

const char* ErrnoCode(int err) {
  switch (err) {
    case ENOENT:
      return "ENOENT";
    case EACCES:
      return "EACCES";
    case EPERM:
      return "EPERM";
    case EISDIR:
      return "EISDIR";
    case EMFILE:
      return "EMFILE";
    case EIO:
      return "EIO";
    default:
      return "EUNKNOWN";
  }
}

napi_value MakeErrnoError(napi_env env, int err, const std::string& path) {
  const char* code = ErrnoCode(err);
  std::string msg = std::string(code) + ": " + std::strerror(err) + ", open '" + path + "'";
  napi_value error;
  napi_create_error(env, MakeString(env, code), MakeString(env, msg), &error);
  napi_value errno_value;
  napi_create_int32(env, -err, &errno_value);
  napi_set_named_property(env, error, "errno", errno_value);
  napi_set_named_property(env, error, "path", MakeString(env, path));
  return error;
}

/* ---------------- RuleSet ---------------- */

struct RuleSet {
  CompileResult compiled;
};

void FinalizeRuleSet(napi_env, void* data, void*) { delete static_cast<RuleSet*>(data); }

RuleSet* Unwrap(napi_env env, napi_callback_info info, size_t* argc, napi_value* argv) {
  napi_value self;
  if (napi_get_cb_info(env, info, argc, argv, &self, nullptr) != napi_ok) return nullptr;
  void* ptr = nullptr;
  if (napi_unwrap(env, self, &ptr) != napi_ok || !ptr) {
    napi_throw_type_error(env, nullptr, "RuleSet bekleniyordu");
    return nullptr;
  }
  return static_cast<RuleSet*>(ptr);
}

napi_value RuleSetNew(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_value self;
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
  std::string text;
  if (argc >= 1) {
    napi_valuetype t;
    napi_typeof(env, argv[0], &t);
    if (t == napi_string && !GetString(env, argv[0], &text)) return nullptr;
  }
  std::unique_ptr<RuleSet> set(new RuleSet());
  try {
    set->compiled = aegis::yara::Compile(text);
  } catch (const std::exception& e) {
    napi_throw_error(env, nullptr, e.what());
    return nullptr;
  }
  NAPI_CALL(env, napi_wrap(env, self, set.get(), FinalizeRuleSet, nullptr, nullptr));
  set.release();
  return self;
}

napi_value RuleSetCount(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  RuleSet* set = Unwrap(env, info, &argc, nullptr);
  if (!set) return nullptr;
  napi_value v;
  NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(set->compiled.rules.size()), &v));
  return v;
}

napi_value RuleSetNames(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  RuleSet* set = Unwrap(env, info, &argc, nullptr);
  if (!set) return nullptr;
  napi_value arr;
  NAPI_CALL(env, napi_create_array_with_length(env, set->compiled.rules.size(), &arr));
  for (size_t i = 0; i < set->compiled.rules.size(); ++i) {
    NAPI_CALL(env, napi_set_element(env, arr, static_cast<uint32_t>(i), MakeString(env, set->compiled.rules[i].name)));
  }
  return arr;
}

napi_value RuleSetSkipped(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  RuleSet* set = Unwrap(env, info, &argc, nullptr);
  if (!set) return nullptr;
  napi_value arr;
  NAPI_CALL(env, napi_create_array_with_length(env, set->compiled.skipped.size(), &arr));
  for (size_t i = 0; i < set->compiled.skipped.size(); ++i) {
    const auto& s = set->compiled.skipped[i];
    napi_value obj;
    NAPI_CALL(env, napi_create_object(env, &obj));
    napi_value name;
    if (s.has_name) {
      name = MakeString(env, s.rule);
    } else {
      napi_get_null(env, &name);
    }
    napi_set_named_property(env, obj, "rule", name);
    napi_set_named_property(env, obj, "error", MakeString(env, s.error));
    NAPI_CALL(env, napi_set_element(env, arr, static_cast<uint32_t>(i), obj));
  }
  return arr;
}

double OptionalNumber(napi_env env, napi_value v, double fallback) {
  napi_valuetype t;
  if (napi_typeof(env, v, &t) != napi_ok || t != napi_number) return fallback;
  double d = fallback;
  napi_get_value_double(env, v, &d);
  return d;
}

napi_value RuleSetMatch(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  RuleSet* set = Unwrap(env, info, &argc, argv);
  if (!set) return nullptr;
  const uint8_t* data = nullptr;
  size_t len = 0;
  if (argc < 1 || !GetBytes(env, argv[0], &data, &len)) {
    napi_throw_type_error(env, nullptr, "match(buffer, filesize?, headLength?) bir Buffer bekler");
    return nullptr;
  }
  aegis::yara::ScanWindow w;
  w.data = data;
  w.len = len;
  w.filesize = argc >= 2 ? OptionalNumber(env, argv[1], static_cast<double>(len)) : static_cast<double>(len);
  double head = argc >= 3 ? OptionalNumber(env, argv[2], static_cast<double>(len)) : static_cast<double>(len);
  if (!(head >= 0)) head = 0;  // NaN dahil
  w.head_length = head < static_cast<double>(len) ? static_cast<size_t>(head) : len;
  int idx = -1;
  try {
    idx = aegis::yara::MatchRules(set->compiled.rules, w);
  } catch (const std::exception& e) {
    napi_throw_error(env, nullptr, e.what());
    return nullptr;
  }
  napi_value v;
  NAPI_CALL(env, napi_create_int32(env, idx, &v));
  return v;
}

/* ---------------- SHA-256 ---------------- */

napi_value Sha256Buffer(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
  const uint8_t* data = nullptr;
  size_t len = 0;
  if (argc < 1 || !GetBytes(env, argv[0], &data, &len)) {
    napi_throw_type_error(env, nullptr, "sha256(buffer) bir Buffer bekler");
    return nullptr;
  }
  return MakeString(env, aegis::Sha256Hex(data, len));
}

napi_value Sha256FileSync(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
  std::string path;
  if (argc < 1 || !GetString(env, argv[0], &path)) {
    napi_throw_type_error(env, nullptr, "sha256FileSync(path) bir yol bekler");
    return nullptr;
  }
  std::string hex;
  int err = 0;
  if (!aegis::Sha256File(path.c_str(), &hex, &err)) {
    napi_throw(env, MakeErrnoError(env, err, path));
    return nullptr;
  }
  return MakeString(env, hex);
}

struct HashJob {
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  std::string path;
  std::string hex;
  int err = 0;
  bool ok = false;
};

void HashExecute(napi_env, void* data) {
  HashJob* job = static_cast<HashJob*>(data);
  job->ok = aegis::Sha256File(job->path.c_str(), &job->hex, &job->err);
}

void HashComplete(napi_env env, napi_status status, void* data) {
  std::unique_ptr<HashJob> job(static_cast<HashJob*>(data));
  if (status != napi_ok) {
    napi_value err;
    napi_create_error(env, nullptr, MakeString(env, "sha256File iptal edildi"), &err);
    napi_reject_deferred(env, job->deferred, err);
  } else if (job->ok) {
    napi_resolve_deferred(env, job->deferred, MakeString(env, job->hex));
  } else {
    napi_reject_deferred(env, job->deferred, MakeErrnoError(env, job->err, job->path));
  }
  napi_delete_async_work(env, job->work);
}

napi_value Sha256FileAsync(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
  std::unique_ptr<HashJob> job(new HashJob());
  if (argc < 1 || !GetString(env, argv[0], &job->path)) {
    napi_throw_type_error(env, nullptr, "sha256File(path) bir yol bekler");
    return nullptr;
  }
  napi_value promise;
  NAPI_CALL(env, napi_create_promise(env, &job->deferred, &promise));
  napi_value name = MakeString(env, "aegis:sha256File");
  NAPI_CALL(env, napi_create_async_work(env, nullptr, name, HashExecute, HashComplete, job.get(), &job->work));
  NAPI_CALL(env, napi_queue_async_work(env, job->work));
  job.release();
  return promise;
}

napi_value Version(napi_env env, napi_callback_info) { return MakeString(env, AEGIS_ENGINE_VERSION); }

}  // namespace

NAPI_MODULE_INIT() {
  napi_property_descriptor methods[] = {
      {"count", nullptr, RuleSetCount, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"names", nullptr, RuleSetNames, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"skipped", nullptr, RuleSetSkipped, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"match", nullptr, RuleSetMatch, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  napi_value rule_set;
  if (napi_define_class(env, "RuleSet", NAPI_AUTO_LENGTH, RuleSetNew, nullptr, 4, methods, &rule_set) != napi_ok) {
    return nullptr;
  }
  napi_property_descriptor exports_desc[] = {
      {"RuleSet", nullptr, nullptr, nullptr, nullptr, rule_set, napi_enumerable, nullptr},
      {"version", nullptr, Version, nullptr, nullptr, nullptr, napi_enumerable, nullptr},
      {"sha256", nullptr, Sha256Buffer, nullptr, nullptr, nullptr, napi_enumerable, nullptr},
      {"sha256FileSync", nullptr, Sha256FileSync, nullptr, nullptr, nullptr, napi_enumerable, nullptr},
      {"sha256File", nullptr, Sha256FileAsync, nullptr, nullptr, nullptr, napi_enumerable, nullptr},
  };
  if (napi_define_properties(env, exports, 5, exports_desc) != napi_ok) return nullptr;
  napi_value accelerated;
  napi_get_boolean(env, aegis::kSha256Accelerated, &accelerated);
  napi_set_named_property(env, exports, "sha256Accelerated", accelerated);
  return exports;
}
