cmake_minimum_required(VERSION 3.16)
project(aegis_engine VERSION 1.0.0 LANGUAGES CXX)

# Aegis C++ tarama motoru
#   aegis_core   : SHA-256, YARA derleyici/eşleştirici, JSON, dosya tarayıcı
#   aegis-scan   : komut satırı tarayıcısı
#   engine_tests : C++ birim testleri (ctest)
# Electron eklentisi (aegis_engine.node) aynı çekirdekten binding.gyp ile derlenir.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(AEGIS_SANITIZE "AddressSanitizer + UBSan ile derle" OFF)

add_library(aegis_core STATIC
  src/core/sha256.cc
  src/core/yara_compile.cc
  src/core/yara_match.cc
  src/core/json.cc
  src/core/scanner.cc)
target_include_directories(aegis_core PUBLIC src/core)
target_compile_definitions(aegis_core PUBLIC AEGIS_ENGINE_VERSION="${PROJECT_VERSION}")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(aegis_core PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter)
  if(AEGIS_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
    target_compile_options(aegis_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(aegis_core PUBLIC -fsanitize=address,undefined)
  endif()
endif()

add_executable(aegis-scan src/cli/main.cc)
target_link_libraries(aegis-scan PRIVATE aegis_core)

enable_testing()
add_executable(engine_tests tests/engine_tests.cc)
target_link_libraries(engine_tests PRIVATE aegis_core)
add_test(NAME engine_tests COMMAND engine_tests)
