{
  "targets": [
    {
      "target_name": "aegis_engine",
      "sources": [
        "src/node/addon.cc",
        "src/core/sha256.cc",
        "src/core/yara_compile.cc",
        "src/core/yara_match.cc"
      ],
      "cflags_cc": ["-std=c++17", "-O2", "-Wall", "-Wextra"],
      "cflags_cc!": ["-fno-exceptions", "-fno-rtti", "-std=gnu++17", "-std=gnu++20"],
      "cflags!": ["-fno-exceptions"],
      "defines": ["NAPI_VERSION=8", "NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "GCC_ENABLE_CPP_RTTI": "YES",
            "GCC_OPTIMIZATION_LEVEL": "2",
            "MACOSX_DEPLOYMENT_TARGET": "11.0",
            "OTHER_CFLAGS": ["-arch x86_64", "-arch arm64"],
            "OTHER_LDFLAGS": ["-arch x86_64", "-arch arm64"]
          }
        }]
      ]
    }
  ]
}
