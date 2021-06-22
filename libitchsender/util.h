#pragma once
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>

namespace util {

using std::string;
using namespace std::literals;

static inline unsigned readUint16BE(const char* in) { return ((uint8_t)in[0] << 8) | (uint8_t)in[1]; }

static inline int readInt32BE(const char* in) {
  return (in[0] << 24) | ((in[1] & 0xFF) << 16) | ((in[2] & 0xFF) << 8) | (in[3] & 0xFF);
}

static inline int64_t readInt48BE(const char* in) {
  return ((int64_t)in[0] << 40) | ((int64_t)(in[1] & 0xFF) << 32) | ((int64_t)(in[2] & 0xFF) << 24) | ((in[3] & 0xFF) << 16) |
         ((in[4] & 0xFF) << 8) | (in[5] & 0xFF);
}

static inline int64_t readInt64BE(const char* in) {
  return ((int64_t)in[0] << 56) | ((int64_t)(in[1] & 0xFF) << 48) | ((int64_t)(in[2] & 0xFF) << 40) |
         ((int64_t)(in[3] & 0xFF) << 32) | ((int64_t)(in[4] & 0xFF) << 24) | ((in[5] & 0xFF) << 16) | ((in[6] & 0xFF) << 8) |
         (in[7] & 0xFF);
}

static inline void putInt16BE(char* dest, int x) {
  dest[0] = (char)(x >> 8);
  dest[1] = (char)x;
}

static inline void putInt32BE(char* dest, int x) {
  dest[0] = (char)(x >> 24);
  dest[1] = (char)(x >> 16);
  dest[2] = (char)(x >> 8);
  dest[3] = (char)x;
}

static inline void putInt64BE(char* dest, int64_t x) {
  dest[0] = (char)(x >> 56);
  dest[1] = (char)(x >> 48);
  dest[2] = (char)(x >> 40);
  dest[3] = (char)(x >> 32);
  dest[4] = (char)(x >> 24);
  dest[5] = (char)(x >> 16);
  dest[6] = (char)(x >> 8);
  dest[7] = (char)x;
}

static inline unsigned readUint16BE(std::ifstream& in) {
  int c1 = (uint8_t)in.get() << 8;
  return c1 | (uint8_t)in.get();
}

template <class T>
string printHex(T const& t) {
  string res;
  res.resize(t.size() * 3);
  for (size_t i = 0, n = t.size(); i < n; i++) {
    char c = t[i];
    // res[i] = c < 32 ? '.' : c;
    res[i * 3] = "0123456789ABCDEF"[(c >> 4) & 0x0F];
    res[i * 3 + 1] = "0123456789ABCDEF"[c & 0x0F];
    res[i * 3 + 2] = ' ';
  }
  if (!res.empty())
    res.resize(res.size() - 1);
  return res;
}

struct ScopedTimer {
  using Clock = std::chrono::steady_clock;
  const Clock::time_point start_time = Clock::now();
  ~ScopedTimer() {
    auto end_time = Clock::now();
    std::cerr << "Duration: " << (end_time - start_time) / 1.0s << "s\n";
  }
};

} // namespace util
