#pragma once

#ifdef _WIN32
#include <timeapi.h>
struct OSSpecific {
  OSSpecific() noexcept { timeBeginPeriod(1); }
  ~OSSpecific() { timeEndPeriod(1); }
};

#else
struct OSSpecific {};

#endif
