#pragma once
#include "util.h"
#include <set>
#include <string>

namespace SGX {

int parseSGXpcap(std::string in_file);

int parseSGXtcpdump(std::string in_file);

int filterSGXpcap(std::string in_file, std::string out_file, std::set<std::string> const& products);

} // namespace SGX
