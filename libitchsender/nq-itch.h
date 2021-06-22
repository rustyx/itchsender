#pragma once
#include "util.h"
#include <string>

namespace NQ {

using nq_bookid_t = int32_t; // int16 actually
using nq_oid_t = int64_t;

struct nq_book_t {
  std::string name;
  bool include;
};

struct nq_order_t {
  int qty;
  int price;
};

// See ftp://emi.nasdaq.com/ITCH

int parse_NQ_ITCH50(std::string nq);

} // namespace NQ
