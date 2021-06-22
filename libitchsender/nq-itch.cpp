#include "nq-itch.h"
#include "util.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <string.h>
#include <vector>

namespace NQ {

using namespace std;
using namespace util;

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

/* some basic NASDAQ ITCH50 format parsing */

int parse_NQ_ITCH50(string nq) {
  vector<char> in_buf(65536);
  ifstream in(nq, ios::binary);
  if (!in)
    throw system_error(errno, generic_category(), nq);
  in.rdbuf()->pubsetbuf(in_buf.data(), in_buf.size());
  vector<char> buf;
  char name[12]{};
  map<nq_bookid_t, nq_book_t> books;
  map<nq_oid_t, nq_order_t> orders;
  while (in) {
    int len = readUint16BE(in);
    if (len <= 0)
      break;
    buf.resize(len);
    in.read(buf.data(), len);
    int64_t tstamp = readInt48BE(&buf[5]);
    // cout << len << '\t' << buf[0] << endl;
    switch (buf[0]) {
    case 'R': {
      nq_bookid_t bookId = readUint16BE(&buf[1]);
      memcpy(name, &buf[11], 8);
      char cat = buf[19];
      books[bookId] = {name, !strcmp(name, "MSFT    ")};
      // cout << name << '\t' << bookId << '\t' << cat << '\n';
      break;
    }
    case 'A':
    case 'F': {
      nq_bookid_t bookId = readUint16BE(&buf[1]);
      nq_oid_t oid = readInt64BE(&buf[11]);
      char side = buf[19];
      int qty = readInt32BE(&buf[20]);
      int price = readInt32BE(&buf[32]);
      orders[oid] = {qty, price};
      auto& book = books[bookId];
      if (book.include)
        cout << tstamp / 1'000'000'000ll << '.' << setw(9) << setfill('0') << tstamp % 1'000'000'000 << '\t' << buf[0] << '\t'
             << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\t' << price << '\n';
      break;
    }
    case 'C':
    case 'E':
    case 'X': {
      nq_bookid_t bookId = readUint16BE(&buf[1]);
      nq_oid_t oid = readInt64BE(&buf[11]);
      int qty = readInt32BE(&buf[19]);
      auto& ord = orders[oid];
      int resqty = ord.qty -= qty;
      auto& book = books[bookId];
      if (book.include)
        cout << tstamp / 1'000'000'000ll << '.' << setw(9) << setfill('0') << tstamp % 1'000'000'000 << '\t' << buf[0] << '\t'
             << book.name << '\t' << oid << '\t' << qty << '\t' << resqty << '\n';
      if (resqty <= 0) {
        orders.erase(oid);
      }
      break;
    }
    case 'U': {
      nq_bookid_t bookId = readUint16BE(&buf[1]);
      nq_oid_t oid = readInt64BE(&buf[11]);
      nq_oid_t oid2 = readInt64BE(&buf[19]);
      int qty = readInt32BE(&buf[27]);
      int price = readInt32BE(&buf[31]);
      auto& ord = orders[oid];
      auto& book = books[bookId];
      if (book.include)
        cout << tstamp / 1'000'000'000ll << '.' << setw(9) << setfill('0') << tstamp % 1'000'000'000 << '\t' << buf[0] << '\t'
             << book.name << '\t' << oid << '\t' << oid2 << '\t' << qty << '\t' << price << '\n';
      orders.erase(oid);
      orders[oid2] = {qty, price};
      break;
    }
    case 'D': {
      nq_bookid_t bookId = readUint16BE(&buf[1]);
      nq_oid_t oid = readInt64BE(&buf[11]);
      auto& book = books[bookId];
      if (book.include)
        cout << tstamp / 1'000'000'000ll << '.' << setw(9) << setfill('0') << tstamp % 1'000'000'000 << '\t' << buf[0] << '\t'
             << book.name << '\t' << oid << '\n';
      orders.erase(oid);
      break;
    }
    }
  }

  return 0;
}

} // namespace NQ
