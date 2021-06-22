#include "sgx-itch.h"
// sgx-itch.h must be first
#include "pcap.h"
#include "sgx-pcap-util.h"
#include "util.h"
#include <algorithm>
#include <boost/iostreams/device/mapped_file.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <sparsehash/dense_hash_map>
#include <string.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace SGX {

using namespace SGX;
using namespace util;
using namespace std;
using namespace std::chrono;
using boost::iostreams::mapped_file;
using google::dense_hash_map;

struct sgx_book_t {
  string name;
  bool include;
};

struct sgx_order_t {
  int64_t qty;
  int price;
};

static constexpr orderid_t sgx_make_oid(orderid_t oid, bookid_t bookId, char side) {
  return oid ^ ((orderid_t)bookId << (30 + (side == 'B')));
}

int parseSGXpcap(string in_file) {
  mapped_file in(in_file, mapped_file::mapmode::readonly);
  if (!in.is_open())
    throw std::system_error(errno, std::generic_category(), in_file);
  char name[33]{};
  dense_hash_map<bookid_t, sgx_book_t> books(100000);
  books.set_empty_key(0);
  books.set_deleted_key(-1);
  dense_hash_map<orderid_t, sgx_order_t> orders(100000);
  orders.set_empty_key(0);
  orders.set_deleted_key(-1);
  // map<int, int> packetSizes;
  int maxPacketSize = 0, maxMsgCount = 0;
  // map<bookid_t, sgx_book_t> books;
  // map<orderid_t, sgx_order_t> orders;
  const char *p = in.const_data(), *end = p + in.size();
  const pcap_hdr_t* pcaphdr = (const pcap_hdr_t*)p;
  if (pcaphdr->magic_number != 0xa1b2c3d4 || pcaphdr->network != 1) {
    std::stringstream tmp;
    tmp << "Unsupported pcap format 0x" << std::hex << pcaphdr->magic_number << ", link type " << pcaphdr->network;
    throw runtime_error(tmp.str());
  }
  p += sizeof(pcap_hdr_t);
  char moldSess[11]{};
  int timeSeconds = 0;
  std::stringstream tmp;
  int64_t tmax = 0, countmax = 0, count = 0;
  while (p < end) {
    const pcaprec_hdr_t* pcaprec = (const pcaprec_hdr_t*)p;
    p += sizeof(pcaprec_hdr_t);
    const char* buf = p;
    p += pcaprec->incl_len;
    unsigned offset = 0x2e; // TODO: calculate offset properly
    if (pcaprec->incl_len < offset + 2)
      continue; // should never happen
    memcpy(moldSess, &buf[offset], 10);
    int64_t seqBr = readInt64BE(&buf[offset + 10]);
    int msgCount = readUint16BE(&buf[offset + 18]);
    if (msgCount == 0 || msgCount == 65535) {
      cout << "msgCount " << msgCount << '\n';
      continue;
    }
    // packetSizes[pcaprec->incl_len]++;
    maxPacketSize = max(maxPacketSize, (int)pcaprec->incl_len);
    maxMsgCount = max(maxMsgCount, msgCount);
    for (int n = 0, base = offset + 20; n < msgCount; n++) {
      int len = readUint16BE(&buf[base + 0]);
      base += 2;
      int timeNanos = readInt32BE(&buf[base + 1]);
      // cout << len << '\t' << buf[base+0] << endl;
      tmp.clear();
      switch (buf[base + 0]) {
      case 'T': {
        timeSeconds = readInt32BE(&buf[base + 1]);
        if (count > countmax) {
          countmax = count;
          tmax = timeSeconds;
        }
        count = 0;
        break;
      }
      case 'R': {
        bookid_t bookId = readInt32BE(&buf[base + 5]);
        memcpy(name, &buf[base + 9], 32);
        int cat = buf[base + 85];
        int priceDecimals = readUint16BE(&buf[base + 89]);
        int valueDecimals = readUint16BE(&buf[base + 91]);
        int oddLotSize = readInt32BE(&buf[base + 93]);
        int roundLotSize = readInt32BE(&buf[base + 97]);
        int blockLotSize = readInt32BE(&buf[base + 101]);
        int64_t nominalValue = readInt64BE(&buf[base + 105]);
        int expiryDate = readInt32BE(&buf[base + 122]);
        for (int i = 31; i > 0 && name[i] == ' '; i--)
          name[i] = 0;
        bool include = true;
        books[bookId] = {name, include};
        if (include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << name << '\t' << bookId
               << '\t' << cat << '\t' << priceDecimals << '\t' << valueDecimals << '\t' << oddLotSize << '\t' << roundLotSize
               << '\t' << blockLotSize << '\t' << nominalValue << '\t' << expiryDate << '\n';
        }
        break;
      }
      case 'L': {
        bookid_t bookId = readInt32BE(&buf[base + 5]);
        int64_t tickSize = readInt64BE(&buf[base + 9]);
        int priceFrom = readInt32BE(&buf[base + 17]);
        int priceTo = readInt32BE(&buf[base + 21]);
        auto& book = books[bookId];
        if (book.include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
               << book.name << '\t' << tickSize << '\t' << priceFrom << '\t' << priceTo << '\n';
        }
        break;
      }
      case 'M': {
        break;
      }
      case 'O': {
        bookid_t bookId = readInt32BE(&buf[base + 5]);
        memcpy(name, &buf[base + 9], 20);
        name[20] = 0;
        for (int i = 19; i > 0 && name[i] == ' '; i--)
          name[i] = 0;
        auto& book = books[bookId];
        if (book.include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
               << book.name << '\t' << name << '\n';
        }
        break;
      }
      case 'S': {
        char code = buf[base + 5];
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << code << '\n';
        break;
      }
      case 'A': {
        count++;
        orderid_t oid = readInt64BE(&buf[base + 5]);
        bookid_t bookId = readInt32BE(&buf[base + 13]);
        char side = buf[base + 17];
        auto xoid = sgx_make_oid(oid, bookId, side);
        int64_t qty = readInt64BE(&buf[base + 22]);
        int price = readInt32BE(&buf[base + 30]);
        orders[xoid] = {qty, price};
        auto& book = books[bookId];
        if (book.include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
               << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\t' << price << '\n';
        }
        break;
      }
      case 'C':
      case 'E': {
        count++;
        orderid_t oid = readInt64BE(&buf[base + 5]);
        bookid_t bookId = readInt32BE(&buf[base + 13]);
        char side = buf[base + 17];
        auto xoid = sgx_make_oid(oid, bookId, side);
        int64_t qty = readInt64BE(&buf[base + 18]);
        auto& book = books[bookId];
        auto& ord = orders[xoid];
        ord.qty -= qty;
        if (book.include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
               << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\n';
        }
        if (ord.qty <= 0) {
          orders.erase(xoid);
        }
        break;
      }
      case 'U': {
        count++;
        orderid_t oid = readInt64BE(&buf[base + 5]);
        bookid_t bookId = readInt32BE(&buf[base + 13]);
        char side = buf[base + 17];
        orderid_t oid2 = readInt32BE(&buf[base + 18]);
        int64_t qty = readInt64BE(&buf[base + 22]);
        int price = readInt32BE(&buf[base + 30]);
        auto xoid = sgx_make_oid(oid, bookId, side);
        auto xoid2 = sgx_make_oid(oid2, bookId, side);
        auto& book = books[bookId];
        auto& ord = orders[xoid];
        if (book.include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
               << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\n';
        }
        orders.erase(xoid);
        orders[xoid2] = {qty, price};
        break;
      }
      case 'D': {
        count++;
        orderid_t oid = readInt64BE(&buf[base + 5]);
        bookid_t bookId = readInt32BE(&buf[base + 13]);
        char side = buf[base + 17];
        auto xoid = sgx_make_oid(oid, bookId, side);
        auto& book = books[bookId];
        if (book.include) {
          cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
               << book.name << '\t' << oid << '\n';
        }
        orders.erase(xoid);
        break;
      }
      case 'P': {
        break;
      }
      case 'Z': {
        break;
      }
      default: {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\n';
      }
      }
      base += len;
      seqBr++;
    }
  }
  cerr << "max rate: " << countmax << " at " << tmax << ", max packet size: " << maxPacketSize
       << ", max msg count: " << maxMsgCount << "\n";
  // cerr << "Packet sizes:\n";
  // for (auto [sz, count] : packetSizes) {
  //   cerr << sz << "\t" << count << "\n";
  // }
  return 0;
}

int parseSGXtcpdump(string in_file) {
  vector<char> in_buf(256 * 1024);
  ifstream in(in_file, ios::binary);
  if (!in)
    throw system_error(errno, generic_category(), in_file);
  in.rdbuf()->pubsetbuf(in_buf.data(), in_buf.size());
  vector<char> buf(4096);
  char name[33]{};
  dense_hash_map<bookid_t, sgx_book_t> books(100000);
  books.set_empty_key(0);
  books.set_deleted_key(-1);
  dense_hash_map<orderid_t, sgx_order_t> orders(100000);
  orders.set_empty_key(0);
  orders.set_deleted_key(-1);
  // map<int, int> packetSizes;
  int maxPacketSize = 0, maxMsgCount = 0;
  // map<bookid_t, sgx_book_t> books;
  // map<orderid_t, sgx_order_t> orders;
  char moldSess[11]{};
  int timeSeconds = 0;
  std::stringstream tmp;
  int64_t seqBr = 0;
  char msglen[2] = {};
  while (in.read(msglen, 2)) {
    unsigned len = readUint16BE(msglen);
    if (len == 0)
      continue;

    buf.resize(len + 1);
    in.read(buf.data(), len);
    if (buf[0] == 'A') {
      buf[31] = 0;
      seqBr = strtoull(&buf[11], nullptr, 10);
    }
    if (buf[0] != 'S')
      continue;
    int base = 1;
    len--;
    int timeNanos = readInt32BE(&buf[base + 1]);
    // cout << len << '\t' << buf[base+0] << endl;
    tmp.clear();
    switch (buf[base + 0]) {
    case 'T': {
      timeSeconds = readInt32BE(&buf[base + 1]);
      break;
    }
    case 'R': {
      bookid_t bookId = readInt32BE(&buf[base + 5]);
      memcpy(name, &buf[base + 9], 32);
      int cat = buf[base + 85];
      int priceDecimals = readUint16BE(&buf[base + 89]);
      int valueDecimals = readUint16BE(&buf[base + 91]);
      int oddLotSize = readInt32BE(&buf[base + 93]);
      int roundLotSize = readInt32BE(&buf[base + 97]);
      int blockLotSize = readInt32BE(&buf[base + 101]);
      int64_t nominalValue = readInt64BE(&buf[base + 105]);
      int expiryDate = readInt32BE(&buf[base + 122]);
      for (int i = 31; i > 0 && name[i] == ' '; i--)
        name[i] = 0;
      bool include = true;
      books[bookId] = {name, include};
      if (include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << name << '\t' << bookId
             << '\t' << cat << '\t' << priceDecimals << '\t' << valueDecimals << '\t' << oddLotSize << '\t' << roundLotSize
             << '\t' << blockLotSize << '\t' << nominalValue << '\t' << expiryDate << '\n';
      }
      break;
    }
    case 'L': {
      bookid_t bookId = readInt32BE(&buf[base + 5]);
      int64_t tickSize = readInt64BE(&buf[base + 9]);
      int priceFrom = readInt32BE(&buf[base + 17]);
      int priceTo = readInt32BE(&buf[base + 21]);
      auto& book = books[bookId];
      if (book.include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << book.name << '\t' << tickSize << '\t' << priceFrom << '\t' << priceTo << '\n';
      }
      break;
    }
    case 'M': {
      break;
    }
    case 'O': {
      bookid_t bookId = readInt32BE(&buf[base + 5]);
      memcpy(name, &buf[base + 9], 20);
      name[20] = 0;
      for (int i = 19; i > 0 && name[i] == ' '; i--)
        name[i] = 0;
      auto& book = books[bookId];
      if (book.include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << book.name << '\t' << name << '\n';
      }
      break;
    }
    case 'S': {
      char code = buf[base + 5];
      cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t' << code
           << '\n';
      break;
    }
    case 'A': {
      orderid_t oid = readInt64BE(&buf[base + 5]);
      bookid_t bookId = readInt32BE(&buf[base + 13]);
      char side = buf[base + 17];
      auto xoid = sgx_make_oid(oid, bookId, side);
      int64_t qty = readInt64BE(&buf[base + 22]);
      int price = readInt32BE(&buf[base + 30]);
      orders[xoid] = {qty, price};
      auto& book = books[bookId];
      if (book.include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\t' << price << '\n';
      }
      break;
    }
    case 'C':
    case 'E': {
      orderid_t oid = readInt64BE(&buf[base + 5]);
      bookid_t bookId = readInt32BE(&buf[base + 13]);
      char side = buf[base + 17];
      auto xoid = sgx_make_oid(oid, bookId, side);
      int64_t qty = readInt64BE(&buf[base + 18]);
      auto& book = books[bookId];
      auto& ord = orders[xoid];
      ord.qty -= qty;
      if (book.include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\n';
      }
      if (ord.qty <= 0) {
        orders.erase(xoid);
      }
      break;
    }
    case 'U': {
      orderid_t oid = readInt64BE(&buf[base + 5]);
      bookid_t bookId = readInt32BE(&buf[base + 13]);
      char side = buf[base + 17];
      orderid_t oid2 = readInt32BE(&buf[base + 18]);
      int64_t qty = readInt64BE(&buf[base + 22]);
      int price = readInt32BE(&buf[base + 30]);
      auto xoid = sgx_make_oid(oid, bookId, side);
      auto xoid2 = sgx_make_oid(oid2, bookId, side);
      auto& book = books[bookId];
      auto& ord = orders[xoid];
      if (book.include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << book.name << '\t' << oid << '\t' << side << '\t' << qty << '\n';
      }
      orders.erase(xoid);
      orders[xoid2] = {qty, price};
      break;
    }
    case 'D': {
      orderid_t oid = readInt64BE(&buf[base + 5]);
      bookid_t bookId = readInt32BE(&buf[base + 13]);
      char side = buf[base + 17];
      auto xoid = sgx_make_oid(oid, bookId, side);
      auto& book = books[bookId];
      if (book.include) {
        cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\t'
             << book.name << '\t' << oid << '\n';
      }
      orders.erase(xoid);
      break;
    }
    case 'P':
    case 'Z':
      break;
    default: {
      cout << timeSeconds << '.' << setw(9) << setfill('0') << timeNanos << '\t' << seqBr << '\t' << buf[base + 0] << '\n';
    }
    }
    base += len;
    seqBr++;
  }
  return 0;
}

int filterSGXpcap(string in_file, string out_file, set<string> const& products) {
  vector<char> in_buf(256 * 1024), out_buf(256 * 1024);
  ifstream in(in_file, ios::binary);
  if (!in)
    throw system_error(errno, generic_category(), in_file);
  ofstream out(out_file, ios::binary | ios::trunc);
  if (!out)
    throw system_error(errno, generic_category(), out_file);
  in.rdbuf()->pubsetbuf(in_buf.data(), in_buf.size());
  out.rdbuf()->pubsetbuf(out_buf.data(), out_buf.size());
  constexpr int udp_hdr_len = 0x2e, mold_hdr_len = 20;
  vector<char> buf, timePacket(udp_hdr_len + mold_hdr_len + 2 + 5);
  char name[33]{};
  map<bookid_t, sgx_book_t> books;
  pcap_hdr_t pcaphdr{};
  in.read((char*)&pcaphdr, sizeof(pcaphdr));
  if (pcaphdr.magic_number != 0xa1b2c3d4 || pcaphdr.network != 1) {
    std::stringstream tmp;
    tmp << "Unsupported pcap format 0x" << std::hex << pcaphdr.magic_number << ", link type " << pcaphdr.network;
    throw runtime_error(tmp.str());
  }
  pcaprec_hdr_t pcaprec{}, timepcaprec{};
  char moldSess[11]{};
  int timeSeconds = 0, lastTime = 0;
  std::stringstream tmp;
  int64_t seqNr = 1;
  out.write((char*)&pcaphdr, sizeof(pcaphdr));
  while (in.read((char*)&pcaprec, sizeof(pcaprec))) {
    auto packetLen = pcaprec.incl_len;
    if (packetLen == 0)
      continue;
    buf.resize(packetLen);
    in.read(buf.data(), packetLen);
    unsigned offset = udp_hdr_len;
    if (packetLen < udp_hdr_len + 2)
      continue;
    memcpy(moldSess, &buf[offset], 10);
    // int64_t seqBr = readInt64BE(&buf[offset + 10]);
    int msgCount = readUint16BE(&buf[offset + 18]);
    bool includeIt = false, hasTime = false;
    for (int n = 0, base = offset + mold_hdr_len; n < msgCount; n++) {
      int len = readUint16BE(&buf[base + 0]);
      base += 2;
      int timeNanos = readInt32BE(&buf[base + 1]);
      // cout << len << '\t' << buf[base+0] << endl;
      tmp.clear();
      switch (buf[base + 0]) {
      case 'T': {
        timeSeconds = readInt32BE(&buf[base + 1]);
        hasTime = true;
        break;
      }
      case 'R': {
        bookid_t bookId = readInt32BE(&buf[base + 5]);
        memcpy(name, &buf[base + 9], 32);
        int cat = buf[base + 85];
        int priceDecimals = readUint16BE(&buf[base + 89]);
        for (int i = 31; i > 0 && name[i] == ' '; i--)
          name[i] = 0;
        bool include = products.count(name);
        books[bookId] = {name, include};
        includeIt |= include;
        break;
      }
      case 'L':
      case 'O': {
        bookid_t bookId = readInt32BE(&buf[base + 5]);
        includeIt |= books[bookId].include;
        break;
      }
      case 'S': {
        includeIt = hasTime = true;
        char code = buf[base + 5];
        if (code == 'O')
          seqNr = 1;
        break;
      }
      case 'A':
      case 'C':
      case 'D':
      case 'E':
      case 'U': {
        bookid_t bookId = readInt32BE(&buf[base + 13]);
        includeIt |= books[bookId].include;
        break;
      }
      }
      base += len;
    }
    if (!includeIt)
      continue;
    if (!hasTime && lastTime != timeSeconds) {
      unsigned len = (unsigned)timePacket.size();
      memcpy(timePacket.data(), buf.data(), udp_hdr_len);
      putInt16BE(&timePacket[0x14], len - 34); // IP len
      putInt16BE(&timePacket[0x2a], len - 54); // UDP len
      memcpy(timePacket.data() + udp_hdr_len, moldSess, 10);
      putInt64BE(&timePacket[udp_hdr_len + 10], seqNr++);
      putInt16BE(&timePacket[udp_hdr_len + 18], 1);
      putInt16BE(&timePacket[udp_hdr_len + mold_hdr_len], 5);
      timePacket[udp_hdr_len + mold_hdr_len + 2] = 'T';
      putInt32BE(&timePacket[udp_hdr_len + mold_hdr_len + 3], timeSeconds);
      timepcaprec = pcaprec;
      timepcaprec.incl_len = timepcaprec.orig_len = len;
      out.write((char*)&timepcaprec, sizeof(timepcaprec));
      out.write(timePacket.data(), timePacket.size());
    }
    lastTime = timeSeconds;
    putInt64BE(&buf[udp_hdr_len + 10], seqNr);
    seqNr += msgCount;
    out.write((char*)&pcaprec, sizeof(pcaprec));
    out.write(buf.data(), packetLen);
  }
  return 0;
}

} // namespace SGX
