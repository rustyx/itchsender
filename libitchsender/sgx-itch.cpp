#include "sgx-itch.h"
#include "pcap.h"
#include <string.h>

namespace SGX {

using namespace SGX;
using namespace std::literals;
namespace this_thread = std::this_thread;
using high_res_clock_t = std::chrono::system_clock;
using std::cout;
using std::exception;
using std::hex;
using std::make_shared;
using std::max;
using std::runtime_error;
using std::string;
using std::stringstream;
using std::to_string;

void MessageRepo::openPcap(string const& filename) {
  pcapFile = make_shared<mapped_file>(filename, mapped_file::mapmode::readonly);
  if (!pcapFile->is_open())
    throw std::system_error(errno, std::generic_category(), filename);
  messageIndex.clear();
  sessionName = "";
  nextSeqNr = 0;
  messageIndex.reserve(pcapFile->size() / 100);
}

void ITCHService::runFromPcap(string const& filename) {
  cout << "Reading pcap " << filename << "\n";
  messageRepo.openPcap(filename);
  const char *p = messageRepo.pcapFile->const_data(), *end = p + messageRepo.pcapFile->size();
  const pcap_hdr_t* pcaphdr = (const pcap_hdr_t*)p;
  if (pcaphdr->magic_number != 0xa1b2c3d4 || pcaphdr->network != 1) {
    stringstream tmp;
    tmp << "Unsupported pcap format 0x" << hex << pcaphdr->magic_number << ", link type " << pcaphdr->network;
    throw runtime_error(tmp.str());
  }
  p += sizeof(pcap_hdr_t);
  cout << "Starting ITCH @ " << itchPort << ", Glimpse @ " << glimpsePort << ", rewinder @ " << rewinderPort << ", "
       << (1e6 / max(1, delayUs)) << " msg/s\n";
  init();
  start();
  auto now = high_res_clock_t::now();
  auto last = now;
  while (p < end) {
    const pcaprec_hdr_t* pcaprec = (const pcaprec_hdr_t*)p;
    p += sizeof(pcaprec_hdr_t);
    const char* buf = p;
    p += pcaprec->incl_len;
    unsigned offset = 0x2e; // TODO: calculate offset properly
    if (pcaprec->incl_len < offset + 2)
      continue; // should never happen
    if (p > end + 1) {
      cout << "warning: incomplete pcap file\n";
      break;
    }
    processPacket(buf + offset, pcaprec->incl_len - offset);
    this_thread::sleep_until(now += microseconds(delayUs));
    if (now - last >= 1s) {
      int64_t seqnr;
      string sess;
      {
        lock_guard lock(mtx);
        sess = messageRepo.sessionName;
        seqnr = messageRepo.nextSeqNr;
      }
      cout << sess << '@' << seqnr << '\n';
      last = now;
    }
  }
}

void ITCHService::processPacket(MoldUDP64Ptr packet, unsigned packetLen) {
  if (packetLen <= 2 || packet.msgCount() == 0 || packet.msgCount() == 65535)
    return;
  lock_guard lock(mtx);
  if (packet.sessionName() != messageRepo.sessionName) {
    messageRepo.messageIndex.clear();
    messageRepo.sessionName = packet.sessionName();
  }
  messageid_t seqNr = packet.seqBr(), nextSeqNr = seqNr + packet.msgCount();
  messageRepo.nextSeqNr = nextSeqNr;
  messageRepo.messageIndex.resize(nextSeqNr + 1);
  const char* data = packet.data();
  for (; seqNr < nextSeqNr; seqNr++) {
    MessagePtr msg{data};
    messageRepo.messageIndex[seqNr] = msg;
    data += 2;
    switch (data[0]) {
    case 'R': {
      bookid_t bookId = readInt32BE(&data[5]);
      Book book;
      book.symbol = string(data + 9, 32);
      book.definitionMsg = msg;
      while (book.symbol.size() > 0 && book.symbol.back() == ' ')
        book.symbol.resize(book.symbol.size() - 1);
      books[bookId] = book;
      break;
    }
    case 'L': {
      bookid_t bookId = readInt32BE(&data[5]);
      books[bookId].tickSizeMsg = msg;
      break;
    }
    case 'O': {
      bookid_t bookId = readInt32BE(&data[5]);
      books[bookId].statusMsg = msg;
      break;
    }
    case 'M': {
      combiBookDef.push_back(msg);
      break;
    }
    case 'A': {
      orderid_t oid = readInt64BE(&data[5]);
      bookid_t bookId = readInt32BE(&data[13]);
      char side = data[17];
      int64_t qty = readInt64BE(&data[22]);
      int price = readInt32BE(&data[30]);
      books[bookId].Side(side)[oid] = {qty, price};
      break;
    }
    case 'C':
    case 'E': {
      orderid_t oid = readInt64BE(&data[5]);
      bookid_t bookId = readInt32BE(&data[13]);
      char side = data[17];
      int64_t qty = readInt64BE(&data[18]);
      auto& bookSide = books[bookId].Side(side);
      Order& order = bookSide[oid];
      order.qty -= qty;
      if (order.qty <= 0) {
        bookSide.erase(oid);
      }
      break;
    }
    case 'U': {
      orderid_t oid = readInt64BE(&data[5]);
      bookid_t bookId = readInt32BE(&data[13]);
      char side = data[17];
      orderid_t oid2 = readInt32BE(&data[18]);
      int64_t qty = readInt64BE(&data[22]);
      int price = readInt32BE(&data[30]);
      auto& bookSide = books[bookId].Side(side);
      Order& order = bookSide[oid];
      bookSide.erase(oid);
      bookSide[oid2] = {qty, price};
      break;
    }
    case 'D': {
      orderid_t oid = readInt64BE(&data[5]);
      bookid_t bookId = readInt32BE(&data[13]);
      char side = data[17];
      auto& bookSide = books[bookId].Side(side);
      bookSide.erase(oid);
      break;
    }
    default:
      break;
    }
    data += msg.len();
  }
  itch->send(vector<char>(packet.packet_data(), data));
}

void ITCHServer::heartbeat() {
  std::lock_guard lock(ctx.mtx);
  std::vector<char> msg(20);
  memcpy(&msg[0], ctx.messageRepo.sessionName.data(), 10);
  putInt64BE(&msg[10], ctx.messageRepo.nextSeqNr);
  send(std::move(msg));
}

bool ITCHServer::receive(std::vector<char> msg, size_t packetLen, ip::udp::endpoint src) {
  if (packetLen < 20) {
    cout << "UDP: incomplete packet received, len=" << packetLen << "\n";
    return true;
  }
  MoldUDP64Ptr ptr(msg.data());
  std::vector<char> reply(1500);
  unsigned offset = 20, count = 0;
  messageid_t start = ptr.seqBr(), end = start + ptr.msgCount();
  {
    std::lock_guard lock(ctx.mtx);
    for (messageid_t seqnr = start; seqnr < end; seqnr++) {
      if (seqnr >= ctx.messageRepo.messageIndex.size())
        break;
      auto m = ctx.messageRepo.messageIndex[seqnr];
      if (!m) {
        cout << "rewinder: no message " << seqnr << " available.\n";
        break;
      }
      if (m.len() + 2 + offset > reply.size())
        break;
      putInt16BE(&reply[offset], m.len());
      offset += 2;
      memcpy(&reply[offset], m.data(), m.len());
      offset += m.len();
      count++;
    }
    memcpy(&reply[0], ctx.messageRepo.sessionName.data(), 10);
  }
  if (count == 0)
    return true;
  putInt64BE(&reply[10], start);
  putInt16BE(&reply[18], count);
  reply.resize(offset);
  send(std::move(reply));
  return true;
}

void GlimpseSession::heartbeat() { send(std::vector<char>{0, 1, 'H'}); }

bool GlimpseSession::receive(std::vector<char> const& msg) {
  switch (msg[2]) {
  case 'L':
    return processLogin(msg);
  case 'O':
    return false;
  case 'U':
    processUnseqDataPacket();
    break;
  }
  return true;
}

bool GlimpseSession::processLogin(std::vector<char> const& msg) {
  std::string tmp(&msg[29], 20);
  int64_t seqnr = std::stoll(tmp);
  if (seqnr > 1) {
    std::vector<char> reply(4);
    putInt16BE(&reply[0], 2);
    reply[2] = 'J';
    reply[3] = 'A';
    return !send(std::move(reply));
  }
  std::vector<char> reply(34);
  putInt16BE(&reply[0], 31);
  reply[2] = 'A';

  std::unique_lock lock(ctx.mtx);
  ServerState snapshot = ctx; // copy slice
  lock.unlock();

  memcpy(&reply[3], snapshot.messageRepo.sessionName.data(), 10);
  if (seqnr == 0) {
    snprintf(&reply[13], 21, "%020lld", (long long int)snapshot.messageRepo.nextSeqNr);
  } else {
    memcpy(&reply[13], "00000000000000000001", 20);
  }
  reply.resize(33); // trim the \0 from snprintf
  if (send(std::move(reply)))
    return false;
  if (seqnr == 1)
    return sendSnapshot(snapshot);
  return true;
}

bool GlimpseSession::sendSnapshot(ServerState const& snapshot) {
  for (auto& b : snapshot.books) {
    auto& book = b.second;
    if (book.definitionMsg && sendMsg(book.definitionMsg))
      return false;
  }
  for (auto& b : snapshot.books) {
    auto& book = b.second;
    if (book.tickSizeMsg && sendMsg(book.tickSizeMsg))
      return false;
  }
  for (auto& b : snapshot.books) {
    auto& book = b.second;
    if (book.statusMsg && sendMsg(book.statusMsg))
      return false;
  }
  for (auto& b : snapshot.combiBookDef) {
    if (sendMsg(b))
      return false;
  }
  for (auto& b : snapshot.books) {
    auto& book = b.second;
    int rank = 0;
    for (auto& o : book.bid) {
      if (sendOrder(b.first, o.first, o.second, ++rank, 'B'))
        return false;
    }
    rank = 0;
    for (auto& o : book.offer) {
      if (sendOrder(b.first, o.first, o.second, ++rank, 'S'))
        return false;
    }
  }
  std::vector<char> reply(35);
  putInt16BE(&reply[0], 22);
  reply[2] = 'S';
  reply[3] = 'G';
  snprintf(&reply[4], 21, "%020lld", (long long int)snapshot.messageRepo.nextSeqNr);
  reply.resize(24);
  return !send(std::move(reply));
}

bool GlimpseSession::sendOrder(bookid_t bookid, orderid_t orderid, Order order, int rank, char side) {
  std::vector<char> reply(40);
  putInt16BE(&reply[0], 38);
  reply[2] = 'S';
  reply[3] = 'A';
  putInt64BE(&reply[8], orderid);
  putInt32BE(&reply[16], bookid);
  reply[20] = side;
  putInt32BE(&reply[21], rank);
  putInt64BE(&reply[25], order.qty);
  putInt32BE(&reply[33], order.price);
  reply[39] = 2; // round lot
  return send(std::move(reply));
}

bool GlimpseSession::sendMsg(MessagePtr msg) {
  std::vector<char> reply(msg.len() + 3);
  putInt16BE(&reply[0], msg.len() + 1);
  reply[2] = 'S';
  memcpy(&reply[3], msg.data(), msg.len());
  return send(std::move(reply));
}

void GlimpseSession::processUnseqDataPacket() {
  // todo
}

} // namespace SGX
