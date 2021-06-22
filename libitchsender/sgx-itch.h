#pragma once
#include "net.h"
// net.h should be first
#include "util.h"
#include <boost/iostreams/device/mapped_file.hpp>
#include <chrono>
#include <map>
#include <memory>
#include <thread>
#include <unordered_map>

namespace SGX {

using namespace std::chrono;
using boost::iostreams::mapped_file;

using bookid_t = uint32_t;
using orderid_t = uint64_t; // unique only within book+side
using messageid_t = uint64_t;
using qty_t = int64_t;
using price_t = int32_t;

struct MoldUDP64Ptr {
  MoldUDP64Ptr() {}
  MoldUDP64Ptr(const char* ptr) : ptr(ptr) {}
  std::string sessionName() const { return string(ptr, 10); }
  int64_t seqBr() const { return readInt64BE(ptr + 10); }
  int msgCount() const {
    unsigned c = readUint16BE(ptr + 18);
    return c < 65535 ? c : 0;
  }
  const char* packet_data() const { return ptr; }
  const char* data() const { return ptr + 20; }
  const char* ptr = nullptr;
};

struct MessagePtr {
  MessagePtr() {}
  MessagePtr(const char* ptr) : ptr(ptr) {}
  unsigned len() const { return readUint16BE(ptr); }
  const char* data() const { return ptr + 2; }
  operator bool() const { return !!ptr; }
  const char* ptr = nullptr;
};

class Order {
public:
  qty_t qty;
  price_t price;
};

class Book {
public:
  std::map<orderid_t, Order>& Side(char side) { return side == 'B' ? bid : offer; }
  std::string symbol;
  MessagePtr definitionMsg, tickSizeMsg, statusMsg;
  std::map<orderid_t, Order> bid, offer;
};

class MessageRepo {
public:
  void openPcap(std::string const& filename);

public:
  std::string sessionName;
  messageid_t nextSeqNr = 0;
  std::vector<MessagePtr> messageIndex;
  std::shared_ptr<mapped_file> pcapFile;
};

class ServerState {
public:
  MessageRepo messageRepo;
  std::unordered_map<bookid_t, Book> books;
  std::vector<MessagePtr> combiBookDef;
};

class ServerContext : public ServerState {
public:
  ServerContext(net::io_context& io_context) : io_context(io_context) {}

public:
  net::io_context& io_context;
  // std::string interfaceIP = "0.0.0.0";
  std::string interfaceIP = "127.0.0.1";
  std::string destIP = "127.0.0.1";
  unsigned itchPort = 21002;
  unsigned rewinderPort = 24002;
  unsigned glimpsePort = 21802;
  int delayUs = 100; //'000;
  int itchHeartbeatMs = 100;
  int glimpseHeartbeatMs = 1000;
  std::vector<std::string> inputs;
  std::mutex mtx; // protects the server state
};

class ITCHServer : public UDPServer<ITCHServer> {
public:
  ITCHServer(ServerContext& ctx)
      : ctx(ctx), UDPServer(ctx.io_context, ip::make_address(ctx.interfaceIP), ctx.rewinderPort, ip::make_address(ctx.destIP),
                            ctx.itchPort, milliseconds(ctx.itchHeartbeatMs)) {}

  void heartbeat() {
    std::lock_guard lock(ctx.mtx);
    std::vector<char> msg(20);
    memcpy(&msg[0], ctx.messageRepo.sessionName.data(), 10);
    putInt64BE(&msg[10], ctx.messageRepo.nextSeqNr);
    send(std::move(msg));
  }

  bool receive(std::vector<char> msg, size_t packetLen, ip::udp::endpoint src) {
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

protected:
  ServerContext& ctx;
};

class GlimpseSession : public TCPSession<GlimpseSession> {
public:
  GlimpseSession(ip::tcp::socket socket, ServerContext& ctx)
      : TCPSession(std::move(socket), ctx.io_context, milliseconds(ctx.glimpseHeartbeatMs)), ctx(ctx) {}

  void heartbeat() { send(std::vector<char>{0, 1, 'H'}); }

  bool receive(std::vector<char> const& msg) {
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

  bool processLogin(std::vector<char> const& msg) {
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

  bool sendSnapshot(ServerState const& snapshot) {
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

  bool sendOrder(bookid_t bookid, orderid_t orderid, Order order, int rank, char side) {
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

  bool sendMsg(MessagePtr msg) {
    std::vector<char> reply(msg.len() + 3);
    putInt16BE(&reply[0], msg.len() + 1);
    reply[2] = 'S';
    memcpy(&reply[3], msg.data(), msg.len());
    return send(std::move(reply));
  }

  void processUnseqDataPacket() {
    // todo
  }

private:
  ServerContext& ctx;
};

class GlimpseServer : public TCPServer<GlimpseServer> {
public:
  GlimpseServer(ServerContext& ctx)
      : ctx(ctx),
        TCPServer(ctx.io_context, ip::make_address(ctx.interfaceIP), ctx.glimpsePort, milliseconds(ctx.glimpseHeartbeatMs)) {}
  void run();
  ServerContext& context() { return ctx; }
  void makeSession(ip::tcp::socket socket) { std::make_shared<GlimpseSession>(std::move(socket), ctx)->start(); }

protected:
  ServerContext& ctx;
};

class ITCHService : public ServerContext {
public:
  ITCHService(net::io_context& io_context) : ServerContext(io_context) {}
  void runFromPcap(std::string const& filename);
  void processPacket(MoldUDP64Ptr packet, unsigned len);
  void init() {
    itch = std::make_unique<ITCHServer>(*this);
    glimpse = std::make_unique<GlimpseServer>(*this);
  }
  void start() {
    itch->start();
    glimpse->start();
  }

protected:
  std::unique_ptr<ITCHServer> itch;
  std::unique_ptr<GlimpseServer> glimpse;
};

} // namespace SGX
