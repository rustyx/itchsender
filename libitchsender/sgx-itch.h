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
  char sessionState = 0;
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

  void heartbeat();
  bool receive(std::vector<char> msg, size_t packetLen, ip::udp::endpoint src);

protected:
  ServerContext& ctx;
};

class GlimpseSession : public TCPSession<GlimpseSession> {
public:
  GlimpseSession(ip::tcp::socket socket, ServerContext& ctx)
      : TCPSession(std::move(socket), ctx.io_context, milliseconds(ctx.glimpseHeartbeatMs)), ctx(ctx) {}

  void heartbeat();
  bool receive(std::vector<char> const& msg);
  bool processLogin(std::vector<char> const& msg);
  bool sendSnapshot(ServerState const& snapshot);
  bool sendOrder(bookid_t bookid, orderid_t orderid, Order order, int rank, char side);
  bool sendMsg(MessagePtr msg);
  void processUnseqDataPacket();

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
