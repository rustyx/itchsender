#pragma once
#include <boost/asio.hpp>
// asio.hpp should be first
#include "util.h"
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace SGX {

namespace net = boost::asio;
namespace ip = boost::asio::ip;
namespace sys = boost::system;
using net_timer_t = net::system_timer;
using std::cout;
using std::deque;
using std::lock_guard;
using std::mutex;
using std::shared_ptr;
using std::vector;
using namespace util;

template <class Sender>
class UDPServer {
public:
  UDPServer(net::io_context& io_context, ip::address srcIP, unsigned srcPort, ip::address destIP, unsigned destPort,
            net_timer_t::duration heartbeatDelay)
      : src(srcIP, srcPort), endpoint(destIP, destPort), socket(io_context, endpoint.protocol()), timer(io_context),
        heartbeatDelay(heartbeatDelay) {
    socket.set_option(ip::udp::socket::reuse_address(true));
    // socket.set_option(ip::multicast::enable_loopback(true));
    // socket.set_option(ip::multicast::outbound_interface(src.address().to_v4()));
    // socket.set_option(ip::multicast::join_group(endpoint.address().to_v4()));
#ifdef _WIN32
    struct winsock_udp_connreset {
      unsigned long value = 0;
      int name() { return 0x9800000C; /* SIO_UDP_CONNRESET */ }
      unsigned long* data() { return &value; }
    };
    winsock_udp_connreset lo_connreset{0};
    sys::error_code ec;
    socket.io_control(lo_connreset, ec);
    if (ec)
      cout << "SIO_UDP_CONNRESET: " << ec.value() << ": " << ec.message() << "\n";
#endif
    socket.bind(src);
  }

  void start() {
    arm_timer();
    do_receive();
  }

  bool receive(vector<char> const& msg, size_t len, ip::udp::endpoint const& src) {
    cout << "UDP recv: " << printHex(vector<char>(msg.data(), msg.data() + len)) << "\n";
    return static_cast<Sender*>(this)->receive(msg, len, src);
  }

  void send(vector<char> const& message) {
    arm_timer();
    sys::error_code ec;
    socket.send_to(net::buffer(message), endpoint, 0, ec);
    if (ec) {
      std::ostringstream tmp;
      tmp << "UDP send: " << ec.value() << ": " << ec.message();
      {
        lock_guard lock(mtx);
        lastError = tmp.str();
      }
      close();
    }
  }

  void close() {
    timer.cancel();
    socket.close();
  }

protected:
  void heartbeat() { static_cast<Sender*>(this)->heartbeat(); }

private:
  void do_receive() {
    socket.async_receive_from(net::buffer(readbuf.data(), readbuf.size()), rewindSrc, [this](sys::error_code ec, size_t len) {
      if (ec) {
        cout << "UDP read: " << ec.value() << ": " << ec.message() << "\n";
        // close();
        // return;
      } else if (!receive(readbuf, len, rewindSrc)) {
        // close();
        // return;
      }
      do_receive();
    });
  }

  void do_send_unlocked() {
    if (!(sending = !queue.empty())) {
      return;
    }
    // cout << "UDP send:";
    // for (auto& msg : queue[activeQueue])
    //   cout << " " << printHex(msg) << "\n";
    arm_timer();
    socket.async_send_to(net::buffer(queue.front()), endpoint, 0, [this](sys::error_code ec, size_t /*length*/) {
      if (ec) {
        std::ostringstream tmp;
        tmp << "UDP send: " << ec.value() << ": " << ec.message();
        lock_guard lock(mtx);
        lastError = tmp.str();
        sending = false;
        close();
        return;
      }
      lock_guard lock(mtx);
      queue.pop_front();
      do_send_unlocked();
    });
  }

  void arm_timer() {
    if (heartbeatDelay == 0ms)
      return;
    timer.expires_from_now(heartbeatDelay);
    timer.async_wait([this](sys::error_code ec) {
      if (ec)
        return;
      arm_timer();
      heartbeat();
    });
  }

protected:
  ip::udp::endpoint endpoint, src, rewindSrc;
  ip::udp::socket socket;
  net_timer_t timer;
  net_timer_t::duration heartbeatDelay;
  vector<char> readbuf = vector<char>(65536);
  std::mutex mtx;
  bool sending = false;
  deque<vector<char>> queue;
  std::string lastError;
};

template <class Session>
class TCPSession : public std::enable_shared_from_this<TCPSession<Session>> {
public:
  TCPSession(ip::tcp::socket socket, net::io_context& io_context, net_timer_t::duration heartbeatDelay)
      : socket(std::move(socket)), timer(io_context), heartbeatDelay(heartbeatDelay) {}
  void start() { do_read_len(); }

protected:
  void heartbeat() {
    // cout << "TCP heartbeat\n";
    static_cast<Session*>(this)->heartbeat();
  }

  bool receive(vector<char> const& msg) {
    cout << "TCP recv: " << printHex(msg) << "\n";
    return static_cast<Session*>(this)->receive(msg);
  }

  bool send(vector<char>&& msg) {
    lock_guard lock(mtx);
    if (!lastError.empty()) {
      cout << lastError << "\n";
      return true;
    }
    queue[activeQueue].push_back(std::move(msg));
    if (!sending) {
      do_write_unlocked();
    }
    return false;
  }

  void close() {
    socket.close();
    timer.cancel();
  }

private:
  void do_read_len() {
    auto self(this->shared_from_this());
    if (readbuf.size() < 2)
      readbuf.resize(2);
    net::async_read(socket, net::buffer(readbuf.data(), 2), [this, self](sys::error_code ec, std::size_t) {
      readbuf.resize(readUint16BE(&readbuf[0]) + 2);
      if (ec) {
        cout << "TCP read: " << ec.value() << ": " << ec.message() << "\n";
        close();
        return;
      }
      if (readbuf.size() <= 2) {
        do_read_len();
        return;
      }
      do_read_body();
    });
  }

  void do_read_body() {
    auto self(this->shared_from_this());
    net::async_read(socket, net::buffer(readbuf.data() + 2, readbuf.size() - 2), [this, self](sys::error_code ec, std::size_t) {
      if (ec) {
        cout << "TCP read: " << ec.value() << ": " << ec.message() << "\n";
        close();
        return;
      }
      if (!receive(readbuf)) {
        close();
        return;
      }
      do_read_len();
    });
  }

  void do_write_unlocked() {
    size_t count = queue[activeQueue].size();
    if (!(sending = (count > 0))) {
      return;
    }
    vector<net::const_buffer> buffers;
    buffers.reserve(count);
    for (auto& msg : queue[activeQueue])
      buffers.push_back(net::buffer(msg));
    // cout << "TCP send:";
    // for (auto& msg : queue[activeQueue])
    //   cout << " " << printHex(msg) << "\n";
    queue[activeQueue ^= 1].clear();
    arm_timer();
    net::async_write(socket, buffers, [this](sys::error_code ec, size_t /*length*/) {
      if (ec) {
        std::ostringstream tmp;
        tmp << "send: " << ec.value() << ": " << ec.message();
        lock_guard lock(mtx);
        lastError = tmp.str();
        sending = false;
        socket.close();
        timer.cancel();
        return;
      }
      lock_guard lock(mtx);
      do_write_unlocked();
    });
  }

  void arm_timer() {
    if (heartbeatDelay == 0ms)
      return;
    auto self(this->shared_from_this());
    timer.expires_from_now(heartbeatDelay);
    timer.async_wait([this, self](sys::error_code ec) {
      if (ec)
        return;
      heartbeat();
    });
  }

protected:
  ip::tcp::socket socket;
  net_timer_t timer;
  net_timer_t::duration heartbeatDelay;
  std::mutex mtx;
  vector<char> readbuf;
  int activeQueue = 0;
  bool sending = false;
  vector<vector<char>> queue[2];
  string lastError;
};

template <class Server>
class TCPServer {
public:
  TCPServer(net::io_context& io_context, ip::address listenAddr, unsigned listenPort, net_timer_t::duration heartbeatDelay)
      : endpoint(listenAddr, listenPort), socket(io_context, endpoint.protocol()), acceptor(io_context, endpoint) {}

  void start() { do_accept(); }

private:
  void do_accept() {
    acceptor.async_accept([this](sys::error_code ec, ip::tcp::socket socket) {
      if (!ec) {
        static_cast<Server*>(this)->makeSession(std::move(socket));
      }
      do_accept();
    });
  }

protected:
  ip::tcp::endpoint endpoint;
  ip::tcp::socket socket;
  ip::tcp::acceptor acceptor;
};

} // namespace SGX
