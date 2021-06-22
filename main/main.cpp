#include "sgx-itch.h"
// sgx-itch.h must be first
#include "OSSpecific.h"
#include "nq-itch.h"
#include "sgx-pcap-util.h"
#include "util.h"
#include <algorithm>
#include <boost/program_options.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace net = boost::asio;
using namespace std::literals;
using namespace boost::program_options;
using std::cout;
using std::exception;
using std::runtime_error;
using std::set;
using std::string;
using std::to_string;

int main(int argc, char** argv) {
  net::io_context ctx;
  std::thread ctxThread;
  try {
    SGX::ITCHService sender{ctx};
    options_description desc("Allowed options");
    string nqItch5, sgxPcap, sgxTcpDump, sgxPcapFilter;
    // clang-format off
    desc.add_options()
      ("help,h", "print usage message")
      ("interface-addr,i", value(&sender.interfaceIP), ("ITCH interface IP,     default " + sender.interfaceIP).c_str())
      ("itch-addr,a",      value(&sender.destIP),      ("ITCH destination IP,   default " + sender.destIP).c_str())
      ("itch-port,p",      value(&sender.itchPort),    ("ITCH destination port, default " + to_string(sender.itchPort)).c_str())
      ("rewinder-port,r",  value(&sender.rewinderPort),("ITCH rewinder port,    default " + to_string(sender.rewinderPort)).c_str())
      ("glimpse-port,g",   value(&sender.glimpsePort), ("Glimpse listen port,   default " + to_string(sender.glimpsePort)).c_str())
      ("delay-us,w",       value(&sender.delayUs),     ("Send delay (microsec), default " + to_string(sender.delayUs)).c_str())
      ("nqitch",           value(&nqItch5),            "nasdaq ITCH 5.0 parsing (unfinished)")
      ("sgxpcap",          value(&sgxPcap),            "SGX ITCH UDP pcap parsing")
      ("sgxpcapfilter",    value(&sgxPcapFilter),      "SGX ITCH UDP pcap extract specified products")
      ("sgxtcpdump",       value(&sgxTcpDump),         "SGX Glimpse tcpdump parsing")
      ("inputs",           value(&sender.inputs))
    ;
    // clang-format on
    positional_options_description p;
    p.add("inputs", -1);
    variables_map vm;
    parsed_options parsed = command_line_parser(argc, argv).options(desc).positional(p).run();
    store(parsed, vm);
    notify(vm);

    int rc = 0;
    do {
      if (vm.count("help")) {
        cout << desc << "\n";
        break;
      }
      if (!nqItch5.empty()) {
        rc = NQ::parse_NQ_ITCH50(nqItch5);
        break;
      }
      if (!sgxPcap.empty()) {
        rc = SGX::parseSGXpcap(sgxPcap);
        break;
      }
      if (!sgxTcpDump.empty()) {
        rc = SGX::parseSGXtcpdump(sgxTcpDump);
        break;
      }
      if (!sgxPcapFilter.empty()) {
        if (sender.inputs.empty())
          throw runtime_error("Missing output file name");
        if (sender.inputs.size() < 2)
          throw runtime_error("Missing filter product(s)");
        if (sender.inputs.size() > 2)
          throw runtime_error("Too many arguments");
        set<string> products;
        auto& prod_list = sender.inputs[1];
        for (size_t i = 0; i < prod_list.size(); i++) {
          size_t comma = prod_list.find_first_of(',', i);
          if (comma == string::npos)
            comma = prod_list.size();
          products.insert(prod_list.substr(i, comma - i));
          i = comma;
        }
        rc = SGX::filterSGXpcap(sgxPcapFilter, sender.inputs[0], products);
        break;
      }
      OSSpecific oss;
      if (sender.inputs.size() != 1)
        throw runtime_error("invalid argument count, expecting 1 pcap file");
      ctxThread = std::thread([&ctx] {
        net::io_context::work lock(ctx);
        ctx.run();
      });
      sender.runFromPcap(sender.inputs[0]);
      ctxThread.join();
    } while (false);
  } catch (std::exception const& e) {
    std::cerr << "error: " << e.what() << std::endl;
    ctxThread.detach();
    exit(1);
  }
}
