#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

struct Arguments {
  std::string interface;
  int parent_pid = 0;
  std::string state, stop, log, found;
};

std::string ShellQuote(const std::string& value) {
  std::string result = "'";
  for (char character : value) result += character == '\'' ? "'\\''" : std::string(1, character);
  return result + "'";
}

void Log(const Arguments& args, const std::string& message) {
  if (args.log.empty()) return;
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm local{};
  localtime_r(&now, &local);
  std::ofstream out(args.log, std::ios::app);
  out << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << " [MAC-HELPER] " << message << '\n';
}

std::string EscapeJson(const std::string& value) {
  std::string result;
  for (char c : value) {
    if (c == '\\' || c == '"') result += '\\';
    if (c == '\n') result += "\\n"; else result += c;
  }
  return result;
}

void State(const Arguments& args, const std::string& stage, const std::string& message,
           const std::string& server = {}, const std::string& device = {},
           const std::string& mac = {}, const std::string& hostname = {}) {
  const std::string temporary = args.state + ".tmp";
  std::ofstream out(temporary, std::ios::trunc);
  out << "{\"stage\":\"" << EscapeJson(stage) << "\",\"message\":\""
      << EscapeJson(message) << "\"";
  if (!server.empty()) out << ",\"serverIp\":\"" << server << "\"";
  if (!device.empty()) out << ",\"deviceIp\":\"" << device << "\"";
  if (!mac.empty()) out << ",\"mac\":\"" << mac << "\"";
  if (!hostname.empty()) out << ",\"hostname\":\"" << EscapeJson(hostname) << "\"";
  out << '}';
  out.close();
  if (std::rename(temporary.c_str(), args.state.c_str()) != 0) {
    std::remove(args.state.c_str());
    std::rename(temporary.c_str(), args.state.c_str());
  }
}

bool ParseArguments(int argc, char** argv, Arguments* args) {
  for (int i = 1; i + 1 < argc; i += 2) {
    const std::string key = argv[i], value = argv[i + 1];
    if (key == "--interface") args->interface = value;
    else if (key == "--parent-pid") args->parent_pid = std::stoi(value);
    else if (key == "--state") args->state = value;
    else if (key == "--stop") args->stop = value;
    else if (key == "--log") args->log = value;
    else if (key == "--found") args->found = value;
  }
  return !args->interface.empty() && !args->state.empty() && !args->stop.empty();
}

bool Run(const std::string& command) { return std::system(command.c_str()) == 0; }

std::string Prefix(const std::string& network) {
  return network.substr(0, network.rfind('.') + 1);
}

std::string ChooseNetwork() {
  const std::array<std::string, 4> candidates = {
      "192.168.234.0", "192.168.235.0", "192.168.236.0", "172.27.234.0"};
  ifaddrs* interfaces = nullptr;
  if (getifaddrs(&interfaces) != 0) return candidates.front();
  for (const auto& network : candidates) {
    in_addr candidate{};
    inet_pton(AF_INET, network.c_str(), &candidate);
    bool overlaps = false;
    for (ifaddrs* item = interfaces; item; item = item->ifa_next) {
      if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET) continue;
      const auto* address = reinterpret_cast<sockaddr_in*>(item->ifa_addr);
      if ((ntohl(address->sin_addr.s_addr) & 0xffffff00u) ==
          (ntohl(candidate.s_addr) & 0xffffff00u)) {
        overlaps = true;
        break;
      }
    }
    if (!overlaps) {
      freeifaddrs(interfaces);
      return network;
    }
  }
  freeifaddrs(interfaces);
  return {};
}

struct Request {
  uint8_t type = 0;
  std::array<uint8_t, 6> mac{};
  std::string hostname, client_id, requested_ip, server_id;
};

std::string Hex(const uint8_t* bytes, size_t length) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (size_t i = 0; i < length; ++i) {
    if (i) out << ':';
    out << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return out.str();
}

bool ParseDhcp(const uint8_t* data, int length, Request* request) {
  if (length < 244 || data[0] != 1 || data[1] != 1 || data[2] < 6 ||
      std::memcmp(data + 236, "\x63\x82\x53\x63", 4) != 0) return false;
  std::copy_n(data + 28, 6, request->mac.begin());
  for (int offset = 240; offset < length;) {
    const uint8_t option = data[offset++];
    if (option == 255) break;
    if (option == 0) continue;
    if (offset >= length) break;
    const uint8_t size = data[offset++];
    if (offset + size > length) break;
    if (option == 53 && size == 1) request->type = data[offset];
    if (option == 12) request->hostname.assign(reinterpret_cast<const char*>(data + offset), size);
    if (option == 61) request->client_id = Hex(data + offset, size);
    if ((option == 50 || option == 54) && size == 4) {
      char address[INET_ADDRSTRLEN]{};
      inet_ntop(AF_INET, data + offset, address, sizeof(address));
      if (option == 50) request->requested_ip = address; else request->server_id = address;
    }
    offset += size;
  }
  return request->type == 1 || request->type == 3;
}

void Option(std::vector<uint8_t>* packet, uint8_t code, const void* value, uint8_t size) {
  packet->push_back(code); packet->push_back(size);
  const auto* bytes = static_cast<const uint8_t*>(value);
  packet->insert(packet->end(), bytes, bytes + size);
}

std::vector<uint8_t> Reply(const uint8_t* request, int length, uint8_t type,
                           const std::string& server_ip, const std::string& lease_ip) {
  std::vector<uint8_t> packet(240, 0);
  packet[0] = 2; packet[1] = 1; packet[2] = 6;
  if (length >= 44) {
    std::copy_n(request + 4, 4, packet.begin() + 4);
    std::copy_n(request + 10, 2, packet.begin() + 10);
    std::copy_n(request + 28, 16, packet.begin() + 28);
  }
  in_addr server{}, lease{}, mask{}, broadcast{};
  inet_pton(AF_INET, server_ip.c_str(), &server);
  inet_pton(AF_INET, lease_ip.c_str(), &lease);
  inet_pton(AF_INET, "255.255.255.0", &mask);
  const std::string broadcast_ip = Prefix(server_ip) + "255";
  inet_pton(AF_INET, broadcast_ip.c_str(), &broadcast);
  std::memcpy(packet.data() + 16, &lease.s_addr, 4);
  std::memcpy(packet.data() + 20, &server.s_addr, 4);
  std::memcpy(packet.data() + 236, "\x63\x82\x53\x63", 4);
  Option(&packet, 53, &type, 1); Option(&packet, 54, &server.s_addr, 4);
  Option(&packet, 1, &mask.s_addr, 4); Option(&packet, 28, &broadcast.s_addr, 4);
  const uint32_t lease_time = htonl(1800), renewal = htonl(900), rebinding = htonl(1575);
  Option(&packet, 51, &lease_time, 4); Option(&packet, 58, &renewal, 4);
  Option(&packet, 59, &rebinding, 4); packet.push_back(255);
  packet.resize(std::max<size_t>(300, packet.size()), 0);
  return packet;
}

int main(int argc, char** argv) {
  Arguments args;
  if (!ParseArguments(argc, argv, &args) || geteuid() != 0) return 2;
  Log(args, "Helper started; interface=" + args.interface + "; parent pid=" + std::to_string(args.parent_pid));
  const std::string network = ChooseNetwork();
  if (network.empty()) { State(args, "error", "诊断网段均与现有网络冲突，请断开 VPN 后重试。"); return 3; }
  const std::string server_ip = Prefix(network) + "1", lease_ip = Prefix(network) + "2";
  State(args, "configuring", "正在配置临时诊断网络…", server_ip);
  const std::string add = "/sbin/ifconfig " + ShellQuote(args.interface) + " alias " + server_ip +
      " netmask 255.255.255.0 broadcast " + Prefix(network) + "255";
  const std::string remove = "/sbin/ifconfig " + ShellQuote(args.interface) + " -alias " + server_ip;
  if (!Run(add)) { Log(args, "ifconfig alias failed"); State(args, "error", "无法添加临时诊断 IP。", server_ip); return 4; }
  Log(args, "Temporary address added; original network configuration unchanged");

  const int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int yes = 1;
  setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
#ifdef IP_BOUND_IF
  const unsigned int interface_index = if_nametoindex(args.interface.c_str());
  if (setsockopt(socket_fd, IPPROTO_IP, IP_BOUND_IF, &interface_index, sizeof(interface_index)) == 0)
    Log(args, "DHCP socket pinned to interface index=" + std::to_string(interface_index));
  else Log(args, "WARNING: IP_BOUND_IF failed; errno=" + std::to_string(errno));
#endif
  sockaddr_in local{}; local.sin_family = AF_INET; local.sin_port = htons(67);
  inet_pton(AF_INET, server_ip.c_str(), &local.sin_addr);
  if (socket_fd < 0 || bind(socket_fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    Log(args, "bind failed; errno=" + std::to_string(errno));
    State(args, "error", "无法监听 DHCP UDP 67 端口。", server_ip); Run(remove); return 5;
  }
  Log(args, "DHCP socket listening on " + server_ip + ":67");
  State(args, "configuring", "正在重新建立网线连接，触发 HAOS 请求 IP…", server_ip);
  Run("/sbin/ifconfig " + ShellQuote(args.interface) + " down");
  std::this_thread::sleep_for(std::chrono::seconds(5));
  Run("/sbin/ifconfig " + ShellQuote(args.interface) + " up");
  Run(add);
  Log(args, "Ethernet interface link cycle completed");
  State(args, "waiting_dhcp", "诊断网络已建立，等待 HAOS 请求 IP…", server_ip);

  std::array<uint8_t, 1600> buffer{};
  std::string last_mac, last_hostname;
  while (access(args.stop.c_str(), F_OK) != 0 &&
         (args.parent_pid <= 0 || kill(args.parent_pid, 0) == 0)) {
    fd_set set; FD_ZERO(&set); FD_SET(socket_fd, &set); timeval timeout{0, 500000};
    if (select(socket_fd + 1, &set, nullptr, nullptr, &timeout) <= 0) continue;
    sockaddr_in remote{}; socklen_t remote_size = sizeof(remote);
    const int received = recvfrom(socket_fd, buffer.data(), buffer.size(), 0,
        reinterpret_cast<sockaddr*>(&remote), &remote_size);
    Request request;
    if (received <= 0 || !ParseDhcp(buffer.data(), received, &request)) continue;
    last_mac = Hex(request.mac.data(), request.mac.size()); last_hostname = request.hostname;
    Log(args, "Received DHCP type=" + std::to_string(request.type) + "; mac=" + last_mac +
        "; hostname=" + last_hostname + "; clientId=" + request.client_id +
        "; requestedIp=" + request.requested_ip + "; serverId=" + request.server_id);
    const uint8_t reply_type = request.type == 1 ? 2 : 5;
    const auto packet = Reply(buffer.data(), received, reply_type, server_ip, lease_ip);
    bool sent = false;
    for (int repeat = 0; repeat < 2; ++repeat) {
      for (const auto& address : {std::string("255.255.255.255"), Prefix(network) + "255"}) {
        sockaddr_in destination{}; destination.sin_family = AF_INET; destination.sin_port = htons(68);
        inet_pton(AF_INET, address.c_str(), &destination.sin_addr);
        sent |= sendto(socket_fd, packet.data(), packet.size(), 0,
            reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) >= 0;
      }
      if (repeat == 0) std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    Log(args, sent ? (reply_type == 2 ? "Sent DHCP OFFER" : "Sent DHCP ACK") : "DHCP reply failed");
    if (reply_type == 5 && sent)
      State(args, "leased", "已为 HAOS 分配地址，正在检测服务…", server_ip, lease_ip, last_mac, last_hostname);
  }
  State(args, "stopping", "正在停止 DHCP 并恢复网卡设置…", server_ip,
        last_mac.empty() ? "" : lease_ip, last_mac, last_hostname);
  close(socket_fd); Run(remove);
  Log(args, "Temporary address removed; cleanup complete");
  std::remove(args.stop.c_str()); std::remove(args.found.c_str());
  State(args, "stopped", "诊断已停止，临时网络设置已清理。", {},
        last_mac.empty() ? "" : lease_ip, last_mac, last_hostname);
  return 0;
}
