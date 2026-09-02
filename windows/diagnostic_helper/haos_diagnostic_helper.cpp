#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Arguments {
  unsigned long adapter_index = 0;
  unsigned long parent_pid = 0;
  fs::path state_file;
  fs::path stop_file;
};

struct DhcpRequest {
  uint8_t type = 0;
  uint32_t transaction_id = 0;
  uint16_t flags = 0;
  std::array<uint8_t, 6> mac{};
  std::string hostname;
};

std::string JsonEscape(const std::string& value) {
  std::ostringstream output;
  for (const unsigned char character : value) {
    switch (character) {
      case '\\': output << "\\\\"; break;
      case '"': output << "\\\""; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (character < 0x20) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<int>(character);
        } else {
          output << character;
        }
    }
  }
  return output.str();
}

void WriteState(const Arguments& arguments, const std::string& stage,
                const std::string& message, const std::string& server_ip = {},
                const std::string& device_ip = {}, const std::string& mac = {},
                const std::string& hostname = {}) {
  std::error_code error;
  fs::create_directories(arguments.state_file.parent_path(), error);
  const fs::path temporary = arguments.state_file.wstring() + L".tmp";
  std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
  output << "{\"stage\":\"" << JsonEscape(stage) << "\",\"message\":\""
         << JsonEscape(message) << "\"";
  if (!server_ip.empty()) output << ",\"serverIp\":\"" << JsonEscape(server_ip) << "\"";
  if (!device_ip.empty()) output << ",\"deviceIp\":\"" << JsonEscape(device_ip) << "\"";
  if (!mac.empty()) output << ",\"mac\":\"" << JsonEscape(mac) << "\"";
  if (!hostname.empty()) output << ",\"hostname\":\"" << JsonEscape(hostname) << "\"";
  output << '}';
  output.close();
  MoveFileExW(temporary.c_str(), arguments.state_file.c_str(),
              MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

bool ParseArguments(int count, wchar_t** values, Arguments* arguments) {
  for (int index = 1; index + 1 < count; index += 2) {
    const std::wstring key = values[index];
    const std::wstring value = values[index + 1];
    if (key == L"--adapter-index") arguments->adapter_index = std::wcstoul(value.c_str(), nullptr, 10);
    else if (key == L"--parent-pid") arguments->parent_pid = std::wcstoul(value.c_str(), nullptr, 10);
    else if (key == L"--state") arguments->state_file = value;
    else if (key == L"--stop") arguments->stop_file = value;
  }
  return arguments->adapter_index != 0 && !arguments->state_file.empty() &&
         !arguments->stop_file.empty();
}

bool RunHidden(const std::wstring& command) {
  std::vector<wchar_t> buffer(command.begin(), command.end());
  buffer.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
    return false;
  }
  WaitForSingleObject(process.hProcess, 15000);
  DWORD exit_code = 1;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return exit_code == 0;
}

bool RouteOverlaps(uint32_t network_host_order) {
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR) return false;
  bool overlaps = false;
  for (ULONG index = 0; index < table->NumEntries; ++index) {
    const auto& row = table->Table[index];
    if (row.DestinationPrefix.Prefix.si_family != AF_INET) continue;
    const uint8_t prefix = row.DestinationPrefix.PrefixLength;
    if (prefix == 0) continue;
    const uint32_t route = ntohl(row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr);
    const uint8_t common_prefix = std::min<uint8_t>(prefix, 24);
    const uint32_t mask = common_prefix >= 32
                              ? 0xffffffffu
                              : (0xffffffffu << (32 - common_prefix));
    if ((network_host_order & mask) == (route & mask)) {
      overlaps = true;
      break;
    }
  }
  FreeMibTable(table);
  return overlaps;
}

std::string ChooseNetwork() {
  const std::array<const char*, 4> candidates = {
      "192.168.234.0", "192.168.235.0", "192.168.236.0", "172.27.234.0"};
  for (const char* candidate : candidates) {
    IN_ADDR address{};
    InetPtonA(AF_INET, candidate, &address);
    if (!RouteOverlaps(ntohl(address.S_un.S_addr))) return candidate;
  }
  return {};
}

std::string ReplaceLastOctet(const std::string& network, int octet) {
  return network.substr(0, network.rfind('.') + 1) + std::to_string(octet);
}

bool ParseDhcp(const uint8_t* data, int length, DhcpRequest* request) {
  if (length < 244 || data[0] != 1 || data[1] != 1 || data[2] < 6 ||
      data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99) {
    return false;
  }
  std::memcpy(&request->transaction_id, data + 4, 4);
  std::memcpy(&request->flags, data + 10, 2);
  std::copy_n(data + 28, 6, request->mac.begin());
  for (int offset = 240; offset < length;) {
    const uint8_t option = data[offset++];
    if (option == 255) break;
    if (option == 0) continue;
    if (offset >= length) break;
    const uint8_t option_length = data[offset++];
    if (offset + option_length > length) break;
    if (option == 53 && option_length == 1) request->type = data[offset];
    if (option == 12 && option_length > 0) {
      request->hostname.assign(reinterpret_cast<const char*>(data + offset), option_length);
    }
    offset += option_length;
  }
  return request->type == 1 || request->type == 3;
}

void AddOption(std::vector<uint8_t>* packet, uint8_t option,
               const void* value, uint8_t length) {
  packet->push_back(option);
  packet->push_back(length);
  const auto* bytes = static_cast<const uint8_t*>(value);
  packet->insert(packet->end(), bytes, bytes + length);
}

std::vector<uint8_t> BuildReply(const uint8_t* request_data, int request_length,
                                uint8_t response_type, const std::string& server_ip,
                                const std::string& lease_ip) {
  std::vector<uint8_t> packet(240, 0);
  packet[0] = 2;
  packet[1] = 1;
  packet[2] = 6;
  if (request_length >= 44) {
    std::copy_n(request_data + 4, 4, packet.begin() + 4);
    std::copy_n(request_data + 10, 2, packet.begin() + 10);
    std::copy_n(request_data + 28, 16, packet.begin() + 28);
  }
  IN_ADDR server{}, lease{};
  InetPtonA(AF_INET, server_ip.c_str(), &server);
  InetPtonA(AF_INET, lease_ip.c_str(), &lease);
  std::memcpy(packet.data() + 16, &lease.S_un.S_addr, 4);
  std::memcpy(packet.data() + 20, &server.S_un.S_addr, 4);
  packet[236] = 99; packet[237] = 130; packet[238] = 83; packet[239] = 99;
  AddOption(&packet, 53, &response_type, 1);
  AddOption(&packet, 54, &server.S_un.S_addr, 4);
  const uint32_t mask = inet_addr("255.255.255.0");
  AddOption(&packet, 1, &mask, 4);
  const uint32_t lease_seconds = htonl(1800);
  AddOption(&packet, 51, &lease_seconds, 4);
  packet.push_back(255);
  packet.resize(std::max<size_t>(packet.size(), 300), 0);
  return packet;
}

std::string FormatMac(const std::array<uint8_t, 6>& mac) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (size_t index = 0; index < mac.size(); ++index) {
    if (index) output << ':';
    output << std::setw(2) << static_cast<int>(mac[index]);
  }
  return output.str();
}

int wmain(int argc, wchar_t** argv) {
  Arguments arguments;
  if (!ParseArguments(argc, argv, &arguments)) return 2;
  std::error_code ignored;
  fs::remove(arguments.stop_file, ignored);

  const std::string network = ChooseNetwork();
  if (network.empty()) {
    WriteState(arguments, "error", "诊断网段均与现有网络冲突，请断开 VPN 后重试。");
    return 3;
  }
  const std::string server_ip = ReplaceLastOctet(network, 1);
  const std::string lease_ip = ReplaceLastOctet(network, 2);
  WriteState(arguments, "configuring", "正在配置临时诊断网络…", server_ip);

  const std::wstring index = std::to_wstring(arguments.adapter_index);
  const std::wstring server(server_ip.begin(), server_ip.end());
  const std::wstring add_address = L"netsh interface ipv4 add address name=" + index +
      L" address=" + server + L" mask=255.255.255.0 store=active";
  const std::wstring delete_address = L"netsh interface ipv4 delete address name=" + index +
      L" address=" + server;
  const std::wstring firewall_name = L"HA Finder Diagnostic DHCP";
  const std::wstring add_firewall = L"netsh advfirewall firewall add rule name=\"" + firewall_name +
      L"\" dir=in action=allow protocol=UDP localport=67 profile=any";
  const std::wstring delete_firewall = L"netsh advfirewall firewall delete rule name=\"" +
      firewall_name + L"\"";

  if (!RunHidden(add_address)) {
    WriteState(arguments, "error", "无法为所选网卡添加临时 IP。", server_ip);
    return 4;
  }
  RunHidden(delete_firewall);
  RunHidden(add_firewall);

  WSADATA winsock{};
  SOCKET socket_handle = INVALID_SOCKET;
  bool winsock_started = WSAStartup(MAKEWORD(2, 2), &winsock) == 0;
  if (winsock_started) socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_handle == INVALID_SOCKET) {
    WriteState(arguments, "error", "无法启动 DHCP 网络服务。", server_ip);
    RunHidden(delete_firewall);
    RunHidden(delete_address);
    if (winsock_started) WSACleanup();
    return 5;
  }

  BOOL broadcast = TRUE;
  setsockopt(socket_handle, SOL_SOCKET, SO_BROADCAST,
             reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_port = htons(67);
  InetPtonA(AF_INET, server_ip.c_str(), &local.sin_addr);
  if (bind(socket_handle, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR) {
    WriteState(arguments, "error", "UDP 67 端口被占用，无法启动 DHCP。", server_ip);
    closesocket(socket_handle);
    WSACleanup();
    RunHidden(delete_firewall);
    RunHidden(delete_address);
    return 6;
  }

  HANDLE parent = arguments.parent_pid == 0 ? nullptr :
      OpenProcess(SYNCHRONIZE, FALSE, arguments.parent_pid);
  WriteState(arguments, "waiting_dhcp", "诊断网络已建立，等待 HAOS 请求 IP…", server_ip);
  std::string last_mac;
  std::string last_hostname;
  std::array<uint8_t, 1500> buffer{};
  while (!fs::exists(arguments.stop_file) &&
         (!parent || WaitForSingleObject(parent, 0) == WAIT_TIMEOUT)) {
    fd_set readers;
    FD_ZERO(&readers);
    FD_SET(socket_handle, &readers);
    timeval timeout{0, 500000};
    if (select(0, &readers, nullptr, nullptr, &timeout) <= 0) continue;
    sockaddr_in remote{};
    int remote_length = sizeof(remote);
    const int received = recvfrom(socket_handle,
        reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
        reinterpret_cast<sockaddr*>(&remote), &remote_length);
    DhcpRequest request;
    if (received <= 0 || !ParseDhcp(buffer.data(), received, &request)) continue;
    last_mac = FormatMac(request.mac);
    last_hostname = request.hostname;
    const uint8_t response_type = request.type == 1 ? 2 : 5;
    const auto response = BuildReply(buffer.data(), received, response_type, server_ip, lease_ip);
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(68);
    destination.sin_addr.s_addr = INADDR_BROADCAST;
    sendto(socket_handle, reinterpret_cast<const char*>(response.data()),
           static_cast<int>(response.size()), 0,
           reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
    if (response_type == 5) {
      WriteState(arguments, "leased", "已为 HAOS 分配地址，正在检测 8123 服务…",
                 server_ip, lease_ip, last_mac, last_hostname);
    }
  }

  WriteState(arguments, "stopping", "正在停止 DHCP 并恢复网卡设置…",
             server_ip, last_mac.empty() ? "" : lease_ip, last_mac, last_hostname);
  if (parent) CloseHandle(parent);
  closesocket(socket_handle);
  WSACleanup();
  RunHidden(delete_firewall);
  RunHidden(delete_address);
  fs::remove(arguments.stop_file, ignored);
  WriteState(arguments, "stopped", "诊断已停止，临时网络设置已清理。",
             {}, last_mac.empty() ? "" : lease_ip, last_mac, last_hostname);
  return 0;
}
