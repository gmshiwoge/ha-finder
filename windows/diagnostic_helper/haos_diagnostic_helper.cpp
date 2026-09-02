#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>

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
  fs::path log_file;
  fs::path found_file;
};

void AppendLog(const Arguments& arguments, const std::string& message) {
  if (arguments.log_file.empty()) return;
  std::error_code error;
  fs::create_directories(arguments.log_file.parent_path(), error);
  SYSTEMTIME time{};
  GetLocalTime(&time);
  std::ofstream output(arguments.log_file, std::ios::binary | std::ios::app);
  output << std::setfill('0') << std::setw(4) << time.wYear << '-'
         << std::setw(2) << time.wMonth << '-' << std::setw(2) << time.wDay
         << ' ' << std::setw(2) << time.wHour << ':' << std::setw(2)
         << time.wMinute << ':' << std::setw(2) << time.wSecond
         << " [HELPER] " << message << '\n';
}

struct DhcpRequest {
  uint8_t type = 0;
  uint32_t transaction_id = 0;
  uint16_t flags = 0;
  std::array<uint8_t, 6> mac{};
  std::string hostname;
  std::string client_id;
  std::string requested_ip;
  std::string server_identifier;
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
    else if (key == L"--log") arguments->log_file = value;
    else if (key == L"--found") arguments->found_file = value;
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

DWORD AddDiagnosticAddress(unsigned long interface_index,
                           const std::string& address,
                           bool* address_created) {
  MIB_UNICASTIPADDRESS_ROW row{};
  InitializeUnicastIpAddressEntry(&row);
  row.InterfaceIndex = interface_index;
  row.Address.Ipv4.sin_family = AF_INET;
  InetPtonA(AF_INET, address.c_str(), &row.Address.Ipv4.sin_addr);
  row.OnLinkPrefixLength = 24;
  row.PrefixOrigin = IpPrefixOriginManual;
  row.SuffixOrigin = IpSuffixOriginManual;
  const DWORD result = CreateUnicastIpAddressEntry(&row);
  *address_created = result == NO_ERROR;
  return result;
}

bool RemoveDiagnosticAddress(unsigned long interface_index,
                             const std::string& address,
                             bool address_created) {
  if (!address_created) return true;
  MIB_UNICASTIPADDRESS_ROW row{};
  InitializeUnicastIpAddressEntry(&row);
  row.InterfaceIndex = interface_index;
  row.Address.Ipv4.sin_family = AF_INET;
  InetPtonA(AF_INET, address.c_str(), &row.Address.Ipv4.sin_addr);
  if (GetUnicastIpAddressEntry(&row) != NO_ERROR) return false;
  return DeleteUnicastIpAddressEntry(&row) == NO_ERROR;
}

bool GetInterfaceMac(unsigned long interface_index,
                     std::array<uint8_t, 6>* mac) {
  MIB_IF_ROW2 row{};
  row.InterfaceIndex = interface_index;
  if (GetIfEntry2(&row) != NO_ERROR || row.PhysicalAddressLength < mac->size()) {
    return false;
  }
  std::copy_n(row.PhysicalAddress, mac->size(), mac->begin());
  return true;
}

bool SetInterfaceEnabled(unsigned long interface_index, bool enabled) {
  MIB_IFROW row{};
  row.dwIndex = interface_index;
  row.dwAdminStatus = enabled ? MIB_IF_ADMIN_STATUS_UP
                              : MIB_IF_ADMIN_STATUS_DOWN;
  return SetIfEntry(&row) == NO_ERROR;
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
    if ((option == 50 || option == 54) && option_length == 4) {
      char address[INET_ADDRSTRLEN]{};
      InetNtopA(AF_INET, const_cast<uint8_t*>(data + offset), address,
                static_cast<DWORD>(sizeof(address)));
      if (option == 50) request->requested_ip = address;
      if (option == 54) request->server_identifier = address;
    }
    if (option == 61 && option_length > 0) {
      std::ostringstream value;
      value << std::hex << std::setfill('0');
      for (uint8_t index = 0; index < option_length; ++index) {
        if (index) value << ':';
        value << std::setw(2) << static_cast<int>(data[offset + index]);
      }
      request->client_id = value.str();
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
  IN_ADDR subnet_mask{};
  InetPtonA(AF_INET, "255.255.255.0", &subnet_mask);
  AddOption(&packet, 1, &subnet_mask.S_un.S_addr, 4);
  const uint32_t lease_seconds = htonl(1800);
  AddOption(&packet, 51, &lease_seconds, 4);
  const uint32_t renewal_seconds = htonl(900);
  const uint32_t rebinding_seconds = htonl(1575);
  AddOption(&packet, 58, &renewal_seconds, 4);
  AddOption(&packet, 59, &rebinding_seconds, 4);
  IN_ADDR broadcast_address{};
  const std::string broadcast_ip =
      server_ip.substr(0, server_ip.rfind('.') + 1) + "255";
  InetPtonA(AF_INET, broadcast_ip.c_str(), &broadcast_address);
  AddOption(&packet, 28, &broadcast_address.S_un.S_addr, 4);
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

int RunHelper(int argc, wchar_t** argv) {
  Arguments arguments;
  if (!ParseArguments(argc, argv, &arguments)) return 2;
  AppendLog(arguments, "Helper started; adapter ifIndex=" +
                           std::to_string(arguments.adapter_index) +
                           "; parent pid=" + std::to_string(arguments.parent_pid));
  std::error_code ignored;
  if (fs::exists(arguments.stop_file)) {
    AppendLog(arguments, "Stop was requested before Helper initialization");
    WriteState(arguments, "stopped", "诊断已取消，未修改网络设置。");
    return 0;
  }

  const std::string network = ChooseNetwork();
  if (network.empty()) {
    AppendLog(arguments, "All diagnostic networks overlap existing routes");
    WriteState(arguments, "error", "诊断网段均与现有网络冲突，请断开 VPN 后重试。");
    return 3;
  }
  const std::string server_ip = ReplaceLastOctet(network, 1);
  const std::string lease_ip = ReplaceLastOctet(network, 2);
  AppendLog(arguments, "Selected network " + network + "/24; server=" +
                           server_ip + "; lease=" + lease_ip);
  WriteState(arguments, "configuring", "正在配置临时诊断网络…", server_ip);

  const std::wstring firewall_name = L"HA Finder Diagnostic DHCP";
  const std::wstring add_firewall = L"netsh advfirewall firewall add rule name=\"" + firewall_name +
      L"\" dir=in action=allow protocol=UDP localport=67 profile=any";
  const std::wstring delete_firewall = L"netsh advfirewall firewall delete rule name=\"" +
      firewall_name + L"\"";

  bool address_created = false;
  const DWORD add_address_result = AddDiagnosticAddress(
      arguments.adapter_index, server_ip, &address_created);
  if (add_address_result != NO_ERROR &&
      add_address_result != ERROR_OBJECT_ALREADY_EXISTS) {
    AppendLog(arguments, "CreateUnicastIpAddressEntry failed; error=" +
                             std::to_string(add_address_result));
    WriteState(arguments, "error", "无法为所选网卡添加临时 IP。", server_ip);
    return 4;
  }
  AppendLog(arguments, address_created
                           ? "Temporary address added with Windows IP Helper; original DHCP/static configuration unchanged"
                           : "Diagnostic address already existed; original configuration unchanged");
  std::array<uint8_t, 6> interface_mac{};
  const bool has_interface_mac =
      GetInterfaceMac(arguments.adapter_index, &interface_mac);
  if (has_interface_mac) {
    AppendLog(arguments, "Selected adapter MAC=" + FormatMac(interface_mac));
  } else {
    AppendLog(arguments, "WARNING: unable to read selected adapter MAC");
  }
  RunHidden(delete_firewall);
  if (RunHidden(add_firewall)) {
    AppendLog(arguments, "Windows Firewall UDP 67 rule added");
  } else {
    AppendLog(arguments, "WARNING: failed to add Windows Firewall rule");
  }

  WSADATA winsock{};
  SOCKET socket_handle = INVALID_SOCKET;
  bool winsock_started = WSAStartup(MAKEWORD(2, 2), &winsock) == 0;
  if (winsock_started) socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_handle == INVALID_SOCKET) {
    AppendLog(arguments, "socket() failed; WSA error=" +
                             std::to_string(WSAGetLastError()));
    WriteState(arguments, "error", "无法启动 DHCP 网络服务。", server_ip);
    RunHidden(delete_firewall);
    RemoveDiagnosticAddress(arguments.adapter_index, server_ip, address_created);
    if (winsock_started) WSACleanup();
    return 5;
  }

  BOOL broadcast = TRUE;
  setsockopt(socket_handle, SOL_SOCKET, SO_BROADCAST,
             reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));
  // Keep DHCP replies on the adapter selected by the user. Limited broadcasts
  // can otherwise be routed through Wi-Fi, a VPN or a virtual switch.
  const DWORD outgoing_interface = htonl(arguments.adapter_index);
  if (setsockopt(socket_handle, IPPROTO_IP, IP_UNICAST_IF,
                 reinterpret_cast<const char*>(&outgoing_interface),
                 sizeof(outgoing_interface)) == SOCKET_ERROR) {
    AppendLog(arguments, "WARNING: IP_UNICAST_IF failed; WSA error=" +
                             std::to_string(WSAGetLastError()));
  } else {
    AppendLog(arguments, "DHCP replies pinned to adapter ifIndex=" +
                             std::to_string(arguments.adapter_index));
  }
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_port = htons(67);
  InetPtonA(AF_INET, server_ip.c_str(), &local.sin_addr);
  int bind_error = 0;
  bool bound = false;
  WriteState(arguments, "configuring", "等待 Windows 启用临时 IP…", server_ip);
  for (int attempt = 1; attempt <= 40 && !fs::exists(arguments.stop_file);
       ++attempt) {
    if (bind(socket_handle, reinterpret_cast<sockaddr*>(&local), sizeof(local)) !=
        SOCKET_ERROR) {
      bound = true;
      if (attempt > 1) {
        AppendLog(arguments, "Address became available after " +
                                 std::to_string(attempt) + " bind attempts");
      }
      break;
    }
    bind_error = WSAGetLastError();
    if (attempt == 1 || attempt % 10 == 0) {
      AppendLog(arguments, "bind(" + server_ip + ":67) attempt=" +
                               std::to_string(attempt) + "; WSA error=" +
                               std::to_string(bind_error));
    }
    // WSAEADDRNOTAVAIL means Windows is still completing duplicate-address
    // detection for the newly-added secondary IP. Other failures will not be
    // repaired by waiting.
    if (bind_error != WSAEADDRNOTAVAIL) break;
    Sleep(500);
  }
  if (!bound) {
    AppendLog(arguments, "bind(" + server_ip + ":67) ultimately failed; WSA error=" +
                             std::to_string(bind_error));
    const std::string message = bind_error == WSAEADDRINUSE
        ? "UDP 67 端口被其他程序占用，无法启动 DHCP。"
        : "Windows 未能启用临时诊断 IP（WSA " +
              std::to_string(bind_error) + "）。";
    WriteState(arguments, "error", message, server_ip);
    closesocket(socket_handle);
    WSACleanup();
    RunHidden(delete_firewall);
    RemoveDiagnosticAddress(arguments.adapter_index, server_ip, address_created);
    return 6;
  }
  AppendLog(arguments, "DHCP socket listening on " + server_ip + ":67");

  // The directly-connected HAOS may have sent its first DHCP DISCOVER before
  // this server was ready, then wait a long time before retrying. Cycle only
  // the selected Ethernet adapter after the socket is listening so HAOS sees
  // a fresh carrier transition and requests an address immediately.
  int link_cycle_count = 0;
  ULONGLONG last_link_cycle = 0;
  const auto cycle_interface = [&]() {
    ++link_cycle_count;
    WriteState(arguments, "configuring",
               "正在重新建立网线连接，触发 HAOS 请求 IP…", server_ip);
    AppendLog(arguments, "Cycling selected Ethernet adapter for 5 seconds; cycle=" +
                             std::to_string(link_cycle_count));
    if (SetInterfaceEnabled(arguments.adapter_index, false)) {
      Sleep(5000);
      if (SetInterfaceEnabled(arguments.adapter_index, true)) {
        AppendLog(arguments, "Ethernet adapter link cycle completed");
      } else {
        AppendLog(arguments,
                  "WARNING: failed to re-enable selected Ethernet adapter");
      }
    } else {
      AppendLog(arguments,
                "WARNING: failed to disable selected Ethernet adapter");
    }
    last_link_cycle = GetTickCount64();
    WriteState(arguments, "waiting_dhcp",
               "诊断网络已建立，等待 HAOS 请求 IP…", server_ip);
  };
  cycle_interface();

  HANDLE parent = arguments.parent_pid == 0 ? nullptr :
      OpenProcess(SYNCHRONIZE, FALSE, arguments.parent_pid);
  WriteState(arguments, "waiting_dhcp", "诊断网络已建立，等待 HAOS 请求 IP…", server_ip);
  std::string last_mac;
  std::string last_hostname;
  bool external_dhcp_seen = false;
  int ignored_host_requests = 0;
  std::array<uint8_t, 1500> buffer{};
  while (!fs::exists(arguments.stop_file) &&
         (!parent || WaitForSingleObject(parent, 0) == WAIT_TIMEOUT)) {
    if (!external_dhcp_seen && !arguments.found_file.empty() &&
        fs::exists(arguments.found_file)) {
      external_dhcp_seen = true;
      AppendLog(arguments,
                "Flutter confirmed HA on port 8123; stopping link-cycle retries");
    }
    if (!external_dhcp_seen && link_cycle_count < 3 &&
        GetTickCount64() - last_link_cycle >= 30000) {
      AppendLog(arguments,
                "No DHCP from an external device after 30 seconds; retrying link cycle");
      cycle_interface();
      continue;
    }
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
    if (received <= 0) continue;
    if (!ParseDhcp(buffer.data(), received, &request)) {
      AppendLog(arguments, "Ignored unrecognized UDP/67 datagram; bytes=" +
                               std::to_string(received));
      continue;
    }
    last_mac = FormatMac(request.mac);
    last_hostname = request.hostname;
    if (has_interface_mac && request.mac == interface_mac) {
      ++ignored_host_requests;
      if (ignored_host_requests == 1 || ignored_host_requests % 10 == 0) {
        AppendLog(arguments, "Ignored DHCP request from this Windows adapter; count=" +
                                 std::to_string(ignored_host_requests) +
                                 "; mac=" + last_mac +
                                 "; hostname=" + last_hostname);
      }
      continue;
    }
    external_dhcp_seen = true;
    AppendLog(arguments, "Received DHCP message type=" +
                             std::to_string(request.type) + "; mac=" + last_mac +
                             "; hostname=" + last_hostname +
                             "; clientId=" + request.client_id +
                             "; requestedIp=" + request.requested_ip +
                             "; serverId=" + request.server_identifier);
    const uint8_t response_type = request.type == 1 ? 2 : 5;
    const auto response = BuildReply(buffer.data(), received, response_type, server_ip, lease_ip);
    const std::array<std::string, 2> destinations = {
        "255.255.255.255", ReplaceLastOctet(network, 255)};
    bool reply_sent = false;
    for (int repetition = 1; repetition <= 2; ++repetition) {
      for (const auto& destination_ip : destinations) {
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(68);
        InetPtonA(AF_INET, destination_ip.c_str(), &destination.sin_addr);
        const int sent = sendto(socket_handle,
            reinterpret_cast<const char*>(response.data()),
            static_cast<int>(response.size()), 0,
            reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
        if (sent == SOCKET_ERROR) {
          AppendLog(arguments, "sendto(" + destination_ip + ") failed; WSA error=" +
                                   std::to_string(WSAGetLastError()));
        } else {
          reply_sent = true;
        }
      }
      if (repetition == 1) Sleep(120);
    }
    if (reply_sent) {
      AppendLog(arguments, std::string(response_type == 2 ? "Sent DHCP OFFER"
                                                          : "Sent DHCP ACK") +
                               " via limited and directed broadcast (2x)");
    }
    if (response_type == 5 && reply_sent) {
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
  // Always leave the selected adapter enabled, even when the main Flutter
  // window was closed during the link-cycle operation.
  SetInterfaceEnabled(arguments.adapter_index, true);
  const bool address_removed = RemoveDiagnosticAddress(
      arguments.adapter_index, server_ip, address_created);
  AppendLog(arguments, address_removed ? "Temporary address removed; cleanup complete"
                                       : "WARNING: failed to remove temporary address");
  fs::remove(arguments.stop_file, ignored);
  fs::remove(arguments.found_file, ignored);
  WriteState(arguments, "stopped", "诊断已停止，临时网络设置已清理。",
             {}, last_mac.empty() ? "" : lease_ip, last_mac, last_hostname);
  return 0;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  int argument_count = 0;
  wchar_t** arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
  if (!arguments) return 2;
  const int result = RunHelper(argument_count, arguments);
  LocalFree(arguments);
  return result;
}
