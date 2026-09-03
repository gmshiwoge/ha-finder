import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:multicast_dns/multicast_dns.dart';

class HaInstance {
  const HaInstance({
    required this.name,
    required this.host,
    required this.port,
    this.scheme = 'http',
    this.verified = true,
  });

  final String name;
  final String host;
  final int port;
  final String scheme;
  final bool verified;
  String get url => '$scheme://${host.contains(':') ? '[$host]' : host}:$port';
}

class HomeAssistantDiscovery {
  static const _serviceType = '_home-assistant._tcp.local';

  Future<List<HaInstance>> discover() async {
    final client = MDnsClient(
      rawDatagramSocketFactory:
          (
            host,
            port, {
            bool reuseAddress = false,
            bool reusePort = false,
            int ttl = 1,
          }) => RawDatagramSocket.bind(
            host,
            port,
            reuseAddress: reuseAddress,
            reusePort: Platform.isWindows ? false : reusePort,
            ttl: ttl,
          ),
    );
    try {
      await client.start();
      final pointers = await client
          .lookup<PtrResourceRecord>(
            ResourceRecordQuery.serverPointer(_serviceType),
            timeout: const Duration(seconds: 4),
          )
          .toList();
      final names = pointers.map((record) => record.domainName).toSet();
      final results = await Future.wait(
        names.map((name) => _resolve(client, name)),
      );
      return results.whereType<HaInstance>().toList()
        ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    } finally {
      client.stop();
    }
  }

  Future<HaInstance?> _resolve(MDnsClient client, String serviceName) async {
    final services = await client
        .lookup<SrvResourceRecord>(
          ResourceRecordQuery.service(serviceName),
          timeout: const Duration(seconds: 2),
        )
        .toList();
    if (services.isEmpty) return null;
    final service = services.first;
    final addresses = await client
        .lookup<IPAddressResourceRecord>(
          ResourceRecordQuery.addressIPv4(service.target),
          timeout: const Duration(seconds: 2),
        )
        .toList();
    final host = addresses.isNotEmpty
        ? addresses.first.address.address
        : _withoutDot(service.target);
    final suffix = '.$_serviceType';
    final name = serviceName.endsWith(suffix)
        ? serviceName.substring(0, serviceName.length - suffix.length)
        : _withoutDot(serviceName);
    return HaInstance(
      name: name.isEmpty ? 'Home Assistant' : name,
      host: host,
      port: service.port,
      scheme: service.port == 443 ? 'https' : 'http',
    );
  }

  Future<List<HaInstance>> discoverEnhanced({
    void Function(int checked, int total)? onProgress,
  }) async {
    List<HaInstance> discovered;
    try {
      discovered = await discover();
    } on Object {
      discovered = const [];
    }
    final subnets = await localSubnets();
    final scanned = await _scanSubnets(subnets.take(3), onProgress: onProgress);
    final booting = await _discoverBootingCandidates(subnets.take(3));
    return _merge([...booting, ...scanned], discovered);
  }

  Future<List<HaInstance>> discoverDiagnosticSubnet(String subnet) async {
    List<HaInstance> mdns;
    try {
      mdns = (await discover())
          .where((instance) => instance.host.startsWith('$subnet.'))
          .toList();
    } on Object {
      mdns = const [];
    }
    final scanned = await _scanSubnets([subnet]);
    return _merge(scanned, mdns);
  }

  Future<HaInstance?> probeHost(String host) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(milliseconds: 450)
      ..findProxy = ((_) => 'DIRECT')
      ..badCertificateCallback = (_, _, _) => true;
    try {
      return await _probeHost(client, host);
    } finally {
      client.close(force: true);
    }
  }

  Future<List<HaInstance>> _scanSubnets(
    Iterable<String> subnets, {
    void Function(int checked, int total)? onProgress,
  }) async {
    final targets = <String>[
      for (final subnet in subnets)
        for (var last = 2; last < 255; last++) '$subnet.$last',
    ];
    final client = HttpClient()
      ..connectionTimeout = const Duration(milliseconds: 450)
      ..findProxy = ((_) => 'DIRECT')
      ..badCertificateCallback = (_, _, _) => true;
    final scanned = <HaInstance>[];
    const batchSize = 40;
    try {
      for (var start = 0; start < targets.length; start += batchSize) {
        final end = (start + batchSize).clamp(0, targets.length);
        final results = await Future.wait(
          targets.sublist(start, end).map((host) => _probeHost(client, host)),
        );
        scanned.addAll(results.whereType<HaInstance>());
        onProgress?.call(end, targets.length);
      }
    } finally {
      client.close(force: true);
    }
    return scanned;
  }

  List<HaInstance> _merge(
    List<HaInstance> scanned,
    List<HaInstance> discovered,
  ) {
    final merged = <String, HaInstance>{};
    for (final instance in [...scanned, ...discovered]) {
      merged['${instance.host}:${instance.port}'] = instance;
    }
    return merged.values.toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
  }

  Future<Set<String>> localSubnets() async {
    final interfaces = await NetworkInterface.list(
      type: InternetAddressType.IPv4,
      includeLoopback: false,
    );
    final subnets = <String>{};
    for (final interface in interfaces) {
      for (final address in interface.addresses) {
        final parts = address.address.split('.');
        if (parts.length != 4 || !_isPrivate(parts)) continue;
        subnets.add(parts.take(3).join('.'));
      }
    }
    return subnets;
  }

  bool _isPrivate(List<String> parts) {
    final first = int.tryParse(parts[0]) ?? 0;
    final second = int.tryParse(parts[1]) ?? 0;
    return first == 10 ||
        (first == 172 && second >= 16 && second <= 31) ||
        (first == 192 && second == 168);
  }

  Future<HaInstance?> _probeHost(HttpClient client, String host) async {
    for (final target in const [
      (scheme: 'http', port: 8123),
      (scheme: 'http', port: 80),
      (scheme: 'https', port: 443),
    ]) {
      try {
        final socket = await Socket.connect(
          host,
          target.port,
          timeout: const Duration(milliseconds: 450),
        );
        socket.destroy();
        final request = await client
            .getUrl(Uri.parse('${target.scheme}://$host:${target.port}/'))
            .timeout(const Duration(seconds: 2));
        request.followRedirects = false;
        request.headers.set(HttpHeaders.userAgentHeader, 'HA Finder/1.0');
        final response = await request.close().timeout(
          const Duration(milliseconds: 2500),
        );
        final body = await response
            .transform(utf8.decoder)
            .join()
            .timeout(const Duration(milliseconds: 2500));
        final normalized = body.replaceAll(RegExp(r'\s+'), '').toLowerCase();
        if (normalized.contains('<title>homeassistant</title>') ||
            normalized.contains('application-name"content="homeassistant') ||
            normalized.contains('"message":"apirunning."')) {
          return HaInstance(
            name: 'Home Assistant · $host',
            host: host,
            port: target.port,
            scheme: target.scheme,
          );
        }
        if (target.port == 80 && normalized.contains('knxos')) {
          return HaInstance(
            name: 'Home Assistant 启动中 · knxos${host.split('.').last}',
            host: host,
            port: 8123,
            verified: false,
          );
        }
      } on Object {
        // Unreachable hosts and non-HA services are not matches.
      }
    }
    return null;
  }

  Future<List<HaInstance>> _discoverBootingCandidates(
    Iterable<String> subnets,
  ) async {
    if (!Platform.isWindows && !Platform.isMacOS) return const [];
    final subnetSet = subnets.toSet();
    if (subnetSet.isEmpty) return const [];
    try {
      await _primeNeighborCache(subnetSet);
      final result = Platform.isWindows
          ? await Process.run('arp.exe', const ['-a'])
          : await Process.run('/usr/sbin/arp', const ['-a']);
      if (result.exitCode != 0) return const [];
      final addresses = RegExp(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
          .allMatches(result.stdout.toString())
          .map((match) => match.group(0)!)
          .where((address) {
            final separator = address.lastIndexOf('.');
            final last = separator > 0
                ? int.tryParse(address.substring(separator + 1))
                : null;
            return separator > 0 &&
                last != null &&
                last >= 2 &&
                last <= 254 &&
                subnetSet.contains(address.substring(0, separator));
          })
          .toSet();
      final client = HttpClient()
        ..connectionTimeout = const Duration(milliseconds: 600)
        ..findProxy = ((_) => 'DIRECT');
      final results = await Future.wait(
        addresses.map((address) async {
          String? hostname;
          try {
            final reversed = await InternetAddress(
              address,
            ).reverse().timeout(const Duration(milliseconds: 800));
            if (_isHaosBootHostname(reversed.host)) {
              hostname = _withoutDot(reversed.host);
            }
          } on Object {
            // Fall through to service fingerprinting when reverse DNS fails.
          }
          hostname ??= await _probeBootService(client, address);
          if (hostname == null) return null;
          return HaInstance(
            name: 'Home Assistant 启动中 · $hostname',
            host: address,
            port: 8123,
            verified: false,
          );
        }),
      );
      client.close(force: true);
      return results.whereType<HaInstance>().toList();
    } on Object {
      return const [];
    }
  }

  Future<String?> _probeBootService(HttpClient client, String address) async {
    try {
      final request = await client
          .getUrl(Uri.parse('http://$address:7681/'))
          .timeout(const Duration(milliseconds: 800));
      request.followRedirects = false;
      final response = await request.close().timeout(
        const Duration(milliseconds: 800),
      );
      final socket = await response.detachSocket();
      socket.destroy();
      return 'wghatools${address.split('.').last}';
    } on Object {
      return null;
    }
  }

  Future<void> _primeNeighborCache(Set<String> subnets) async {
    final targets = <String>[
      for (final subnet in subnets)
        for (var last = 2; last < 255; last++) '$subnet.$last',
    ];
    const batchSize = 40;
    for (var start = 0; start < targets.length; start += batchSize) {
      final end = (start + batchSize).clamp(0, targets.length);
      await Future.wait(
        targets.sublist(start, end).map((address) async {
          try {
            if (Platform.isWindows) {
              await Process.run('ping.exe', ['-n', '1', '-w', '300', address]);
            } else {
              await Process.run('/sbin/ping', [
                '-c',
                '1',
                '-W',
                '500',
                address,
              ]);
            }
          } on Object {
            // TCP probing still populates the neighbor table on systems where
            // launching the platform ping utility is unavailable.
          }
        }),
      );
    }
  }

  bool _isHaosBootHostname(String hostname) {
    final normalized = hostname.toLowerCase().replaceAll(
      RegExp(r'[\s._-]+'),
      '',
    );
    return normalized.contains('homeassistant') ||
        normalized.contains('wghatools') ||
        normalized.contains('knxos');
  }

  String _withoutDot(String value) =>
      value.endsWith('.') ? value.substring(0, value.length - 1) : value;
}
