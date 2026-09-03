import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:multicast_dns/multicast_dns.dart';
import 'package:url_launcher/url_launcher.dart';

import 'haos_diagnostic.dart';
import 'home_assistant_discovery.dart' as shared;

void main() => runApp(const HaFinderApp());

class HaFinderApp extends StatelessWidget {
  const HaFinderApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'HA Finder',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff0796d2)),
      scaffoldBackgroundColor: const Color(0xfff5f8fa),
      useMaterial3: true,
    ),
    home: const FinderPage(),
  );
}

class HaInstance {
  const HaInstance({
    required this.name,
    required this.host,
    required this.port,
    this.scheme = 'http',
  });

  final String name;
  final String host;
  final int port;
  final String scheme;
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
            // Windows Winsock does not support SO_REUSEPORT and reports
            // WSAENOPROTOOPT (10042) when multicast_dns enables it.
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
      // Enhanced discovery is the fallback path: an mDNS failure must not
      // prevent the subnet probe from running, especially on Windows.
      discovered = const [];
    }
    final subnets = await _localSubnets();
    final targets = <String>[];
    for (final subnet in subnets.take(3)) {
      for (var last = 1; last < 255; last++) {
        targets.add('$subnet.$last');
      }
    }

    final client = HttpClient()
      ..connectionTimeout = const Duration(milliseconds: 450)
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

    final merged = <String, HaInstance>{};
    // Prefer the richer mDNS name when both methods find the same instance.
    for (final instance in [...scanned, ...discovered]) {
      merged['${instance.host}:${instance.port}'] = instance;
    }
    return merged.values.toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
  }

  Future<Set<String>> _localSubnets() async {
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
      } on Object {
        // An unreachable host or non-HA service is simply not a match.
      }
    }
    return null;
  }

  String _withoutDot(String value) =>
      value.endsWith('.') ? value.substring(0, value.length - 1) : value;
}

class FinderPage extends StatefulWidget {
  const FinderPage({super.key});

  @override
  State<FinderPage> createState() => _FinderPageState();
}

class _FinderPageState extends State<FinderPage> {
  final _discovery = shared.HomeAssistantDiscovery();
  List<shared.HaInstance> _instances = const [];
  bool _searching = false;
  bool _enhanced = false;
  String? _progress;
  String? _resultMessage;
  bool _resultSuccess = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    scheduleMicrotask(_refresh);
  }

  Future<void> _refresh() async {
    if (_searching) return;
    setState(() {
      _searching = true;
      _enhanced = false;
      _progress = null;
      _resultMessage = null;
      _error = null;
    });
    try {
      final instances = await _discovery.discover();
      if (mounted) {
        setState(() {
          _instances = instances;
          _resultSuccess = instances.isNotEmpty;
          _resultMessage = instances.isEmpty
              ? '搜索完成：没有发现 Home Assistant'
              : '搜索完成：发现 ${instances.length} 个服务器';
        });
      }
    } on Object catch (error) {
      if (mounted) setState(() => _error = '搜索失败：$error');
    } finally {
      if (mounted) setState(() => _searching = false);
    }
  }

  Future<void> _enhancedRefresh() async {
    if (_searching) return;
    setState(() {
      _searching = true;
      _enhanced = true;
      _progress = '先进行 mDNS 搜索…';
      _resultMessage = null;
      _error = null;
    });
    try {
      final existing = _instances;
      final instances = await _discovery.discoverEnhanced(
        onProgress: (checked, total) {
          if (!mounted) return;
          setState(() => _progress = '正在探测局域网：$checked / $total');
        },
      );
      final merged = <String, shared.HaInstance>{};
      for (final instance in [...instances, ...existing]) {
        final key = '${instance.host}:${instance.port}';
        final current = merged[key];
        if (current == null || instance.verified || !current.verified) {
          merged[key] = instance;
        }
      }
      if (mounted) {
        setState(() {
          _instances = merged.values.toList()
            ..sort(
              (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
            );
          final added = _instances.length - existing.length;
          _resultSuccess = _instances.isNotEmpty;
          if (_instances.isEmpty) {
            _resultMessage = '加强搜索完成：没有发现 Home Assistant';
          } else if (added > 0) {
            _resultMessage = '加强搜索完成：发现 ${_instances.length} 个服务器，新增 $added 个';
          } else {
            _resultMessage = '加强搜索完成：没有发现新服务器，已保留现有 ${_instances.length} 个';
          }
        });
      }
    } on Object catch (error) {
      if (mounted) setState(() => _error = '加强搜索失败：$error');
    } finally {
      if (mounted) {
        setState(() {
          _searching = false;
          _enhanced = false;
          _progress = null;
        });
      }
    }
  }

  void _clear() {
    if (_searching) return;
    setState(() {
      _instances = const [];
      _error = null;
      _progress = null;
      _resultSuccess = false;
      _resultMessage = '列表已清空';
    });
  }

  Future<void> _open(shared.HaInstance instance) async {
    if (!instance.verified) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('已发现 HAOS，但 Home Assistant 服务仍在启动，请稍后再次加强搜索。'),
          ),
        );
      }
      return;
    }
    final opened = await launchUrl(
      Uri.parse(instance.url),
      mode: LaunchMode.externalApplication,
    );
    if (!opened && mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('无法打开 ${instance.url}')));
    }
  }

  Future<void> _copy(shared.HaInstance instance) async {
    await Clipboard.setData(ClipboardData(text: instance.url));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('已复制 ${instance.url}'),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    floatingActionButton: FloatingActionButton.extended(
      onPressed: () => showHaosDiagnostic(context),
      icon: const Icon(Icons.cable_rounded),
      label: const Text('HAOS 诊断助手'),
    ),
    body: SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 860),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(32, 28, 32, 32),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _Header(
                  searching: _searching,
                  enhanced: _enhanced,
                  onRefresh: _refresh,
                  onEnhancedRefresh: _enhancedRefresh,
                  onClear: _clear,
                  canClear: _instances.isNotEmpty,
                ),
                const SizedBox(height: 14),
                if (_progress != null || _resultMessage != null)
                  _SearchNotice(
                    message: _progress ?? _resultMessage!,
                    searching: _progress != null,
                    success: _resultSuccess,
                  ),
                const SizedBox(height: 18),
                Expanded(child: _content()),
              ],
            ),
          ),
        ),
      ),
    ),
  );

  Widget _content() {
    if (_searching && _instances.isEmpty) {
      return _MessageState(
        icon: Icons.radar_rounded,
        title: '正在搜索局域网',
        subtitle: _progress ?? '正在查找 Home Assistant 服务…',
        loading: true,
      );
    }
    if (_error != null && _instances.isEmpty) {
      return _MessageState(
        icon: Icons.wifi_off_rounded,
        title: '无法完成搜索',
        subtitle: _error!,
      );
    }
    if (_instances.isEmpty) {
      return const _MessageState(
        icon: Icons.search_off_rounded,
        title: '没有发现 Home Assistant',
        subtitle: '请确认电脑和服务器连接到同一个局域网，然后再次刷新。',
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          '发现 ${_instances.length} 个服务器',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            color: const Color(0xff52636d),
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 12),
        Expanded(
          child: ListView.separated(
            itemCount: _instances.length,
            separatorBuilder: (_, _) => const SizedBox(height: 12),
            itemBuilder: (_, index) {
              final instance = _instances[index];
              return _ServerCard(
                instance: instance,
                onOpen: () => _open(instance),
                onCopy: () => _copy(instance),
              );
            },
          ),
        ),
      ],
    );
  }
}

class _Header extends StatelessWidget {
  const _Header({
    required this.searching,
    required this.enhanced,
    required this.onRefresh,
    required this.onEnhancedRefresh,
    required this.onClear,
    required this.canClear,
  });
  final bool searching;
  final bool enhanced;
  final VoidCallback onRefresh;
  final VoidCallback onEnhancedRefresh;
  final VoidCallback onClear;
  final bool canClear;

  @override
  Widget build(BuildContext context) => Row(
    children: [
      ClipRRect(
        borderRadius: BorderRadius.circular(14),
        child: Image.asset(
          'assets/images/ha_finder_logo_rounded.png',
          width: 64,
          height: 64,
          fit: BoxFit.cover,
        ),
      ),
      const SizedBox(width: 16),
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'HA Finder',
              style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                fontWeight: FontWeight.w800,
                color: const Color(0xff16313f),
              ),
            ),
            const SizedBox(height: 3),
            Text(
              '查找局域网中的 Home Assistant',
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: const Color(0xff6a7d87)),
            ),
          ],
        ),
      ),
      OutlinedButton.icon(
        onPressed: searching ? null : onEnhancedRefresh,
        icon: const Icon(Icons.manage_search_rounded),
        label: Text(enhanced ? '加强搜索中' : '加强搜索'),
      ),
      const SizedBox(width: 10),
      TextButton.icon(
        onPressed: searching || !canClear ? null : onClear,
        icon: const Icon(Icons.delete_outline_rounded),
        label: const Text('清空'),
      ),
      const SizedBox(width: 10),
      FilledButton.icon(
        onPressed: searching ? null : onRefresh,
        icon: searching
            ? const SizedBox.square(
                dimension: 18,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : const Icon(Icons.refresh_rounded),
        label: Text(searching ? '搜索中' : '刷新'),
      ),
    ],
  );
}

class _SearchNotice extends StatelessWidget {
  const _SearchNotice({
    required this.message,
    required this.searching,
    required this.success,
  });

  final String message;
  final bool searching;
  final bool success;

  @override
  Widget build(BuildContext context) {
    final color = searching
        ? const Color(0xff1e789c)
        : success
        ? const Color(0xff287a4b)
        : const Color(0xff687b85);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.09),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.22)),
      ),
      child: Row(
        children: [
          if (searching)
            SizedBox.square(
              dimension: 17,
              child: CircularProgressIndicator(strokeWidth: 2, color: color),
            )
          else
            Icon(
              success ? Icons.check_circle_outline : Icons.info_outline,
              size: 19,
              color: color,
            ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: TextStyle(color: color, fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }
}

class _ServerCard extends StatelessWidget {
  const _ServerCard({
    required this.instance,
    required this.onOpen,
    required this.onCopy,
  });
  final shared.HaInstance instance;
  final VoidCallback onOpen;
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) => Material(
    color: Colors.white,
    borderRadius: BorderRadius.circular(18),
    clipBehavior: Clip.antiAlias,
    child: InkWell(
      onTap: instance.verified ? onOpen : null,
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Row(
          children: [
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: const Color(0xffe7f6fc),
                borderRadius: BorderRadius.circular(14),
              ),
              child: const Icon(Icons.home_rounded, color: Color(0xff0796d2)),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    instance.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                      color: const Color(0xff203943),
                    ),
                  ),
                  if (!instance.verified) ...[
                    const SizedBox(height: 4),
                    const Text(
                      '网络已上线，等待 8123 服务启动',
                      style: TextStyle(
                        color: Color(0xffa36b00),
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                  const SizedBox(height: 4),
                  SelectableText(
                    instance.url,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: const Color(0xff687b85),
                    ),
                  ),
                ],
              ),
            ),
            Tooltip(
              message: '复制地址',
              child: IconButton(
                onPressed: onCopy,
                icon: const Icon(Icons.copy_rounded),
              ),
            ),
            const SizedBox(width: 4),
            FilledButton.icon(
              onPressed: instance.verified ? onOpen : null,
              icon: Icon(
                instance.verified
                    ? Icons.open_in_new_rounded
                    : Icons.hourglass_top_rounded,
                size: 18,
              ),
              label: Text(instance.verified ? '打开' : '启动中'),
            ),
          ],
        ),
      ),
    ),
  );
}

class _MessageState extends StatelessWidget {
  const _MessageState({
    required this.icon,
    required this.title,
    required this.subtitle,
    this.loading = false,
  });
  final IconData icon;
  final String title;
  final String subtitle;
  final bool loading;

  @override
  Widget build(BuildContext context) => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (loading)
          const CircularProgressIndicator()
        else
          Icon(icon, size: 58, color: const Color(0xff88a0ab)),
        const SizedBox(height: 20),
        Text(
          title,
          style: Theme.of(context).textTheme.titleLarge?.copyWith(
            fontWeight: FontWeight.w700,
            color: const Color(0xff38515d),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          subtitle,
          textAlign: TextAlign.center,
          style: Theme.of(
            context,
          ).textTheme.bodyMedium?.copyWith(color: const Color(0xff758892)),
        ),
      ],
    ),
  );
}
