import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import 'home_assistant_discovery.dart';

class DiagnosticAdapter {
  const DiagnosticAdapter({
    required this.name,
    required this.description,
    required this.index,
    required this.speed,
  });

  final String name;
  final String description;
  final int index;
  final String speed;

  factory DiagnosticAdapter.fromJson(Map<String, dynamic> json) {
    return DiagnosticAdapter(
      name: json['Name']?.toString() ?? 'Ethernet',
      description: json['InterfaceDescription']?.toString() ?? '',
      index: int.tryParse(json['ifIndex']?.toString() ?? '') ?? 0,
      speed: json['LinkSpeed']?.toString() ?? '',
    );
  }
}

class DiagnosticSnapshot {
  const DiagnosticSnapshot({
    required this.stage,
    required this.message,
    this.serverIp,
    this.deviceIp,
    this.mac,
    this.hostname,
  });

  final String stage;
  final String message;
  final String? serverIp;
  final String? deviceIp;
  final String? mac;
  final String? hostname;

  factory DiagnosticSnapshot.fromJson(Map<String, dynamic> json) {
    return DiagnosticSnapshot(
      stage: json['stage']?.toString() ?? 'starting',
      message: json['message']?.toString() ?? '正在启动诊断…',
      serverIp: json['serverIp']?.toString(),
      deviceIp: json['deviceIp']?.toString(),
      mac: json['mac']?.toString(),
      hostname: json['hostname']?.toString(),
    );
  }
}

class HaosDiagnosticController extends ChangeNotifier {
  List<DiagnosticAdapter> adapters = const [];
  DiagnosticAdapter? selectedAdapter;
  DiagnosticSnapshot snapshot = const DiagnosticSnapshot(
    stage: 'idle',
    message: '请选择连接 HAOS 的有线网卡。',
  );
  bool loadingAdapters = false;
  bool running = false;
  bool haReady = false;
  HaInstance? detectedInstance;
  HaInstance? verifiedInstance;
  String? error;
  Timer? _pollTimer;
  Timer? _haProbeTimer;
  bool _discoveryRunning = false;
  bool _cancelRequested = false;
  final HomeAssistantDiscovery _discovery = HomeAssistantDiscovery();

  Directory get _sessionDirectory => Directory(
    '${Directory.systemTemp.path}${Platform.pathSeparator}ha_finder_diagnostic',
  );
  File get _stateFile =>
      File('${_sessionDirectory.path}${Platform.pathSeparator}state.json');
  File get _stopFile =>
      File('${_sessionDirectory.path}${Platform.pathSeparator}stop.request');
  File get _logFile =>
      File('${_sessionDirectory.path}${Platform.pathSeparator}diagnostic.log');
  File get _foundFile =>
      File('${_sessionDirectory.path}${Platform.pathSeparator}device.found');

  String? get deviceIp =>
      verifiedInstance?.host ?? detectedInstance?.host ?? snapshot.deviceIp;

  Future<void> _appendLog(String message) async {
    await _sessionDirectory.create(recursive: true);
    await _logFile.writeAsString(
      '${DateTime.now().toIso8601String()} [APP] $message\n',
      mode: FileMode.append,
      flush: true,
    );
  }

  Future<void> loadAdapters() async {
    if (!Platform.isWindows && !Platform.isMacOS) return;
    loadingAdapters = true;
    error = null;
    _cancelRequested = false;
    notifyListeners();
    try {
      if (Platform.isMacOS) {
        await _loadMacAdapters();
        return;
      }
      const command = r'''Get-NetAdapter -Physical |
Where-Object {
  $_.Status -eq 'Up' -and
  ($_.PhysicalMediaType -eq '802.3' -or $_.InterfaceDescription -match 'Ethernet|GbE|LAN')
} |
Select-Object Name,InterfaceDescription,ifIndex,LinkSpeed |
ConvertTo-Json -Compress''';
      final result = await Process.run('powershell.exe', const [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        command,
      ], runInShell: false);
      if (result.exitCode != 0) {
        throw Exception(result.stderr.toString().trim());
      }
      final text = result.stdout.toString().trim();
      if (text.isEmpty) {
        adapters = const [];
      } else {
        final decoded = jsonDecode(text);
        final items = decoded is List ? decoded : [decoded];
        adapters = items
            .whereType<Map>()
            .map(
              (item) =>
                  DiagnosticAdapter.fromJson(Map<String, dynamic>.from(item)),
            )
            .where((adapter) => adapter.index > 0)
            .toList();
      }
      selectedAdapter = adapters.length == 1 ? adapters.first : null;
      if (adapters.isEmpty) {
        error = '未检测到已连接的物理有线网卡。请插入网线后重新检测。';
      }
    } on Object catch (caught) {
      error = '读取网卡失败：$caught';
    } finally {
      loadingAdapters = false;
      notifyListeners();
    }
  }

  Future<void> _loadMacAdapters() async {
    final previousDevice = selectedAdapter?.name;
    final result = await Process.run('/usr/sbin/networksetup', const [
      '-listallhardwareports',
    ]);
    if (result.exitCode != 0) {
      throw Exception(result.stderr.toString().trim());
    }
    final blocks = result.stdout.toString().split(RegExp(r'\n\s*\n'));
    final found = <DiagnosticAdapter>[];
    for (final block in blocks) {
      final port = RegExp(r'Hardware Port:\s*(.+)').firstMatch(block)?.group(1);
      final device = RegExp(r'Device:\s*(\S+)').firstMatch(block)?.group(1);
      if (port == null || device == null) continue;
      final lower = port.toLowerCase();
      if (!lower.contains('ethernet') &&
          !lower.contains('lan') &&
          !lower.contains('usb')) {
        continue;
      }
      var speed = '';
      final details = await Process.run('/sbin/ifconfig', [device]);
      final media = RegExp(
        r'media:\s*([^\n]+)',
      ).firstMatch(details.stdout.toString())?.group(1);
      if (media != null) speed = media.trim();
      found.add(
        DiagnosticAdapter(
          name: device,
          description: port.trim(),
          index: found.length + 1,
          speed: speed,
        ),
      );
    }
    adapters = found;
    final previousMatches = adapters
        .where((adapter) => adapter.name == previousDevice)
        .toList();
    if (previousMatches.isNotEmpty &&
        _macAdapterScore(previousMatches.first) > 0) {
      selectedAdapter = previousMatches.first;
    } else {
      final connected = [...adapters]
        ..sort(
          (left, right) =>
              _macAdapterScore(right).compareTo(_macAdapterScore(left)),
        );
      selectedAdapter =
          connected.isNotEmpty && _macAdapterScore(connected.first) > 0
          ? connected.first
          : adapters.length == 1
          ? adapters.first
          : null;
    }
    if (adapters.isEmpty) {
      error = '未检测到有线网卡。请连接 USB/雷雳转网口后重新检测。';
    }
  }

  int _macAdapterScore(DiagnosticAdapter adapter) {
    final media = adapter.speed.toLowerCase();
    if (media.isEmpty ||
        media == 'none' ||
        media.contains('status: inactive')) {
      return 0;
    }
    if (media.contains('10000base') || media.contains('10gbase')) return 10000;
    if (media.contains('5000base') || media.contains('5gbase')) return 5000;
    if (media.contains('2500base') || media.contains('2.5gbase')) return 2500;
    if (media.contains('1000base')) return 1000;
    if (media.contains('100base')) return 100;
    if (media.contains('10base')) return 10;
    return media.contains('base') ? 1 : 0;
  }

  void selectAdapter(DiagnosticAdapter? adapter) {
    selectedAdapter = adapter;
    notifyListeners();
  }

  Future<void> start() async {
    final adapter = selectedAdapter;
    if ((!Platform.isWindows && !Platform.isMacOS) ||
        adapter == null ||
        running) {
      return;
    }
    error = null;
    haReady = false;
    detectedInstance = null;
    verifiedInstance = null;
    running = true;
    snapshot = DiagnosticSnapshot(
      stage: 'authorization',
      message: Platform.isMacOS
          ? '请在 macOS 授权窗口中输入管理员密码…'
          : '请在 Windows 管理员授权窗口中选择“是”…',
    );
    notifyListeners();

    try {
      if (await _sessionDirectory.exists()) {
        await _sessionDirectory.delete(recursive: true);
      }
      await _sessionDirectory.create(recursive: true);
      await _appendLog('开始诊断，网卡=${adapter.name}，ifIndex=${adapter.index}');
      if (Platform.isMacOS) {
        await _startMacHelper(adapter);
        return;
      }
      final executableDirectory = File(Platform.resolvedExecutable).parent.path;
      final helper = '$executableDirectory\\haos_diagnostic_helper.exe';
      if (!await File(helper).exists()) {
        throw Exception('没有找到 Windows 诊断 Helper，请重新安装最新版 HA Finder。');
      }

      final escapedHelper = helper.replaceAll("'", "''");
      final escapedState = _stateFile.path.replaceAll("'", "''");
      final escapedStop = _stopFile.path.replaceAll("'", "''");
      final escapedLog = _logFile.path.replaceAll("'", "''");
      final escapedFound = _foundFile.path.replaceAll("'", "''");
      final arguments = <String>[
        '--adapter-index',
        '${adapter.index}',
        '--state',
        '"$escapedState"',
        '--stop',
        '"$escapedStop"',
        '--log',
        '"$escapedLog"',
        '--found',
        '"$escapedFound"',
        '--parent-pid',
        '$pid',
      ].join(' ');
      final isAdministrator = await _isRunningAsAdministrator();
      await _appendLog('主程序管理员权限=$isAdministrator');
      if (_cancelRequested) return;
      final script = isAdministrator
          ? "Start-Process -FilePath '$escapedHelper' -ArgumentList '$arguments'"
          : "Start-Process -FilePath '$escapedHelper' -ArgumentList '$arguments' -Verb RunAs";
      final result = await Process.run('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        script,
      ]);
      if (result.exitCode != 0) {
        await _appendLog(
          'Helper 启动失败 exitCode=${result.exitCode} stderr=${result.stderr}',
        );
        throw Exception('管理员授权被取消或 Helper 无法启动。');
      }
      if (_cancelRequested) {
        await _stopFile.writeAsString('stop', flush: true);
        return;
      }
      _pollTimer = Timer.periodic(
        const Duration(milliseconds: 600),
        (_) => unawaited(_pollState()),
      );
    } on Object catch (caught) {
      running = false;
      error = '$caught';
      unawaited(_appendLog('启动异常：$caught'));
      snapshot = const DiagnosticSnapshot(stage: 'error', message: '诊断模式启动失败。');
      notifyListeners();
    }
  }

  String _shellQuote(String value) => "'${value.replaceAll("'", "'\\''")}'";

  String _appleScriptQuote(String value) =>
      '"${value.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

  Future<void> _startMacHelper(DiagnosticAdapter adapter) async {
    final executableDirectory = File(Platform.resolvedExecutable).parent;
    final helper = File(
      '${executableDirectory.parent.path}/Helpers/haos_diagnostic_helper',
    );
    if (!await helper.exists()) {
      throw Exception('没有找到 macOS 诊断 Helper，请重新安装最新版 HA Finder。');
    }
    final command = <String>[
      _shellQuote(helper.path),
      '--interface',
      _shellQuote(adapter.name),
      '--state',
      _shellQuote(_stateFile.path),
      '--stop',
      _shellQuote(_stopFile.path),
      '--log',
      _shellQuote(_logFile.path),
      '--found',
      _shellQuote(_foundFile.path),
      '--parent-pid',
      '$pid',
      '</dev/null >/dev/null 2>&1 &',
    ].join(' ');
    final script =
        'do shell script ${_appleScriptQuote(command)} with administrator privileges';
    final result = await Process.run('/usr/bin/osascript', ['-e', script]);
    if (result.exitCode != 0) {
      await _appendLog(
        'macOS Helper 授权或启动失败：${result.stderr.toString().trim()}',
      );
      throw Exception('管理员授权被取消或 macOS Helper 无法启动。');
    }
    if (_cancelRequested) {
      await _stopFile.writeAsString('stop', flush: true);
      return;
    }
    _pollTimer = Timer.periodic(
      const Duration(milliseconds: 600),
      (_) => unawaited(_pollState()),
    );
  }

  Future<void> _pollState() async {
    try {
      if (!await _stateFile.exists()) return;
      final decoded = jsonDecode(await _stateFile.readAsString());
      if (decoded is! Map) return;
      snapshot = DiagnosticSnapshot.fromJson(
        Map<String, dynamic>.from(decoded),
      );
      if (snapshot.serverIp != null &&
          (snapshot.stage == 'configuring' ||
              snapshot.stage == 'waiting_dhcp' ||
              snapshot.stage == 'leased')) {
        _startHaProbe();
      }
      if (snapshot.stage == 'stopped' || snapshot.stage == 'error') {
        running = false;
        _pollTimer?.cancel();
      }
      if (snapshot.stage == 'error') error = snapshot.message;
      notifyListeners();
    } on Object {
      // The helper replaces the JSON file atomically; retry on the next tick.
    }
  }

  Future<bool> _isRunningAsAdministrator() async {
    const command =
        r'''$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)''';
    final result = await Process.run('powershell.exe', const [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      command,
    ]);
    return result.exitCode == 0 &&
        result.stdout.toString().trim().toLowerCase() == 'true';
  }

  Future<String> readLog() async {
    if (!await _logFile.exists()) return '尚未生成诊断日志。';
    return _logFile.readAsString();
  }

  void _startHaProbe() {
    if (_haProbeTimer != null || haReady) return;
    unawaited(_discoverHa());
    _haProbeTimer = Timer.periodic(
      const Duration(seconds: 8),
      (_) => unawaited(_discoverHa()),
    );
  }

  Future<void> _discoverHa() async {
    if (_discoveryRunning || haReady) return;
    _discoveryRunning = true;
    try {
      HaInstance? instance;
      final targetAddress = snapshot.deviceIp ?? detectedInstance?.host;
      if (targetAddress != null) {
        instance = await _discovery.probeDiagnosticHost(targetAddress);
      }
      final subnet = _diagnosticSubnet();
      if (instance == null && subnet != null) {
        final instances = await _discovery.discoverDiagnosticSubnet(subnet);
        if (instances.isNotEmpty) instance = instances.first;
      }
      if (instance != null) {
        final previous = detectedInstance;
        detectedInstance = instance;
        if (instance.verified) {
          verifiedInstance = instance;
          haReady = true;
          await _foundFile.writeAsString(instance.host, flush: true);
          await _appendLog('已验证 Home Assistant 8123 服务：${instance.url}');
          _haProbeTimer?.cancel();
          _haProbeTimer = null;
        } else if (previous?.host != instance.host ||
            previous?.verified == true) {
          await _appendLog(
            '已发现 HAOS 网络特征：${instance.name} (${instance.host})，继续等待 8123 服务',
          );
        }
        notifyListeners();
      }
    } on Object {
      // The next discovery pass retries mDNS and enhanced subnet scanning.
    } finally {
      _discoveryRunning = false;
    }
  }

  String? _diagnosticSubnet() {
    final server = snapshot.serverIp;
    if (server == null) return null;
    final separator = server.lastIndexOf('.');
    if (separator < 0) return null;
    return server.substring(0, separator);
  }

  Future<void> openHa() async {
    final instance = verifiedInstance;
    if (instance == null) return;
    await launchUrl(
      Uri.parse(instance.url),
      mode: LaunchMode.externalApplication,
    );
  }

  Future<void> stop() async {
    if (!running) return;
    _cancelRequested = true;
    snapshot = DiagnosticSnapshot(
      stage: 'stopping',
      message: '正在停止 DHCP 并恢复网卡设置…',
      serverIp: snapshot.serverIp,
      deviceIp: snapshot.deviceIp,
      mac: snapshot.mac,
      hostname: snapshot.hostname,
    );
    notifyListeners();
    await _stopFile.writeAsString('stop');
    for (var attempt = 0; attempt < 10 && running; attempt++) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      await _pollState();
    }
    if (running) {
      running = false;
      error = '停止请求已发送，后台正在完成网络清理。';
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _haProbeTimer?.cancel();
    if (running) unawaited(_stopFile.writeAsString('stop'));
    super.dispose();
  }
}

Future<void> showHaosDiagnostic(BuildContext context) async {
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (_) => const HaosDiagnosticDialog(),
  );
}

class HaosDiagnosticDialog extends StatefulWidget {
  const HaosDiagnosticDialog({super.key});

  @override
  State<HaosDiagnosticDialog> createState() => _HaosDiagnosticDialogState();
}

class _HaosDiagnosticDialogState extends State<HaosDiagnosticDialog> {
  late final HaosDiagnosticController controller;

  @override
  void initState() {
    super.initState();
    controller = HaosDiagnosticController()..addListener(_update);
    unawaited(controller.loadAdapters());
  }

  void _update() {
    if (mounted) setState(() {});
  }

  Future<void> _close() async {
    if (controller.running) await controller.stop();
    if (mounted) Navigator.of(context).pop();
  }

  @override
  void dispose() {
    controller.removeListener(_update);
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: !controller.running,
      child: Dialog(
        insetPadding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 660, minHeight: 540),
          child: Padding(
            padding: const EdgeInsets.all(26),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Container(
                      width: 48,
                      height: 48,
                      decoration: BoxDecoration(
                        color: const Color(0xffe7f6fc),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: const Icon(
                        Icons.cable_rounded,
                        color: Color(0xff0796d2),
                      ),
                    ),
                    const SizedBox(width: 14),
                    const Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'HAOS 诊断助手',
                            style: TextStyle(
                              fontSize: 22,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          Text(
                            'HAOS Direct Diagnostic',
                            style: TextStyle(color: Color(0xff71838c)),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      onPressed: _close,
                      icon: const Icon(Icons.close),
                    ),
                  ],
                ),
                const SizedBox(height: 22),
                if (!Platform.isWindows && !Platform.isMacOS) ...[
                  const _InfoBox(
                    icon: Icons.info_outline,
                    text:
                        '界面已支持 macOS；创建直连 DHCP 网络的功能将在下一阶段通过 macOS Privileged Helper 提供。',
                  ),
                ] else ...[
                  const _InfoBox(
                    icon: Icons.warning_amber_rounded,
                    text:
                        '请先用网线将电脑与 HAOS 直连。开始后会申请管理员权限、添加临时 IP 并启动 DHCP；停止或退出时自动清理。',
                  ),
                  const SizedBox(height: 18),
                  _adapterSelector(),
                  const SizedBox(height: 20),
                  _statusPanel(),
                  if (controller.error != null) ...[
                    const SizedBox(height: 12),
                    Text(
                      controller.error!,
                      style: const TextStyle(color: Colors.red),
                    ),
                  ],
                  const SizedBox(height: 22),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: _showLog,
                        style: TextButton.styleFrom(
                          foregroundColor: const Color(0xff82949d),
                        ),
                        child: const Text('查看诊断日志'),
                      ),
                      const Spacer(),
                      if (controller.running)
                        OutlinedButton.icon(
                          onPressed: controller.stop,
                          icon: const Icon(Icons.stop_circle_outlined),
                          label: const Text('停止并恢复网络'),
                        )
                      else
                        OutlinedButton.icon(
                          onPressed: controller.loadAdapters,
                          icon: const Icon(Icons.refresh),
                          label: const Text('重新检测网卡'),
                        ),
                      const SizedBox(width: 10),
                      if (controller.haReady)
                        FilledButton.icon(
                          onPressed: controller.openHa,
                          icon: const Icon(Icons.open_in_new),
                          label: const Text('打开 HAOS'),
                        )
                      else
                        FilledButton.icon(
                          onPressed:
                              !controller.running &&
                                  controller.selectedAdapter != null
                              ? controller.start
                              : null,
                          icon: const Icon(Icons.play_arrow_rounded),
                          label: const Text('开始诊断'),
                        ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _showLog() async {
    final log = await controller.readLog();
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('诊断日志'),
        content: SizedBox(
          width: 720,
          height: 420,
          child: SelectionArea(
            child: SingleChildScrollView(
              child: Text(
                log,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: log));
              if (context.mounted) Navigator.of(context).pop();
            },
            child: const Text('复制日志'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }

  Widget _adapterSelector() {
    if (controller.loadingAdapters) {
      return const LinearProgressIndicator();
    }
    return InputDecorator(
      decoration: const InputDecoration(
        labelText: '连接 HAOS 的有线网卡',
        border: OutlineInputBorder(),
        prefixIcon: Icon(Icons.settings_ethernet),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<DiagnosticAdapter>(
          value: controller.selectedAdapter,
          isDense: true,
          isExpanded: true,
          hint: const Text('请选择有线网卡'),
          items: controller.adapters
              .map(
                (adapter) => DropdownMenuItem(
                  value: adapter,
                  child: Text('${adapter.name}  ${adapter.speed}'),
                ),
              )
              .toList(),
          onChanged: controller.running ? null : controller.selectAdapter,
        ),
      ),
    );
  }

  Widget _statusPanel() {
    final stage = controller.snapshot.stage;
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: const Color(0xfff6f9fa),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Column(
        children: [
          _StatusRow(
            label: '诊断网络',
            value: controller.snapshot.serverIp ?? _stageText(stage),
            active:
                stage != 'idle' &&
                stage != 'authorization' &&
                stage != 'error' &&
                stage != 'stopped',
          ),
          const Divider(height: 24),
          _StatusRow(
            label: 'DHCP / HAOS',
            value:
                controller.deviceIp ??
                (stage == 'waiting_dhcp' ? '等待设备请求 IP…' : '尚未分配地址'),
            active: controller.deviceIp != null,
          ),
          const Divider(height: 24),
          _StatusRow(
            label: 'Home Assistant',
            value: controller.haReady
                ? '${controller.verifiedInstance?.port ?? ''} 服务正常'
                : controller.detectedInstance != null
                ? 'HAOS 已发现，等待 8123 服务启动…'
                : controller.deviceIp != null
                ? 'HAOS 已联网，正在检测 8123…'
                : '等待发现设备',
            active: controller.haReady,
          ),
          if (controller.snapshot.mac != null) ...[
            const Divider(height: 24),
            _StatusRow(
              label: '设备信息',
              value:
                  '${controller.snapshot.hostname ?? '未知设备'} · ${controller.snapshot.mac}',
              active: true,
            ),
          ],
        ],
      ),
    );
  }

  String _stageText(String stage) => switch (stage) {
    'authorization' => '等待管理员授权',
    'configuring' => '正在配置临时网络…',
    'waiting_dhcp' => '网络已建立',
    'stopping' => '正在恢复网络…',
    'stopped' => '已停止并恢复',
    'error' => '建立失败',
    _ => '尚未建立',
  };
}

class _InfoBox extends StatelessWidget {
  const _InfoBox({required this.icon, required this.text});
  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: const Color(0xfffff8e6),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: const Color(0xffffd978)),
    ),
    child: Row(
      children: [
        Icon(icon, color: const Color(0xff9b6a00)),
        const SizedBox(width: 12),
        Expanded(child: Text(text)),
      ],
    ),
  );
}

class _StatusRow extends StatelessWidget {
  const _StatusRow({
    required this.label,
    required this.value,
    required this.active,
  });
  final String label;
  final String value;
  final bool active;

  @override
  Widget build(BuildContext context) => Row(
    children: [
      Icon(
        active ? Icons.check_circle : Icons.radio_button_unchecked,
        size: 20,
        color: active ? const Color(0xff2b8a57) : const Color(0xff90a1a9),
      ),
      const SizedBox(width: 10),
      SizedBox(
        width: 128,
        child: Text(label, style: const TextStyle(fontWeight: FontWeight.w600)),
      ),
      Expanded(child: Text(value, textAlign: TextAlign.right)),
    ],
  );
}
