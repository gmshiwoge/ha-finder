import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

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
  String? error;
  Timer? _pollTimer;
  Timer? _haProbeTimer;

  Directory get _sessionDirectory => Directory(
    '${Directory.systemTemp.path}${Platform.pathSeparator}ha_finder_diagnostic',
  );
  File get _stateFile =>
      File('${_sessionDirectory.path}${Platform.pathSeparator}state.json');
  File get _stopFile =>
      File('${_sessionDirectory.path}${Platform.pathSeparator}stop.request');

  Future<void> loadAdapters() async {
    if (!Platform.isWindows) return;
    loadingAdapters = true;
    error = null;
    notifyListeners();
    try {
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

  void selectAdapter(DiagnosticAdapter? adapter) {
    selectedAdapter = adapter;
    notifyListeners();
  }

  Future<void> start() async {
    final adapter = selectedAdapter;
    if (!Platform.isWindows || adapter == null || running) return;
    error = null;
    haReady = false;
    running = true;
    snapshot = const DiagnosticSnapshot(
      stage: 'authorization',
      message: '请在 Windows 管理员授权窗口中选择“是”…',
    );
    notifyListeners();

    try {
      if (await _sessionDirectory.exists()) {
        await _sessionDirectory.delete(recursive: true);
      }
      await _sessionDirectory.create(recursive: true);
      final executableDirectory = File(Platform.resolvedExecutable).parent.path;
      final helper = '$executableDirectory\\haos_diagnostic_helper.exe';
      if (!await File(helper).exists()) {
        throw Exception('没有找到 Windows 诊断 Helper，请重新安装最新版 HA Finder。');
      }

      final escapedHelper = helper.replaceAll("'", "''");
      final escapedState = _stateFile.path.replaceAll("'", "''");
      final escapedStop = _stopFile.path.replaceAll("'", "''");
      final arguments = <String>[
        '--adapter-index',
        '${adapter.index}',
        '--state',
        '"$escapedState"',
        '--stop',
        '"$escapedStop"',
        '--parent-pid',
        '$pid',
      ].join(' ');
      final script =
          "Start-Process -FilePath '$escapedHelper' -ArgumentList '$arguments' -Verb RunAs";
      final result = await Process.run('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        script,
      ]);
      if (result.exitCode != 0) {
        throw Exception('管理员授权被取消或 Helper 无法启动。');
      }
      _pollTimer = Timer.periodic(
        const Duration(milliseconds: 600),
        (_) => unawaited(_pollState()),
      );
    } on Object catch (caught) {
      running = false;
      error = '$caught';
      snapshot = const DiagnosticSnapshot(stage: 'error', message: '诊断模式启动失败。');
      notifyListeners();
    }
  }

  Future<void> _pollState() async {
    try {
      if (!await _stateFile.exists()) return;
      final decoded = jsonDecode(await _stateFile.readAsString());
      if (decoded is! Map) return;
      snapshot = DiagnosticSnapshot.fromJson(
        Map<String, dynamic>.from(decoded),
      );
      if (snapshot.stage == 'leased' && snapshot.deviceIp != null) {
        _startHaProbe();
      }
      if (snapshot.stage == 'stopped' || snapshot.stage == 'error') {
        running = false;
        _pollTimer?.cancel();
      }
      notifyListeners();
    } on Object {
      // The helper replaces the JSON file atomically; retry on the next tick.
    }
  }

  void _startHaProbe() {
    if (_haProbeTimer != null || haReady) return;
    unawaited(_probeHa());
    _haProbeTimer = Timer.periodic(
      const Duration(seconds: 2),
      (_) => unawaited(_probeHa()),
    );
  }

  Future<void> _probeHa() async {
    final address = snapshot.deviceIp;
    if (address == null || haReady) return;
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    try {
      final request = await client
          .getUrl(Uri.parse('http://$address:8123/'))
          .timeout(const Duration(seconds: 3));
      final response = await request.close().timeout(
        const Duration(seconds: 3),
      );
      final body = await response
          .transform(utf8.decoder)
          .join()
          .timeout(const Duration(seconds: 3));
      if (body.toLowerCase().contains('<title>home assistant</title>') ||
          body.toLowerCase().contains(
            'application-name" content="home assistant',
          )) {
        haReady = true;
        _haProbeTimer?.cancel();
        _haProbeTimer = null;
        notifyListeners();
      }
    } on Object {
      // HAOS may have a lease before Home Assistant has finished booting.
    } finally {
      client.close(force: true);
    }
  }

  Future<void> openHa() async {
    final address = snapshot.deviceIp;
    if (address == null) return;
    await launchUrl(
      Uri.parse('http://$address:8123'),
      mode: LaunchMode.externalApplication,
    );
  }

  Future<void> stop() async {
    if (!running) return;
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
    for (var attempt = 0; attempt < 20 && running; attempt++) {
      await Future<void>.delayed(const Duration(milliseconds: 300));
      await _pollState();
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
                if (!Platform.isWindows) ...[
                  const _InfoBox(
                    icon: Icons.info_outline,
                    text:
                        '界面已支持 macOS；创建直连 DHCP 网络的功能将在下一阶段通过 macOS Privileged Helper 提供。',
                  ),
                ] else ...[
                  const _InfoBox(
                    icon: Icons.warning_amber_rounded,
                    text:
                        '请先用网线将电脑与 HAOS 直连。开始后会申请管理员权限、添加临时 IP 并启动 DHCP；停止或退出时自动恢复。',
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

  Widget _adapterSelector() {
    if (controller.loadingAdapters) {
      return const LinearProgressIndicator();
    }
    return DropdownButtonFormField<DiagnosticAdapter>(
      value: controller.selectedAdapter,
      decoration: const InputDecoration(
        labelText: '连接 HAOS 的有线网卡',
        border: OutlineInputBorder(),
        prefixIcon: Icon(Icons.settings_ethernet),
      ),
      items: controller.adapters
          .map(
            (adapter) => DropdownMenuItem(
              value: adapter,
              child: Text('${adapter.name}  ${adapter.speed}'),
            ),
          )
          .toList(),
      onChanged: controller.running ? null : controller.selectAdapter,
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
            active: stage != 'idle' && stage != 'authorization',
          ),
          const Divider(height: 24),
          _StatusRow(
            label: 'DHCP / HAOS',
            value:
                controller.snapshot.deviceIp ??
                (stage == 'waiting_dhcp' ? '等待设备请求 IP…' : '尚未分配地址'),
            active: controller.snapshot.deviceIp != null,
          ),
          const Divider(height: 24),
          _StatusRow(
            label: 'Home Assistant',
            value: controller.haReady
                ? '8123 服务正常'
                : controller.snapshot.deviceIp != null
                ? '等待服务启动…'
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
