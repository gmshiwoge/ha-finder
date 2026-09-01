import 'package:flutter_test/flutter_test.dart';
import 'package:ha_finder/main.dart';

void main() {
  test('builds an IPv4 Home Assistant URL', () {
    const instance = HaInstance(name: 'Home', host: '192.168.1.20', port: 8123);
    expect(instance.url, 'http://192.168.1.20:8123');
  });

  test('wraps an IPv6 address in brackets', () {
    const instance = HaInstance(name: 'Home', host: 'fe80::1', port: 8123);
    expect(instance.url, 'http://[fe80::1]:8123');
  });
}
