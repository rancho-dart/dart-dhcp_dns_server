// This file is the main entry point for the Dart application.
// After launching, it start two services: a DHCP server and a DNS server.
// Each one is started in its own process.

import 'dart:async';
import 'dart:io';

// It sets up a global error handler to catch and log all uncaught exceptions.
void main() async {
  // Set up a global error handler to catch and log all uncaught exceptions
  runZonedGuarded(() async {
    // 启动 DHCP 服务的进程
    final dhcpProcess = await Process.start('dart', ['dhcp_service.dart']);
    print('DHCP Service started with PID: ${dhcpProcess.pid}');

    // 启动 DNS 服务的进程
    final dnsProcess = await Process.start('dart', ['dns_service.dart']);
    print('DNS Service started with PID: ${dnsProcess.pid}');

    // 等待两个进程完成
    await Future.wait([
      dhcpProcess.exitCode,
      dnsProcess.exitCode,
    ]);
  }, (error, stackTrace) {
    print('Uncaught exception:');
    print('------------------');
    print('$error');
    print('Strack trace:');
    print('------------------');
    print('$stackTrace');
    print('------------------');
    print('Exited with error.');
    print('==================');

    exit(1);
  });
}
