// This file is the main entry point for the Dart application.
// After launching, it start two services: a DHCP server and a DNS server.
// Each one is started in its own process.

import 'dart:async';
import 'dart:io';

import 'dhcp_service.dart';

// It sets up a global error handler to catch and log all uncaught exceptions.
void main() async {
  // Set up a global error handler to catch and log all uncaught exceptions
  runZonedGuarded(() async {
    await dhcpMainFunc();
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
