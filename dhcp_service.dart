// Description: This file contains the main function for the DHCP server.
// It initializes the server, loads the configuration, and handles incoming DHCP packets.
// It also includes error handling and memory management.

import 'dart:io';
import 'dart:ffi';
import 'dart:async';
import 'package:ffi/ffi.dart';
import 'package:yaml/yaml.dart';
import 'package:sqlite3/sqlite3.dart';
import 'dhcp_c_interface.dart';
import 'dhcp_pkt.dart';
import 'constants.dart'; // Import the file containing constants
import 'dhcp_pool.dart';
import 'ip_address.dart';
import 'common_routines.dart';

////////////////////////////////////////////////////////////////////////////////

Future<void> dhcpMainFunc() async {
  print("Starting DHCP Server...");

  // Load configuration from YAML file
  pools.addAll(await Initialize(CONFIG_FILE_NAME));

  print("Configuration ${CONFIG_FILE_NAME}|loaded successfully.");

  // Allocate memory and call C function
  final resultPointer = calloc<RawDhcpPacket>();
  try {
    while (true) {
      print('\n===== Waiting for DHCP packet =====');
      print('Current time: ${DateTime.now()}');
      final returnCode = dhcpCInterface.callRecvDhcpPacket(resultPointer);
      print('Current time: ${DateTime.now()}');

      if (returnCode == 0) {
        print('DHCP packet received successfully.');
      } else {
        dhcpCInterface.printErrorMessage(returnCode);
        sleep(Duration(seconds: 1));
        continue;
      }

      DhcpPkt dhcpPkt = DhcpPkt(resultPointer);
      dhcpPkt.printMessageType();

      try {
        switch (dhcpPkt.options[OPTION_DHCP_MESSAGE_TYPE]?[0]) {
          case DHCP_DISCOVER: // DHCP DISCOVER
            dhcpPkt.handleDhcpDiscovery();
            break;
          case DHCP_OFFER: // DHCP OFFER
            // This is sent by the server to the client
            // So we need to do nothing here
            // In fact, we shouldn't even receive this packet
            print('Received DHCP OFFER, but no action needed.');
            break;
          case DHCP_REQUEST: // DHCP REQUEST
            dhcpPkt.handleDhcpRequest();
            break;
          case DHCP_ACK: // DHCP ACK
            dhcpPkt.handleDhcpAck();
            break;
          case DHCP_NAK: // DHCP NAK
            dhcpPkt.handleDhcpNak();
            break;
          case DHCP_RELEASE: // DHCP RELEASE
            dhcpPkt.handleDhcpRelease();
            break;
          default:
            print('Unknown DHCP message type: ${dhcpPkt.options[53]?[0]}');
            break;
        }
      } catch (e, stackTrace) {
        print('Error handling DHCP packet: $e');
        print('Stack trace: $stackTrace');
      }
    }
  } finally {
    // Ensure memory is freed
    calloc.free(resultPointer);
  }
}

Future<Map<String, DhcpPool>> Initialize(String configPath) async {
  // 1. Load the YAML configuration file
  final file = File(configPath);
  final yamlString = await file.readAsString();
  final yamlMap = loadYaml(yamlString) as Map;
  final Map<String, DhcpPool> pools = {};

  if (yamlMap.containsKey('interfaces')) {
    final interfaces = yamlMap['interfaces'] as List;
    for (var interface in interfaces) {
      try {
        // Validate interface name
        final ifaceName = interface['name'] as String;
        if (isInvalidString(ifaceName)) {
          throw FormatException('Invalid interface name: $ifaceName');
        }

        // Check if DHCP is enabled for this interface
        final dhcpEnabled = interface['dhcp_enabled'] as bool? ?? false;
        if (!dhcpEnabled) {
          print('DHCP is not enabled for interface: $ifaceName. Skipping...');
          continue;
        }

        // Validate address pool
        final addressPool = interface['address_pool'] as String;
        if (addressPool.isEmpty) {
          throw FormatException('Address pool cannot be empty');
        }

        final ipRange = addressPool.split('-');
        if (ipRange.length != 2) {
          throw FormatException('Invalid IP range format');
        }

        final startIp = ipRange[0];
        if (isInvalidIp(startIp)) {
          throw FormatException('Invalid start IP format: $startIp');
        }

        final endIp = ipRange[1];
        if (isInvalidIp(endIp)) {
          throw FormatException('Invalid end IP format: $endIp');
        }

        // Validate domain name
        final domain = interface['domain'] as String;
        if (isInvalidString(domain)) {
          throw FormatException('Invalid domain name: $domain');
        }

        // Validate gateway
        final gateway = interface['gateway'] as String;
        if (isInvalidIp(gateway)) {
          throw FormatException('Invalid gateway format: $gateway');
        }

        // Validate DNS servers
        final dnsServers = interface['dns_servers'] as List;

        if (dnsServers.isEmpty || dnsServers.length > 3) {
          throw FormatException('DNS servers count must be between 1 and 3');
        }

        if (dnsServers.any((dns) => isInvalidIp(dns))) {
          throw FormatException('DNS server addresses must be valid IPs');
        }

        final broadcastAddress = DhcpPool.formatIpAddress([
          startIp.split('.').sublist(0, 3).map(int.parse).toList()[0],
          startIp.split('.').sublist(0, 3).map(int.parse).toList()[1],
          startIp.split('.').sublist(0, 3).map(int.parse).toList()[2],
          255
        ]);

        final dhcpServer = await getInterfaceIpInSubnet(ifaceName, startIp);

        // Validate static bindings
        final staticBindings = interface['static_bindings'] as List?;
        final Map<String, String> bindings = {};
        if (staticBindings != null) {
          for (var binding in staticBindings) {
            final mac = binding['mac'] as String;
            final ip = binding['ip'] as String;

            if (isInvalidIp(ip)) {
              throw FormatException('Invalid static binding IP format: $ip');
            }

            if (isInvalidMac(mac)) {
              throw FormatException('Invalid MAC address format: $mac');
            }

            bindings[mac] = ip;
          }
        }

        pools[ifaceName] = DhcpPool(
          startIp: DhcpPool.parseIpAddress(startIp),
          endIp: DhcpPool.parseIpAddress(endIp),
          subnetMask: DhcpPool.parseIpAddress('255.255.255.0'), // Default subnet mask
          gateway: DhcpPool.parseIpAddress(gateway),
          dnsServers: List<String>.from(dnsServers).map(DhcpPool.parseIpAddress).toList(),
          leaseTime: 86400, // Default lease time
          domain: domain,
          dhcpServer: dhcpServer,
          broadcastAddress: DhcpPool.parseIpAddress(broadcastAddress),
          bindings: bindings,
        );
      } on FormatException catch (e) {
        print('Error loading interface configuration: ${e.message}');
      }
    }
  }

  print('Initializing database...');
  final db = sqlite3.open(DB_FILE_NAME);
  try {
    // 2. Insert a record into the database for each ip address in the pool
    db.execute('''
      DROP TABLE IF EXISTS addressPool;
      CREATE TABLE addressPool (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        iface_name TEXT NOT NULL,
        ip_address TEXT NOT NULL
      );
      DROP INDEX IF EXISTS idx_ip_address;  
      CREATE INDEX idx_ip_address ON addressPool (iface_name, ip_address);
    ''');

    pools.forEach((ifaceName, pool) {
      final startIp = pool.startIp.toList();
      final endIp = pool.endIp.toList();
      for (int i = startIp[3]; i <= endIp[3]; i++) {
        final ipAddress = '${startIp[0]}.${startIp[1]}.${startIp[2]}.$i';
        db.execute('INSERT INTO addressPool (iface_name, ip_address) VALUES (?, ?)', [ifaceName, ipAddress]);
      }
    });

    // 3.for each binded MAC-IP address, insert a record into the leases table
    // Here we don't drop the leases table, because we need to keep all the leases(static & dynamic) after reboot
    db.execute('''
      CREATE TABLE IF NOT EXISTS leases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        iface_name TEXT NOT NULL,
        mac_address TEXT NOT NULL UNIQUE,
        ip_address TEXT NOT NULL,
        is_dynamic boolean NOT NULL,  -- 0 for static, 1 for dynamic
        fqdn TEXT,            
        dart_support boolean, -- support dart protocol?
        dart_version INTEGER,  -- currently, dart protocol has only version 1.0 
        expires_time INTEGER  -- timestamp when the lease expires
      );
      CREATE INDEX IF NOT EXISTS idx_mac_address ON leases (mac_address);
      CREATE INDEX IF NOT EXISTS idx_ip_address ON leases (ip_address);
    ''');

    // Delete all binded records from leases table
    db.execute('DELETE FROM leases WHERE is_dynamic = 0;');

    pools.forEach((ifaceName, pool) {
      pool.bindings.forEach((mac, ip) {
        db.execute('INSERT INTO leases (iface_name, mac_address, ip_address, is_dynamic) VALUES (?, ?, ?, ?)', [
          ifaceName,
          mac,
          ip,
          0, // static
        ]);
      });
    });
  } finally {
    db.dispose();
  }

  print('Database initialized and populated with IP addresses.');

  // 4. Return the pools
  return pools;
}

Future<IpAddress> getInterfaceIpInSubnet(String ifaceName, String startIp) async {
  final interfaces = await NetworkInterface.list();
  for (final interface in interfaces) {
    if (interface.name == ifaceName) {
      for (final address in interface.addresses) {
        final ipParts = address.address.split('.');
        final startIpParts = startIp.split('.');
        if (ipParts.length == 4 && ipParts[0] == startIpParts[0] && ipParts[1] == startIpParts[1] && ipParts[2] == startIpParts[2]) {
          return DhcpPool.parseIpAddress(address.address);
        }
      }
    }
  }
  throw Exception('No IP address found in the subnet for interface $ifaceName');
}

Future<void> main() async {
  // Set up a global error handler to catch and log all uncaught exceptions
  await dhcpMainFunc();
}
