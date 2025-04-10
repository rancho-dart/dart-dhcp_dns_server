import 'package:sqlite3/sqlite3.dart' as sqlite3;
import 'ip_address.dart';
import 'constants.dart';

class DhcpPool {
  IpAddress startIp;
  IpAddress endIp;
  IpAddress subnetMask;
  IpAddress gateway;
  IpAddress dhcpServer;
  IpAddress broadcastAddress;

  List<IpAddress> dnsServers;
  int leaseTime;
  String domain;
  Map<String, String> bindings; // Add this field to store static bindings

  // Method to get a lease for a client based on MAC address
  List<int>? getLease(String ifaceName, List<int> macAddress, String requestedIp) {
    // DHCP服务器为客户端分配IP地址的优先次序如下：
    // 1.与客户端 MAC 地址或客户端 ID 静态绑定的 IP 地址；
    if (bindings.containsKey(macAddress.join(':'))) {
      // If MAC address is found in bindings, return the associated IP address
      return bindings[macAddress.join(':')]!.split('.').map(int.parse).toList();
    }

    // 后面的操作需要从表中查询了，我们先打开数据库
    final db = sqlite3.sqlite3.open(DB_FILE_NAME);
    try {
      // 2.DHCP 服务器记录的曾经分配给客户端的 IP 地址
      // 因为我们已经把静态绑定的IP写入leases表，实际上从表中读取也是可以的，只是效率差一点
      final result = db.select('SELECT ip_address FROM leases WHERE mac_address = ?', [macAddress.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')]);
      if (result.isNotEmpty) {
        return (result.first['ip_address'] as String).split('.').map(int.parse).toList();
      }

      // 3.客户端发送的 DHCP-DISCOVER 报文中 Option 50 字段指定的 IP 地址
      if (requestedIp.isNotEmpty) {
        final leaseResult = db.select(
          'SELECT expires_time FROM leases WHERE ip_address = ? AND mac_address = ?',
          [requestedIp, macAddress.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')],
        );

        if (leaseResult.isEmpty) {
          // If the IP is not leased, return it
          return requestedIp.split('.').map(int.parse).toList();
        } else {
          final expiresTime = leaseResult.first['expires_time'] as int;
          final currentTime = DateTime.now().millisecondsSinceEpoch ~/ 1000;
          if (expiresTime < currentTime) {
            // If the lease time is over, return the IP
            return requestedIp.split('.').map(int.parse).toList();
          }
        }
      }

      // 4.在 DHCP 地址池中，顺序查找可供分配的 IP 地址，最先找到的 IP 地址；
      final availableIpResult = db.select('''
        SELECT ip_address FROM addressPool
        WHERE iface_name = ? AND ip_address NOT IN (
          SELECT ip_address FROM leases WHERE iface_name = ?
        )
        LIMIT 1
      ''', [ifaceName, ifaceName]);

      if (availableIpResult.isNotEmpty) {
        return (availableIpResult.first['ip_address'] as String).split('.').map(int.parse).toList();
      }

      // 5.如果未找到可用的 IP 地址，则依次查询租约过期、曾经发生过冲突的 IP 地址，如果找到则进行分配，否则将不予处理。
      final expiredIpResult = db.select('''
        SELECT ip_address FROM leases
        WHERE iface_name = ? AND expires_time < ?
        LIMIT 1
      ''', [ifaceName, DateTime.now().millisecondsSinceEpoch ~/ 1000]);
      if (expiredIpResult.isNotEmpty) {
        return expiredIpResult.first['ip_address']!.split('.').map(int.parse).toList();
      }
    } finally {
      db.dispose();
    }
    return null; // No available IP found
  }

  DhcpPool({
    required this.startIp,
    required this.endIp,
    required this.subnetMask,
    required this.gateway,
    required this.dnsServers,
    required this.leaseTime,
    required this.domain,
    required this.dhcpServer,
    required this.broadcastAddress,
    required this.bindings,
  });

  // Add a helper method to format IP address
  static String formatIpAddress(List<int> ip) {
    return ip.join('.');
  }

  factory DhcpPool.fromMap(Map<String, dynamic> map) {
    return DhcpPool(
      startIp: parseIpAddress(map['startIp']),
      endIp: parseIpAddress(map['endIp']),
      subnetMask: parseIpAddress(map['subnetMask']),
      gateway: parseIpAddress(map['gateway']),
      dnsServers: List<String>.from(map['dnsServers']).map(parseIpAddress).toList(),
      leaseTime: map['leaseTime'],
      domain: map['domain'],
      dhcpServer: parseIpAddress(map['dhcpServer']), // Assuming gateway as DHCP server
      broadcastAddress: parseIpAddress(map['broadcastAddress']),
      bindings: Map<String, String>.from(map['bindings'] ?? {}),
    );
  }

  static IpAddress parseIpAddress(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) {
      throw FormatException('Invalid IP address format: $ip');
    }
    final result = parts.map((part) {
      final value = int.tryParse(part);
      if (value == null || value < 0 || value > 255) {
        throw FormatException('Invalid IP address format: $ip');
      }
      return value;
    }).toList();
    return IpAddress(result);
  }

  // Override toString method to format IP addresses
  @override
  String toString() {
    return 'DhcpPool(startIp: ${startIp}, endIp: ${endIp}, subnetMask: ${subnetMask}, gateway: ${gateway}, dnsServers: ${dnsServers.map((dns) => dns).toList()}, leaseTime: $leaseTime, domain: $domain)';
  }
}

// Define DhcpPool class
final Map<String, DhcpPool> pools = {};
