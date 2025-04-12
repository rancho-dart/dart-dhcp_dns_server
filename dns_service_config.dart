import 'package:yaml/yaml.dart';
import 'dart:io';

import 'common_routines.dart';

class DnsInterface {
  final String ifaceName;
  final String direction;
  final String domain;
  final List<String> dnsServers;

  DnsInterface({
    required this.ifaceName,
    required this.direction,
    required this.domain,
    required this.dnsServers,
  });
}

Map<String, DnsInterface> loadDnsInterfaceConfig(String configPath) {
  Map<String, DnsInterface> dnsInterfaces = {};

  // 读取配置文件并初始化 DNS 服务
  final file = File(configPath);
  if (!file.existsSync()) {
    throw Exception('Configuration file not found: $configPath');
  }

  final configContent = file.readAsStringSync();
  final config = loadYaml(configContent);

  if (config is! YamlMap) {
    throw Exception('Invalid configuration format.');
  }

  for (var interface in config['interfaces'] ?? []) {
    final direction = interface['direction'] as String? ?? '(not specified)';
    if (direction != 'uplink' && direction != 'downlink') {
      throw Exception('Invalid interface $interface direction: $direction');
    }

    final domain = interface['domain'] as String;
    if (domain.isEmpty) {
      throw Exception('Domain name cannot be empty.');
    }

    final dnsServers = interface['dns_servers'] as List;
    if (dnsServers.isEmpty) {
      throw Exception('DNS servers list cannot be empty.');
    }
    for (var server in dnsServers) {
      if (isInvalidIp(server)) {
        throw Exception('Invalid DNS server address: $server');
      }
    }
    dnsInterfaces[interface['name']] = DnsInterface(
      ifaceName: interface['name'],
      direction: direction,
      domain: domain,
      dnsServers: List<String>.from(dnsServers),
    );
  }

  // 全局合法性检查
  bool hasUplink = false;
  String? uplinkDomain;
  for (var iface in dnsInterfaces.values) {
    if (iface.direction == 'uplink') {
      if (hasUplink) {
        throw Exception('Multiple uplink interfaces found. Only one uplink is allowed.');
      }
      uplinkDomain = iface.domain;
      hasUplink = true;
    }
  }

  if (!hasUplink) {
    throw Exception('No uplink interface found. At least one uplink is required.');
  }

  // 检查所有 downlink 接口是否是 uplink 的子域
  for (var iface in dnsInterfaces.values) {
    if (iface.direction == 'downlink' && (!iface.domain.endsWith('.$uplinkDomain') || iface.domain.replaceFirst('.$uplinkDomain', '').contains('.'))) {
      throw Exception('Downlink interface ${iface.ifaceName} domain ${iface.domain} is not a subdomain of the uplink domain $uplinkDomain.');
    }
  }

  return dnsInterfaces;
}

// final DnsInterfaces = loadDnsInterfaceConfig(CONFIG_FILE_NAME);
