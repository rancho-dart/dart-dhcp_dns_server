import 'package:dart_raw/raw.dart';
import 'package:dart_dns/dart_dns.dart';
import 'dart:typed_data'; // Ensure Uint8List is available
import 'dart:io'; // 添加用于 UDP 套接字的库
import 'package:sqlite3/sqlite3.dart'; // 添加 SQLite 库
import 'constants.dart'; // 添加常量文件
import 'dns_service_config.dart'; // 添加 DNS 服务配置文件

// 定义枚举类型 DnsResponseCode
enum DnsResponseCode {
  noError, // 0: No error
  formatError, // 1: Format error
  serverFailure, // 2: Server failure
  nameError, // 3: Name error (NXDOMAIN)
  notImplemented, // 4: Not implemented
  refused, // 5: Refused
}

class DnsQueryHandler {
  final String interfaceName;
  final String interfaceDomain;
  final String interfaceAddress; // 新增字段
  final String interfaceDirection;
  final Datagram datagram;

  DnsQueryHandler({
    required this.interfaceName,
    required this.interfaceDomain,
    required this.interfaceDirection,
    required this.datagram, // 这是接收到的 DNS 查询数据报，包含查询方IP和端口号
    required this.interfaceAddress, // 这是HomeGW的接口地址
  });

  void processQuery() {
    final rawReader = RawReader.withBytes(datagram.data);
    RawWriter rawWriter = RawWriter.withCapacity(512);

    print('Processing DNS query on interface: $interfaceName, Domain: $interfaceDomain');
    print('Raw packet data: ${datagram.data}');

    final dnsPacket = DnsPacket();
    dnsPacket.decodeSelf(rawReader);

    print('Decoded DNS query: ${dnsPacket.questions}');

    DnsResponseCode responsedCode;

    try {
      DnsResourceRecord? answer;
      for (final query in dnsPacket.questions) {
        final fqdn = query.name.toLowerCase();
        final isSameDomain = (fqdn.endsWith(interfaceDomain) && !fqdn.replaceFirst('.$interfaceDomain', '').contains('.'));
        switch (query.type) {
          case DnsRecordType.a:
            // Handle A record queries
            answer = handleQueryA(isSameDomain, fqdn);
            break;
          case DnsRecordType.txt:
            // Handle TXT record queries
            answer = handleQueryTxt(isSameDomain, fqdn);
            break;
          default:
            print('Unsupported query type: ${query.type}');
            break;
        }
      }

      if (answer != null) {
        dnsPacket.answers.add(answer);
        responsedCode = DnsResponseCode.noError; // NOERROR
      } else {
        responsedCode = DnsResponseCode.nameError; // NXDOMAIN: No such domain
      }
    } catch (e) {
      print('Error processing DNS query: $e');
      responsedCode = DnsResponseCode.refused; // REFUSED: Server refused
    }

    dnsPacket
      ..isResponse = true
      ..responseCode = responsedCode.index;
    dnsPacket.encodeSelf(rawWriter);
    final responseBytes = rawWriter.toByteDataCopy();
    sendDnsResponse(responseBytes.buffer.asUint8List());
  }

  DnsResourceRecord? handleQueryA(bool isSameDomain, String fqdn) {
    String? ip;

    if (interfaceDirection == 'uplink') {
      for (final dnsInterface in dnsInterfaces.values) {
        if (dnsInterface.direction == "downlink" && fqdn.endsWith(dnsInterface.domain)) {
          ip = interfaceAddress;
          break;
        }
      }

      if (ip == null) {
        throw Exception('FQDN $fqdn does not belong to any known subdomain.');
      }
    }

    // 从这里开始，查询方和被查询方都属于downlink（子域）
    if (isSameDomain) {
      // 同一个子域，返回DHCP SERVER分配的IP
      // 查询 SQLite 数据库
      ip = queryIpFromSqlite(fqdn);
    } else {
      // 不同子域，报文需由当前服务器转发，返回当前接口的IP
      ip = interfaceAddress;
    }

    if (ip != null) {
      print('Returning IP for $fqdn: $ip');
      final answer = DnsResourceRecord.withAnswer(
        name: fqdn,
        type: DnsRecordType.a.value,
        data: Uint8List.fromList(ip.split('.').map((s) => int.parse(s)).toList()),
      );
      return answer;
    } else {
      print('No IP found for "$fqdn" in interface: $interfaceName');
      return null;
    }
  }

  String? queryIpFromSqlite(String fqdn) {
    // 在这里实现查询 SQLite 数据库的逻辑
    // 返回匹配的 IP 地址，或者 null 如果没有找到

    final db = sqlite3.open(DB_FILE_NAME); // DB_FILE_NAME is the constant from constants.dart
    try {
      final result = db.select(
        'SELECT ip_address FROM leases WHERE fqdn = ?',
        [fqdn],
      );

      if (result.isNotEmpty) {
        return result.first['ip_address'] as String?;
      }
    } catch (e) {
      print('Error querying SQLite database: $e');
    } finally {
      db.dispose();
    }
    return null;
  }

  void sendDnsResponse(Uint8List responseBytes) async {
    // 使用指定的网络接口地址绑定套接字
    final socket = await RawDatagramSocket.bind(InternetAddress(interfaceAddress), 53);
    socket.send(responseBytes, datagram.address, datagram.port);
    print('DNS response sent from interface $interfaceName ($interfaceAddress) to ${datagram.address}:${datagram.port}');
    socket.close();
  }

  DnsResourceRecord? handleQueryTxt(bool isSameDomain, String fqdn) {
    String? txt;

    if (isSameDomain) {
      // 查询 SQLite 数据库
      txt = queryTxtFromSqlite(fqdn);

      if (txt == null) {
        print('No TXT record found for "$fqdn"  ');

        return null;
      }
    } else {
      // 如果查询的是其他域的 TXT 记录，那就意味着报文需要经过网关转发。告诉客户端：网关支持Dart协议
      txt = "Dart:v1";
    }

    // TXT 记录的格式是：第一个字节是长度，后面是字符串内容
    final txtWithLength = Uint8List(txt.length + 1)
      ..[0] = txt.length
      ..setRange(1, txt.length + 1, txt.codeUnits);

    final answer = DnsResourceRecord.withAnswer(name: fqdn, type: DnsRecordType.txt.value, data: txtWithLength);
    print('Returning TXT record for $fqdn: $txt');
    return answer;
  }

  String? queryTxtFromSqlite(String fqdn) {
    // 在这里实现查询 SQLite 数据库的逻辑
    // 返回匹配的 TXT 记录，或者 null 如果没有找到

    final db = sqlite3.open(DB_FILE_NAME); // DB_FILE_NAME is the constant from constants.dart
    try {
      final result = db.select(
        'SELECT dart_support, dart_version FROM leases WHERE fqdn = ?',
        [fqdn],
      );

      if (result.isNotEmpty) {
        if (result.first['dart_support'] == 1) {
          //这是一台支持Dart协议的主机
          final txt = 'Dart:v${result.first['dart_version']}';
          print('Returning TXT record for $fqdn: $txt');
          return txt;
        } else {
          print('Dart support is not enabled for $fqdn');
          return ""; // 这是一台传统主机，不支持Dart
        }
      }
      // 没有关于这台主机的记录（任何类型的记录都没有）
      print('No record found for "$fqdn" ');
      return null;
    } catch (e) {
      print('Error querying SQLite database: $e');
    } finally {
      db.dispose();
    }
    return null;
  }

  RawWriter localHandleQueryTypeA(DnsQuestion query) {
    return RawWriter.withCapacity(512);
  }
}
