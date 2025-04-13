import 'package:dart_raw/raw.dart';
import 'package:dart_dns/dart_dns.dart';
import 'dart:typed_data'; // Ensure Uint8List is available
import 'package:dart_dns/dart_dns.dart' show DnsNameCodec; // Ensure DnsNameCodec is available
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

  String decodeDnsName(Uint8List data, {int offset = 0}) {
    final buffer = StringBuffer();
    int currentOffset = offset;

    while (currentOffset < data.length) {
      final length = data[currentOffset];
      if (length == 0) break; // 结束标志
      currentOffset++;

      if (length >= 0xC0) {
        // 处理压缩指针
        final pointer = ((length & 0x3F) << 8) | data[currentOffset];
        currentOffset++;
        buffer.write(decodeDnsName(data, offset: pointer));
        break;
      } else {
        // 普通标签
        buffer.write(String.fromCharCodes(data.sublist(currentOffset, currentOffset + length)));
        currentOffset += length;
        if (data[currentOffset] != 0) buffer.write('.');
      }
    }

    return buffer.toString();
  }

  void processQuery() async {
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

        DnsInterface? destInterface;
        DnsInterface? uplinkInterface;

        int longestMatchLength = 0;

        for (final dnsInterface in dnsInterfaces.values) {
          if (dnsInterface.direction == 'uplink') {
            uplinkInterface = dnsInterface;
          }

          final domain = dnsInterface.domain;
          if (fqdn.endsWith(domain)) {
            final matchLength = domain.length;
            if (matchLength > longestMatchLength) {
              longestMatchLength = matchLength;
              destInterface = dnsInterface;
            }
          }
        }

        if (destInterface == null) {
          destInterface = uplinkInterface; // treat the uplink interface as the default
        }

        if (destInterface != null)
          switch (query.type) {
            case DnsRecordType.a:
              // Handle A record queries
              answer = await handleQueryA(destInterface, fqdn);
              break;
            case DnsRecordType.txt:
              // Handle TXT record queries
              answer = handleQueryTxt(destInterface, fqdn);
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

  Future<DnsResourceRecord?> handleQueryA(DnsInterface destInterface, String fqdn) async {
    String? ip;

    switch (interfaceDirection) {
      case 'lookback':
        // 处理来自环回接口的查询。这个接口服务于本机上的DART路由器
        if (destInterface.direction == 'uplink') {
          // 使用 destInterface 中配置的 DNS SERVER 对 fqdn 进行解析
          final dnsServer = destInterface.dnsServers.firstWhere((server) => server.isNotEmpty, orElse: () => throw Exception('No DNS server found'));

          // Perform a custom DNS query using the specified DNS server
          final dnsClient = UdpDnsClient(remoteAddress: InternetAddress(dnsServer));

          final nameList = <String>[];
          nameList.add(fqdn);

          // some fqdn may be a CNAME, so we need to follow the CNAME chain
          final packet = await dnsClient.lookupPacket(fqdn, type: InternetAddressType.IPv4, recordType: DnsRecordType.a);

          for (var answer in packet.answers) {
            if (nameList.contains(answer.name)) {
              if (answer.type == DnsResourceRecord.typeIp4) {
                ip = answer.data.toString();
                break;
              } else if (answer.type == DnsResourceRecord.typeCanonicalName) {
                // DnsResourceRecord.decodeSelf()没有能够正确处理CNAME记录中的压缩指针。我们需要重载这个方法
                // TODO: 待重载DnsResourceRecord.decodeSelf()
                // 解析CNAME记录
                final cname = decodeDnsName(Uint8List.fromList(answer.data));
                nameList.add(cname);
              }
            }
          }
        } else if (destInterface.direction == 'downlink') {
          ip = queryIpFromSqlite(fqdn);
          if (ip == null) {
            print('No IP found for $fqdn in interface: $interfaceName');
          }
        }

        break;
      case 'uplink':
        // 处理上行接口的查询
        if (destInterface.direction == 'uplink') {
          // 查询的是下行接口，理论上不应该收到这样的查询。抛出异常：这不是我负责的域
          throw Exception('FQDN $fqdn does not belong to any subdomain maintained by me.');
        } else if (destInterface.direction == 'downlink') {
          // 查询的是下行接口，直接返回HomeGW的IP
          ip = interfaceAddress;
        }
        break;
      case 'downlink':
        // 处理下行接口的查询
        if (destInterface.name == interfaceName) {
          // 查询的是同一个子域，直接返回DHCP SERVER分配的IP
          ip = queryIpFromSqlite(fqdn);
          if (ip == null) {
            print('No IP found for $fqdn in interface: $interfaceName');
          } else
            ip = interfaceAddress;
        }
        break;
      default:
        throw Exception('Invalid interface "$interfaceName" direction: $interfaceDirection');
    }

    // if (interfaceDirection == 'uplink') {
    //   if (destInterface?.direction == 'downlink') {
    //     ip = interfaceAddress;
    //   } else {
    //     // 查询的不是下行接口，理论上不应该收到这样的查询。抛出异常：这不是我负责的域
    //     throw Exception('FQDN $fqdn does not belong to any subdomain maintained by me.');
    //   }
    // }

    // // 从这里开始，查询方和被查询方都属于downlink（子域）
    // if (destInterface?.name == interfaceName) {
    //   // 同一个子域，返回DHCP SERVER分配的IP
    //   // 查询 SQLite 数据库
    //   ip = queryIpFromSqlite(fqdn);
    // } else {
    //   // 不同子域，报文需由当前服务器转发，返回当前接口的IP
    //   ip = interfaceAddress;
    // }

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

  DnsResourceRecord? handleQueryTxt(DnsInterface? destInterface, String fqdn) {
    String? txt;

    if (destInterface?.name == interfaceName) {
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
