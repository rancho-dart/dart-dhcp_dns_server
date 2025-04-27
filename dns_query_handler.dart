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
      List<DnsResourceRecord>? answers;
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
              answers = await handleQueryA(destInterface, fqdn);
              break;
            default:
              print('Unsupported query type: ${query.type}');
              break;
          }
      }

      if (answers!.isNotEmpty) {
        dnsPacket.answers.addAll(answers);
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

  ({bool success, String ip4, String domain}) parseAsIp4Prefixed(String name) {
    List<String> parts = name.split('.');
    if (parts.length >= 4) {
      String ip4Prefix = parts.sublist(0, 4).join('.');
      if (InternetAddress.tryParse(ip4Prefix) != null) {
        String remaining = parts.sublist(4).join('.');
        return (success: true, ip4: ip4Prefix, domain: remaining);
      }
    }
    return (success: false, ip4: '', domain: '');
  }

  Future<List<DnsResourceRecord>> handleQueryA(DnsInterface destInterface, String fqdn) async {
    // 当前类DnsQueryHandler绑定在每个接口上，每个实例都会有自己的interfaceName和interfaceDomain
    // 当前接口是收到查询报文的接口，destInterface是通向被查询的fqdn的接口
    // 我们比较当前接口信息与预期的报文去向接口信息，以便分别作出响应

    // 约定：如果一个fqdn是这样的：A.B.C.D.domain.com，它的含义是：
    // 这台主机支持Dart协议，且在domain.com域内，A.B.C.D是它的IP地址。
    // 需要注意的是：根据我们的解析规则，通过DNS解析这个FQDN的时候，如果不在同一域内，
    // 结果是去这个域的网关的IP。只有在同一域内，才会返回A.B.C.D（理论上）

    // 为什么要这样设计呢？因为大多数主机并没有将自己注册到DNS系统，当报文返回的时候，
    // Dart路由器无法通过DNS解析出报文的目标地址。Dart路由器可以检查：Dart报头中的目标
    // 地址是本域地址，并且目标地址去掉域后缀后是一个有效的IP地址，那么这就是本域内的IP。
    // 这样不需要通过DNS解析就直接得到了目标IPv4地址。
    // 实际上，因为目标机器大概率不会在DNS系统注册自己的域名，因此查询DNS不会得到想要的
    // 结果，除非DNS也引入本规则来解析

    // 对于那些在DNS系统中注册过的主机，譬如www.jd.com之类的，我们如何表示这个主机支持Dart呢？
    // 我们引入一个CNAME记录，仍以www.jd.com为例：
    // Answer 1：CNAME Record: www.jd.com -> ip-A.B.C.D.jd.com
    // Answer 2：A     Record: A.B.C.D.jd.com -> A.B.C.D（这个A.B.C.D是www.jd.com在jd.com域内的IP）
    // 当连接的发起方在DNS查询过程中看到有A.B.C.D.jd.com这样一条记录，它就知道目标机器支持Dart

    String? ip;
    bool? dartSupported = false;
    String? cname;

    switch (interfaceDirection) {
      case 'lookback':
        // 处理来自环回接口的查询。这个接口服务于本机上的DART路由器
        // 首先尝试用IP前缀的风格解析
        final result = parseAsIp4Prefixed(fqdn);
        if (result.success && result.domain == destInterface.domain) {
          // 如果FQDN是这样的：A.B.C.D.domain.com,且domain.com是目标接口的域，那么A.B.C.D是目标IP
          ip = result.ip4;
          dartSupported = true;
          cname = 'dart-host.${fqdn}'; // 让cname以“dart-host.”开头，告诉查询方目标主机支持Dart
          break;
        }

        if (destInterface.direction == 'uplink') {
          // 使用 destInterface 中配置的 DNS SERVER 对 fqdn 进行解析
          final dnsServer = destInterface.dnsServers.firstWhere((server) => server.isNotEmpty, orElse: () => throw Exception('No DNS server found'));

          // Perform a custom DNS query using the specified DNS server
          final dnsClient = UdpDnsClient(remoteAddress: InternetAddress(dnsServer));

          // some fqdn may be a CNAME, so we need to follow the CNAME chain
          final DnsPacket = await dnsClient.lookupPacket(fqdn, type: InternetAddressType.IPv4, recordType: DnsRecordType.a);

          final List<String> nameList = [fqdn];
          for (final answer in DnsPacket.answers) {
            // 跟踪cname链直到找到A记录
            if (!nameList.contains(answer.name)) continue;

            if (answer.type == DnsRecordType.cname.value) {
              nameList.add(answer.dataAsHumanReadableString());
              continue;
            }

            if (answer.type == DnsRecordType.a.value) {
              ip = answer.dataAsHumanReadableString();

              // 成功的查询返回的结果可能有三：
              // cname以dart-host.开头，那么它就是目标主机支持Dart
              // cname以dart-gateway开头，那么它是转发到下一个域的Dart网关的接口IP
              // 如果以上两条均不满足，那么目标主机不支持Dart

              // if answer.name starts with "dart-host."
              if (answer.name.startsWith('dart-host.') || answer.name.startsWith('dart-gateway.')) {
                cname = answer.name;
                dartSupported = true;
              } else {
                dartSupported = false;
              }
            }
          }
        } else if (destInterface.direction == 'downlink') {
          ip = queryIpFromSqlite(fqdn);
          dartSupported = queryDartSupportedStatusFromSqlite(fqdn);
          if (dartSupported!) {
            cname = 'dart-host.${fqdn}';
          }
        }

        break;
      case 'uplink':
        // 处理来自上行接口的查询
        if (destInterface.direction == 'uplink') {
          // 查询的是通向上行接口的报文，理论上不应该收到这样的查询。抛出异常：这不是我负责的域
          throw Exception('FQDN $fqdn does not belong to any subdomain maintained by me.');
        } else if (destInterface.direction == 'downlink') {
          // 查询的是下行接口负责的域，直接返回HomeGW的IP
          ip = interfaceAddress;
          dartSupported = true;
          cname = 'dart-gateway.${destInterface.domain}'; // 告诉查访方：这个fqdn支持Dart，但地址不详
        }
        break;
      case 'downlink':
        // 处理来自下行接口的查询
        if (destInterface.name == interfaceName) {
          // 查询的是同一个子域，直接返回DHCP SERVER分配的IP
          ip = queryIpFromSqlite(fqdn);
          dartSupported = queryDartSupportedStatusFromSqlite(fqdn);
          if (dartSupported!) {
            cname = 'dart-host.${fqdn}';
          }
        } else {
          ip = interfaceAddress;
          dartSupported = true;
          cname = 'dart-gateway.${interfaceDomain}';
        }
        break;
      default:
        throw Exception('Invalid interface "$interfaceName" direction: $interfaceDirection');
    }

    List<DnsResourceRecord> answers = [];
    String? nameForARecord = fqdn;
    if (ip != null) {
      print('Returning IP for $fqdn: $ip');
      if (dartSupported == true && cname != null) {
        // 添加当前域名的CNAME记录
        // 再添加当前域名的A记录

        final answer = DnsResourceRecord.withAnswer(
          name: fqdn,
          type: DnsRecordType.cname.value,
          data: Uint8List.fromList(cname.codeUnits),
        );
        answers.add(answer);
        nameForARecord = cname;
      }

      final answer = DnsResourceRecord.withAnswer(
        name: nameForARecord,
        type: DnsRecordType.a.value,
        data: Uint8List.fromList(ip.split('.').map((s) => int.parse(s)).toList()),
      );
      answers.add(answer);
    } else {
      print('No IP found for "$fqdn" in interface: $interfaceName');
    }
    return answers;
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

  bool? queryDartSupportedStatusFromSqlite(String fqdn) {
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
          return true;
        } else {
          print('Dart support is not enabled for $fqdn');
          return false; // 这是一台传统主机，不支持Dart
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
