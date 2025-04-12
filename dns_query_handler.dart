import 'package:dart_raw/raw.dart';
import 'package:dart_dns/dart_dns.dart';
import 'dart:typed_data'; // Ensure Uint8List is available
import 'dart:io'; // 添加用于 UDP 套接字的库

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
  final String domain;
  final Datagram datagram;

  DnsQueryHandler({
    required this.interfaceName,
    required this.domain,
    required this.datagram,
  });

  void processQuery() {
    final rawReader = RawReader.withBytes(datagram.data);
    RawWriter rawWriter = RawWriter.withCapacity(512);

    print('Processing DNS query on interface: $interfaceName, Domain: $domain');
    print('Raw packet data: ${datagram.data}');

    final dnsPacket = DnsPacket();
    dnsPacket.decodeSelf(rawReader);

    print('Decoded DNS query: ${dnsPacket.questions}');

    // Decode the raw DNS packet

    bool localHandled = false;
    // Check the query type
    for (final query in dnsPacket.questions) {
      switch (query.type) {
        case DnsRecordType.a:
          // rawWriter = localHandleQueryTypeA(query);
          // Search the local database for the requested domain
          final localDb = {
            'example.com': '192.168.1.1',
            'test.com': '192.168.1.2',
          };

          final fqdn = query.name.toLowerCase();
          if (localDb.containsKey(fqdn)) {
            final ip = localDb[fqdn]!;
            print('Found in local DB: $fqdn -> $ip');

            // Construct the DNS response
            final answer = DnsResourceRecord.withAnswer(
              name: query.name,
              type: DnsRecordType.a.value, // Record type A (IPv4 address)
              data: Uint8List.fromList(ip.split('.').map((s) => int.parse(s)).toList()),
            );
            dnsPacket.answers.add(answer);
            localHandled = true;
          } else {
            print('Not found in local DB: $fqdn');
            localHandled = false;
          }
          break;
        // case DnsRecordType.aaaa:
        //   print('Query type: AAAA');
        //   break;
        default:
          print("FQDN: ${query.name}");
          print('query type: ${query.type}');
      }
    }

    if (!localHandled) {
      print('No local handling for this query');
      return;
    }
    // Encode the DNS response packet
    dnsPacket
          ..isResponse = true
          ..responseCode = DnsResponseCode.noError.index // 0 represents "no error" in DNS response codes
        // ..questionsCount = dnsPacket.questions.length
        // ..answersCount = dnsPacket.answers.length;
        ;

    dnsPacket.encodeSelf(rawWriter);

    final responseBytes = rawWriter.toByteDataCopy();
    sendDnsResponse(responseBytes.buffer.asUint8List());
  }

  void sendDnsResponse(Uint8List responseBytes) async {
    // 获取指定的网络接口地址
    final interfaces = await NetworkInterface.list();
    final interface = interfaces.firstWhere((i) => i.name == interfaceName, orElse: () => throw Exception('Interface $interfaceName not found'));

    if (interface.addresses.isEmpty) {
      throw Exception('No addresses found for interface $interfaceName');
    }

    final sourceAddress = interface.addresses.first;

    // 使用指定的网络接口地址绑定套接字
    // 理论上，我们应当绑定到物理接口进行发送（因为在Dart协议中不同接口可能有相同的IP地址）
    // 简单起见，我们暂时不绑定到物理接口了
    final socket = await RawDatagramSocket.bind(sourceAddress, 53); // 53是DNS端口号
    socket.send(responseBytes, datagram.address, datagram.port);
    print('DNS response sent from interface $interfaceName (${sourceAddress.address}) to ${datagram.address}:${datagram.port}');
    socket.close();
  }
}

RawWriter localHandleQueryTypeA(DnsQuestion query) {
  return RawWriter.withCapacity(512);
}
