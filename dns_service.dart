import 'dart:io';
import 'dart:async';
import 'constants.dart';
import 'dns_service_config.dart';
import 'dns_query_handler.dart';

Future<void> main() async {
  print('DNS Service is starting...');

  final completer = Completer<void>(); // 用于保持程序运行

  try {
    final dnsInterfaces = loadDnsInterfaceConfig(CONFIG_FILE_NAME);

    // 获取所有网络接口
    final interfaces = await NetworkInterface.list();
    for (var interface in interfaces) {
      // 检查接口名称是否在配置中
      if (!dnsInterfaces.containsKey(interface.name)) {
        print('Skipping interface: ${interface.name} (not in configuration)');
        continue;
      }

      for (var address in interface.addresses) {
        // 排除 IPv6 地址
        if (address.type != InternetAddressType.IPv4) {
          print('Skipping address: ${address.address} (not IPv4)');
          continue;
        }

        print('Listening on interface: ${interface.name}, address: ${address.address}');

        // 为每个接口地址创建一个 UDP socket
        var socket = await RawDatagramSocket.bind(address, 53);
        socket.listen((RawSocketEvent event) {
          if (event == RawSocketEvent.read) {
            Datagram? datagram = socket.receive();
            if (datagram != null) {
              // print('Received DNS query on interface: ${interface.name}, address: ${address.address}');
              // print('Data: ${datagram.data}');

              // 创建 DnsQueryHandler 实例
              final handler = DnsQueryHandler(
                interfaceName: interface.name,
                interfaceAddress: address.address,
                domain: dnsInterfaces[interface.name]?.domain ?? '',
                datagram: datagram,
              );

              // 处理查询
              handler.processQuery();
            }
          }
        });
      }
    }

    print('DNS Service is running...');
    await completer.future; // 阻塞程序，直到 completer.complete() 被调用
  } catch (e, stackTrace) {
    print('DNS Service encountered an error: $e');
    print('Stack trace: $stackTrace'); // 添加堆栈信息以便调试
  } finally {
    print('DNS Service is shutting down...');
  }
}
