import 'dart:io';
import 'dart:ffi';
import 'dart:async';
import 'package:ffi/ffi.dart';
import 'package:yaml/yaml.dart';
import 'package:sqlite3/sqlite3.dart';
import 'dhcp_c_interface.dart';
import 'dhcp_pkt.dart';
import 'constants.dart'; // Import the file containing constants

// Define DhcpPool class
final Map<String, DhcpPool> pools = {};

class IpAddress {
  late final List<int> _ip;

  IpAddress(List<int> ip) {
    if (ip.length != 4) {
      throw ArgumentError('IP address must be a list of 4 integers.');
    }
    _ip = ip;
  }

  List<int> toList() {
    return _ip;
  }

  @override
  String toString() {
    return _ip.join('.');
  }
}

// Define a global variable for DhcpCInterface
late final DhcpCInterface dhcpCInterface;

////////////////////////////////////////////////////////////////////////////////
void main() async {
  // Set up a global error handler to catch and log all uncaught exceptions
  runZonedGuarded(() async {
    await mainFunc();
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

Future<void> mainFunc() async {
  print("Starting DHCP Server...");

  // Initialize the global DhcpCInterface instance
  dhcpCInterface = DhcpCInterface();

  // Load configuration from YAML file
  pools.addAll(await Initialize(CONFIG_FILE_NAME));

  print("Configuration ${CONFIG_FILE_NAME}|loaded successfully.");

  // Allocate memory and call C function
  final resultPointer = calloc<RawDhcpPacket>();
  try {
    while (true) {
      print('\n===== Waiting for DHCP packet =====');
      final returnCode = dhcpCInterface.callRecvDhcpPacket(resultPointer);

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

class DhcpPkt {
  String iface = '';
  int op = 0;
  int htype = 0;
  int hlen = 0;
  int hops = 0;
  int xid = 0;
  int secs = 0;
  int flags = 0;
  List<int> ciaddr = [];
  List<int> yiaddr = [];
  List<int> siaddr = [];
  List<int> giaddr = [];
  List<int> chaddr = [];
  String sname = '';
  String file = '';
  Map<int, List<int>> options = {};

  void handleDhcpDiscovery() {
    bool dartSupported = false;
    int dartVersion = 0;
    print('Handling DHCP DISCOVER for client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');

    // Add logic to process the DHCP DISCOVER packet
    final requestedIp = options[50]?.map((e) => e.toString()).join('.');

    if (options.containsKey(224)) {
      // Check for Dart protocol support
      final dartOption = String.fromCharCodes(options[224]!);
      if (dartOption.toLowerCase().startsWith('dart:')) {
        dartSupported = true;
        final dartVersionString = dartOption.split(':')[1].toLowerCase().replaceAll('v', '');
        dartVersion = int.tryParse(dartVersionString) ?? 0;
      }
    }

    final leaseIp = pools[iface]?.getLease(iface, chaddr, requestedIp ?? '');
    if (leaseIp == null) {
      throw Exception('No available IPs to allocate for client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
    }

    print('Allocated IP: ${leaseIp.join('.')} to client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');

    final clientMac = chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':');

    // The DHCP server should also update the lease information in the database
    final db = sqlite3.open(DB_FILE_NAME);
    try {
      final leaseIpStr = leaseIp.join('.');

      // Check if the IP is already in the leases table
      final existingLease = db.select(
        'SELECT * FROM leases WHERE iface_name = ? AND ip_address = ? AND mac_address = ?',
        [iface, leaseIpStr, clientMac],
      );

      final fqdn = options.containsKey(12) ? '${String.fromCharCodes(options[12]!)}.${pools[iface]!.domain}' : '';
      final expiresTime = DateTime.now().millisecondsSinceEpoch ~/ 1000 + pools[iface]!.leaseTime;
      if (existingLease.isNotEmpty) {
        // Update the lease information
        db.execute('UPDATE leases SET fqdn = ?, dart_support = ?, dart_version = ?, expires_time = ? WHERE iface_name = ? AND ip_address = ? AND mac_address = ?',
            [fqdn, dartSupported, dartVersion, expiresTime, iface, leaseIpStr, clientMac]);
        print('Updated lease for IP: $leaseIpStr and MAC: $clientMac');
      } else {
        // Insert a new lease record
        db.execute('INSERT INTO leases (iface_name, mac_address, ip_address, is_dynamic, fqdn, dart_support, dart_version, expires_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [
          iface,
          clientMac,
          leaseIpStr,
          1, // dynamic lease
          fqdn, // fqdn
          dartSupported, // dart_support
          dartVersion, // dart_version
          expiresTime // expires_time
        ]);
        print('Inserted new lease for IP: $leaseIpStr and MAC: $clientMac');
      }
    } finally {
      db.dispose();
    }

    sendDhcpPacket(iface, clientMac, leaseIp, DHCP_OFFER);
  }

  void handleDhcpRequest() {
    // 如果有多台DHCP服务器向DHCP客户端回应DHCP-OFFER报文，则DHCP客户端只接受第一个收到的DHCP-OFFER报文。
    // 然后以广播方式发送DHCP-REQUEST请求报文，该报文中包含Option 54（服务器标识选项），即它选择的DHCP服务器的IP地址信息。
    // 以广播方式发送DHCP-REQUEST请求报文，是为了通知所有的DHCP服务器，它将选择Option 54中标识的DHCP服务器提供的IP地址，
    // 其他DHCP服务器可以重新使用曾提供的IP地址。
    // 收到DHCP客户端发送的DHCP-REQUEST请求报文后，DHCP服务器根据DHCP-REQUEST报文中携带的MAC地址来查找有没有相应的租约记录。
    // 如果有，则发送DHCP-ACK报文作为应答，通知DHCP客户端可以使用分配的IP地址。

    // DHCP客户端收到DHCP服务器返回的DHCP-ACK确认报文后，会以广播的方式发送免费ARP报文，探测是否有主机使用服务器分配的IP地址，
    // 如果在规定的时间内没有收到回应，客户端才使用此地址。否则，客户端会发送DHCP-DECLINE报文给DHCP服务器，通知DHCP服务器该
    // 地址不可用，并重新申请IP地址。

    // 如果DHCP服务器收到DHCP-REQUEST报文后，没有找到相应的租约记录，或者由于某些原因无法正常分配IP地址，
    // 则发送DHCP-NAK报文作为应答，通知DHCP客户端无法分配合适IP地址。DHCP客户端需要重新发送DHCP-DISCOVER报文来请求新的IP地址。

    print('Handling DHCP REQUEST for client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
    // Add logic to process the DHCP REQUEST packet
    final requestedIp = options[50]?.map((e) => e.toString()).join('.');
    if (requestedIp == null) {
      print('No requested IP found in options.');
      return;
    }
    // Check if the requested IP is valid
    if (isInvalidIp(requestedIp)) {
      print('Requested IP $requestedIp is not valid.');
      return;
    }

    final serverId = options[54]?.map((e) => e.toString()).join('.');
    final clientMac = chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':');

    if (serverId != null && serverId != pools[iface]?.dhcpServer.toString()) {
      // If the server ID does not match or is null, clear the lease record
      releaseIpInDB(requestedIp, clientMac);
      return;
    }

    final db = sqlite3.open(DB_FILE_NAME);
    try {
      final leaseRecord = db.select(
        'SELECT * FROM leases WHERE iface_name = ? AND ip_address = ? AND mac_address = ?',
        [iface, requestedIp, clientMac],
      );

      if (leaseRecord.isNotEmpty) {
        // If a lease record exists, reply with a DHCP ACK
        final leaseIp = requestedIp.split('.').map(int.parse).toList();
        print('Lease record found for IP: $requestedIp and MAC: $clientMac. Sending DHCP ACK.');
        sendDhcpPacket(iface, clientMac, leaseIp, DHCP_ACK);
        print('Allocated IP: ${leaseIp.join('.')} to client MAC: $clientMac');
      } else {
        // If no lease record exists, reply with a DHCP NAK
        print('No lease record found for IP: $requestedIp and MAC: $clientMac. Sending DHCP NAK.');
        sendDhcpPacket(iface, clientMac, [0, 0, 0, 0], DHCP_NAK);
        return; // Exit the function as no valid lease is available
      }
    } catch (e) {
      print('An error occurred: $e');
    } finally {
      db.dispose();
    }
  }

  void sendDhcpPacket(String iface, String clientMac, List<int> yiaddr, int messageType) {
    final packet = calloc<RawDhcpPacket>();
    try {
      final data = packet.ref.data;

      // Fill in the common DHCP packet fields
      data[0] = 2; // op: BOOTREPLY
      data[1] = htype; // htype: same as REQUEST
      data[2] = hlen; // hlen: same as REQUEST
      data[3] = hops; // hops: same as REQUEST
      data[4] = (xid >> 24) & 0xFF; // xid
      data[5] = (xid >> 16) & 0xFF;
      data[6] = (xid >> 8) & 0xFF;
      data[7] = xid & 0xFF;
      data[8] = 0; // secs
      data[9] = 0;
      data[10] = (flags >> 8) & 0xFF; // flags
      data[11] = flags & 0xFF;
      data.setRange(12, 16, ciaddr); // ciaddr
      data.setRange(16, 20, yiaddr); // yiaddr: acknowledged IP or no IP assigned
      data.setRange(20, 24, pools[iface]!.dhcpServer.toList()); // siaddr: DHCP server
      data.setRange(24, 28, pools[iface]!.gateway.toList()); // giaddr
      data.setRange(28, 28 + chaddr.length, chaddr); // chaddr
      data.setRange(236, 240, [99, 130, 83, 99]); // magic cookie

      // Add DHCP options
      int offset = 240; // Start of options
      data[offset++] = OPTION_DHCP_MESSAGE_TYPE; // DHCP Message Type
      data[offset++] = 1; // Length
      data[offset++] = messageType; // DHCP message type (e.g., OFFER, ACK, NAK)

      if (messageType == DHCP_OFFER || messageType == DHCP_ACK) {
        // DHCP OFFER or ACK
        data[offset++] = OPTION_SUBNET_MASK; // Subnet Mask
        data[offset++] = 4; // Length
        data.setRange(offset, offset + 4, pools[iface]!.subnetMask.toList());
        offset += 4;

        data[offset++] = OPTION_DOMAIN_NAME_SERVER; // DNS Servers
        data[offset++] = (pools[iface]!.dnsServers.length * 4); // Length
        for (final dns in pools[iface]!.dnsServers) {
          data.setRange(offset, offset + 4, dns.toList());
          offset += 4;
        }

        final domainLength = pools[iface]!.domain.length;
        data[offset++] = OPTION_DOMAIN_NAME; // Domain Name
        data[offset++] = domainLength; // Length
        data.setRange(offset, offset + domainLength, pools[iface]!.domain.codeUnits);
        offset += domainLength;

        data[offset++] = OPTION_IP_ADDRESS_LEASE_TIME; // Lease Time
        data[offset++] = 4; // Length
        final leaseTime = pools[iface]!.leaseTime;
        data[offset++] = (leaseTime >> 24) & 0xFF;
        data[offset++] = (leaseTime >> 16) & 0xFF;
        data[offset++] = (leaseTime >> 8) & 0xFF;
        data[offset++] = leaseTime & 0xFF;

        data[offset++] = OPTION_ROUTER; // Router (Gateway)
        data[offset++] = 4; // Length
        data.setRange(offset, offset + 4, pools[iface]!.gateway.toList());
        offset += 4;
      }

      data[offset++] = OPTION_SERVER_IDENTIFIER; // Server Identifier
      data[offset++] = 4; // Length
      data.setRange(offset, offset + 4, pools[iface]!.dhcpServer.toList()); // Server IP
      offset += 4;

      data[offset++] = OPTION_END; // End Option
      // Add padding to the tail
      while (offset < 300) {
        // Ensure the packet is at least 300 bytes long
        data[offset++] = 0; // Fill remaining space with zeros
      }

      // Set the length of the packet
      packet.ref.length = offset;
      for (int i = 0; i < IFNAMSIZ; i++) {
        packet.ref.iface[i] = 0;
      }
      packet.ref.iface.setRange(0, iface.length, iface.codeUnits);
      packet.ref.iface[iface.length] = 0; // Null-terminate the interface name

      // Send the DHCP packet
      final sendResult = dhcpCInterface.callSendDhcpPacket(packet);
      if (sendResult == 0) {
        print('DHCP ${messageType == DHCP_OFFER ? 'OFFER' : messageType == DHCP_ACK ? 'ACK' : 'NAK'} sent successfully.');
      } else {
        dhcpCInterface.printErrorMessage(sendResult);
      }
    } finally {
      calloc.free(packet);
    }
  }

  void releaseIpInDB(String clientIp, String clientMac) {
    final db = sqlite3.open(DB_FILE_NAME);
    try {
      final leaseRecord = db.select(
        'SELECT is_dynamic FROM leases WHERE iface_name = ? AND ip_address = ? AND mac_address = ?',
        [iface, clientIp, clientMac],
      );

      if (leaseRecord.isNotEmpty) {
        final isDynamic = leaseRecord.first['is_dynamic'] as int;
        if (isDynamic == 1) {
          // the lease is dynamic, delete the record
          db.execute(
            'DELETE FROM leases WHERE iface_name = ? AND ip_address = ? AND mac_address = ?',
            [iface, clientIp, clientMac],
          );
          print('Dynamic lease for IP $clientIp cleared for client MAC: $clientMac');
        } else {
          // the lease is static, clear the expires_time field
          db.execute(
            'UPDATE leases SET expires_time = 0 WHERE iface_name = ? AND ip_address = ? AND mac_address = ?',
            [iface, clientIp, clientMac],
          );
          print('Static lease for IP $clientIp updated (expires_time cleared) for client MAC: $clientMac');
        }
      }
    } finally {
      db.dispose();
    }
  }

  void handleDhcpAck() {
    print('Handling DHCP ACK for client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
    // Add logic to process the DHCP ACK packet
  }

  void handleDhcpNak() {
    print('Handling DHCP NAK for client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
    // Add logic to process the DHCP NAK packet
  }

  void printMessageType() {
    const Map<int, String> messageTypes = {
      1: 'DHCP DISCOVER',
      2: 'DHCP OFFER',
      3: 'DHCP REQUEST',
      4: 'DHCP DECLINE',
      5: 'DHCP ACK',
      6: 'DHCP NAK',
      7: 'DHCP RELEASE',
      8: 'DHCP INFORM',
      9: 'DHCP FORCERENEW',
      10: 'DHCP LEASEQUERY',
    };

    final messageType = messageTypes[options[53]?[0]] ?? 'Unknown Message Type';
    print('--- Message Type: $messageType ---');
    print('Client IP: ${ciaddr.join(".")}');
    final serverIp = options[54]?.map((e) => e.toString()).join('.') ?? '0.0.0.0';
    print('Server IP: $serverIp');
    print('Client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
  }

  DhcpPkt(Pointer<RawDhcpPacket> resultPointer) {
    final ifaceArray = resultPointer.ref.iface;
    final data = resultPointer.ref.data;
    final length = resultPointer.ref.length;

    // Get the interface name as a string
    iface = getStringFromPointer(ifaceArray.sublist(0, IFNAMSIZ), IFNAMSIZ);

    // Parse fixed fields
    op = data[0];
    htype = data[1];
    hlen = data[2];
    hops = data[3];
    xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    secs = (data[8] << 8) | data[9];
    flags = (data[10] << 8) | data[11];
    ciaddr = [data[12], data[13], data[14], data[15]];
    yiaddr = [data[16], data[17], data[18], data[19]];
    siaddr = [data[20], data[21], data[22], data[23]];
    giaddr = [data[24], data[25], data[26], data[27]];
    chaddr = data.sublist(28, 34);

    final snameArr = data.sublist(44, 108);
    sname = getStringFromPointer(snameArr, 64);
    file = getStringFromPointer(data.sublist(108, 236), 128);

    // Parse variable fields
    options = {};
    int offset = 240;
    while (offset < length) {
      int optionCode = data[offset++];
      if (optionCode == 0) {
        continue; // Padding
      } else if (optionCode == 255) {
        break; // End of options
      }
      int optionLength = data[offset++];
      List<int> optionValue = data.sublist(offset, offset + optionLength);
      options[optionCode] = optionValue;

      offset += optionLength;
    }
  }

  void printParsedData() {
    print('Parsed Data:');
    print('Op: $op');
    print('Htype: $htype');
    print('Hlen: $hlen');
    print('Hops: $hops');
    print('Xid: $xid');
    print('Secs: $secs');
    print('Flags: $flags');
    print('Ciaddr: ${ciaddr.join('.')}');
    print('Yiaddr: ${yiaddr.join('.')}');

    printOptions();
  }

  void printHexData(Array<Uint8> data, int length) {
    print("Data in hexadecimal and corresponding characters:");
    for (int i = 0; i < length; i++) {
      if (i % 16 == 0) {
        // Every 16 bytes new line
        if (i != 0) {
          // If not first line, print previous line's characters first
          stdout.write("  ");
          for (int j = i - 16; j < i; j++) {
            if (data[j] >= 32 && data[j] <= 126) {
              // Only print visible characters
              stdout.write("${String.fromCharCode(data[j])} ");
            } else {
              stdout.write(". "); // Non-visible characters replaced with '.'
            }
          }
          print("");
        }
        stdout.write("${data[i].toRadixString(16).padLeft(2, '0')} "); // Print hexadecimal value
      } else {
        stdout.write("${data[i].toRadixString(16).padLeft(2, '0')} "); // Print hexadecimal
      }
    }
    // Print last line's characters
    if (length % 16 != 0) {
      print("  ");
      for (int j = length - (length % 16); j < length; j++) {
        if (data[j] >= 32 && data[j] <= 126) {
          // Only print visible characters
          print("${String.fromCharCode(data[j])} ");
        } else {
          print(". "); // Non-visible characters replaced with '.'
        }
      }
    }
    print("\n");
  }

  String? getOptionAsString(int optionCode) {
    if (options.containsKey(optionCode)) {
      final value = options[optionCode];
      if (value != null) {
        // Specific options directly converted to string
        if (optionCode == 12 || // Host Name
            optionCode == 15 || // Domain Name
            optionCode == 17 || // Root Path
            optionCode == 66 || // TFTP Server Name
            optionCode == 67 ||
            optionCode == 224) {
          return String.fromCharCodes(value);
        }
        // Other options returned as hexadecimal
        return value.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':');
      }
    }
    return null; // Return null if option does not exist
  }

  void printOptions() {
    const Map<int, String> optionNames = {
      OPTION_SUBNET_MASK: 'Subnet Mask',
      OPTION_TIME_OFFSET: 'Time Offset',
      OPTION_ROUTER: 'Router',
      OPTION_NAME_SERVER: 'Name Server',
      OPTION_DOMAIN_NAME_SERVER: 'Domain Name Server',
      OPTION_HOST_NAME: 'Host Name',
      OPTION_BOOTFILE_SIZE: 'Bootfile Size',
      OPTION_DOMAIN_NAME: 'Domain Name',
      OPTION_ROOT_PATH: 'Root Path',
      OPTION_IP_FORWARDING: 'IP Forwarding Enable/Disable',
      OPTION_INTERFACE_MTU: 'Interface MTU',
      OPTION_BROADCAST_ADDRESS: 'Broadcast Address',
      OPTION_NTP_SERVERS: 'Network Time Protocol Servers',
      OPTION_VENDOR_SPECIFIC_INFO: 'Vendor-Specific Information',
      OPTION_NETBIOS_NAME_SERVER: 'NETBIOS Name Srv',
      OPTION_NETBIOS_NODE_TYPE: 'NETBIOS Node Type',
      OPTION_REQUESTED_IP_ADDRESS: 'Requested IP Address',
      OPTION_IP_ADDRESS_LEASE_TIME: 'IP Address Lease Time',
      OPTION_DHCP_MESSAGE_TYPE: 'DHCP Message Type',
      OPTION_SERVER_IDENTIFIER: 'Server Identifier',
      OPTION_PARAMETER_REQUEST_LIST: 'Parameter Request List',
      OPTION_RENEWAL_TIME: 'Renewal Time',
      OPTION_REBINDING_TIME: 'Rebinding Time',
      OPTION_CLIENT_IDENTIFIER: 'Client Identifier',
      OPTION_TFTP_SERVER_NAME: 'TFTP Server Name',
      OPTION_BOOTFILE_NAME: 'Bootfile Name',
      OPTION_DOMAIN_SEARCH: 'Domain Search',
      OPTION_CLASSLESS_STATIC_ROUTE: 'Classless Static Route',
      OPTION_VENDOR_SPECIFIC_INFO_224: 'Vendor-Specific Information',
    };

    print('Available DHCP Options:');
    options.forEach((code, value) {
      final optionName = optionNames[code] ?? 'Unknown Option';
      String optionValue;
      optionValue = getOptionAsString(code) ?? "No Value";

      print('$code: $optionName = $optionValue');
    });
  }

  void handleDhcpRelease() {
    // DHCP RELEASE is used to inform the server that the client is releasing its IP address
    // This can be used to free up the IP address for other clients to use
    final clientMac = chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':');
    final clientIp = ciaddr.join('.');
    print('Releasing IP: $clientIp for client MAC: $clientMac');
    releaseIpInDB(clientIp, clientMac);

    // The server needs not respond to this message
    return;
  }
}

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
    final db = sqlite3.open(DB_FILE_NAME);
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
      startIp: _parseIpAddress(map['startIp']),
      endIp: _parseIpAddress(map['endIp']),
      subnetMask: _parseIpAddress(map['subnetMask']),
      gateway: _parseIpAddress(map['gateway']),
      dnsServers: List<String>.from(map['dnsServers']).map(_parseIpAddress).toList(),
      leaseTime: map['leaseTime'],
      domain: map['domain'],
      dhcpServer: _parseIpAddress(map['dhcpServer']), // Assuming gateway as DHCP server
      broadcastAddress: _parseIpAddress(map['broadcastAddress']),
      bindings: Map<String, String>.from(map['bindings'] ?? {}),
    );
  }

  static IpAddress _parseIpAddress(String ip) {
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
          startIp: DhcpPool._parseIpAddress(startIp),
          endIp: DhcpPool._parseIpAddress(endIp),
          subnetMask: DhcpPool._parseIpAddress('255.255.255.0'), // Default subnet mask
          gateway: DhcpPool._parseIpAddress(gateway),
          dnsServers: List<String>.from(dnsServers).map(DhcpPool._parseIpAddress).toList(),
          leaseTime: 86400, // Default lease time
          domain: domain,
          dhcpServer: dhcpServer,
          broadcastAddress: DhcpPool._parseIpAddress(broadcastAddress),
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

bool isInvalidMac(String mac) => !RegExp(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$').hasMatch(mac);

Future<IpAddress> getInterfaceIpInSubnet(String ifaceName, String startIp) async {
  final interfaces = await NetworkInterface.list();
  for (final interface in interfaces) {
    if (interface.name == ifaceName) {
      for (final address in interface.addresses) {
        final ipParts = address.address.split('.');
        final startIpParts = startIp.split('.');
        if (ipParts.length == 4 && ipParts[0] == startIpParts[0] && ipParts[1] == startIpParts[1] && ipParts[2] == startIpParts[2]) {
          return DhcpPool._parseIpAddress(address.address);
        }
      }
    }
  }
  throw Exception('No IP address found in the subnet for interface $ifaceName');
}

bool isInvalidString(String s) {
  if (s.isEmpty || s.length > IFNAMSIZ || s.contains(RegExp(r'[^a-zA-Z0-9_.-]'))) {
    return true;
  }
  return false;
}

bool isInvalidIp(String ip) {
  final parts = ip.split('.');
  if (parts.length != 4) {
    return true; // Invalid if not 4 octets
  }
  for (final part in parts) {
    final intValue = int.tryParse(part);
    if (intValue == null || intValue < 0 || intValue > 255) {
      return true; // Invalid if any octet is not in range
    }
  }
  return false; // Valid IP
}
