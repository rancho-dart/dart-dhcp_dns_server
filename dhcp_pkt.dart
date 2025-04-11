import 'dhcp_c_interface.dart';

import 'dart:ffi';
import 'package:ffi/ffi.dart'; // Import ffi package for calloc
import 'constants.dart';
import 'dart:io';
import 'package:sqlite3/sqlite3.dart';
import 'dhcp_pool.dart';
import 'common_routines.dart';

// final dhcpCInterface = DhcpCInterface();

// Function to convert Pointer<Uint8> to Dart String
String getStringFromPointer(List<int> list, int maxLength) {
  final List<int> byteList = [];

  for (int i = 0; i < maxLength; i++) {
    if (list[i] == 0) break; // End on '\0'
    byteList.add(list[i]);
  }

  return String.fromCharCodes(byteList);
}

extension Uint8ArrayExtension on Array<Uint8> {
  List<int> sublist(int i, int j) {
    return List<int>.generate(j - i, (index) => this[i + index]);
  }

  void setRange(int i, int j, List<int> ciaddr) {
    for (int index = i; index < j; index++) {
      this[index] = ciaddr[index - i];
    }
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

    sendDhcpPacket(pools, iface, clientMac, leaseIp, DHCP_OFFER);
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
        sendDhcpPacket(pools, iface, clientMac, leaseIp, DHCP_ACK);
        print('Allocated IP: ${leaseIp.join('.')} to client MAC: $clientMac');
      } else {
        // If no lease record exists, reply with a DHCP NAK
        print('No lease record found for IP: $requestedIp and MAC: $clientMac. Sending DHCP NAK.');
        sendDhcpPacket(pools, iface, clientMac, [0, 0, 0, 0], DHCP_NAK);
        return; // Exit the function as no valid lease is available
      }
    } catch (e) {
      print('An error occurred: $e');
    } finally {
      db.dispose();
    }
  }

  void sendDhcpPacket(Map<String, DhcpPool> pools, String iface, String clientMac, List<int> yiaddr, int messageType) {
    final packet = calloc<RawPacket>();
    try {
      final data = packet.ref.udpData;

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
      packet.ref.udpDataLength = offset;
      for (int i = 0; i < IFNAMSIZ; i++) {
        packet.ref.ifaceName[i] = 0;
      }
      packet.ref.ifaceName.setRange(0, iface.length, iface.codeUnits);
      packet.ref.ifaceName[iface.length] = 0; // Null-terminate the interface name

      // Send the DHCP packet
      final sendResult = dhcpCInterface.callSendDhcpPacket(packet);
      if (sendResult == 0) {
        print('DHCP ${messageType == DHCP_OFFER ? 'OFFER' : messageType == DHCP_ACK ? 'ACK' : 'NAK'} sent successfully.');
        print('Packet sent at: ${DateTime.now()}');
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

  DhcpPkt(Pointer<RawPacket> resultPointer) {
    final ifaceArray = resultPointer.ref.ifaceName;
    final data = resultPointer.ref.udpData;
    final length = resultPointer.ref.udpDataLength;

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
