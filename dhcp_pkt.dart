import 'dhcp_c_interface.dart';
import 'dart:ffi';

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
    print('=== Message Type: $messageType ===');
    print('Client IP: ${yiaddr.join(".")}');
    print('Server IP: ${siaddr.join(".")}');
    print('Client MAC: ${chaddr.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
  }

  // Add other methods as needed...
}
