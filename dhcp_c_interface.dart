import 'dart:ffi';

const String C_LIB_FILE_NAME = './dhcp_iface.so';

// Define constants
const int IFNAMSIZ = 16; // Typical interface name size
const int MAX_PACKET_SIZE = 4096; // Maximum packet size

// Define DhcpPacketResult structure
base class RawPacket extends Struct {
  @Array<Uint8>(IFNAMSIZ)
  external Array<Uint8> ifaceName;

  @Int32()
  external int udpDataLength;

  @Array<Uint8>(MAX_PACKET_SIZE)
  external Array<Uint8> udpData;
}

typedef RawDhcpNative = Int32 Function(Pointer<RawPacket> result);
typedef RawDhcp = int Function(Pointer<RawPacket> result);

class DhcpCInterface {
  final DynamicLibrary _dylib;
  late final RawDhcp _recvDhcpPacket;
  late final RawDhcp _sendDhcpPacket;

  DhcpCInterface() : _dylib = DynamicLibrary.open(C_LIB_FILE_NAME) {
    _recvDhcpPacket = _dylib.lookupFunction<RawDhcpNative, RawDhcp>('recv_dhcp_packet_with_iface');
    _sendDhcpPacket = _dylib.lookupFunction<RawDhcpNative, RawDhcp>('send_dhcp_packet_with_iface');
  }

  void printErrorMessage(int returnCode) {
    final errorMessages = {
      -1: 'Error: Invalid interface name',
      -2: 'Error: Packet too large',
      -3: 'Error: No DHCP packets received',
      -4: 'Error: Invalid DHCP packet',
      -5: 'Error: No memory available',
      -6: 'Error: Invalid packet length',
      -7: 'Error: Invalid interface index',
      -8: 'Error: Invalid socket descriptor',
      -9: 'Error: Invalid packet format',
      -10: 'Error: Invalid packet checksum',
      -11: 'Error: Invalid packet source address',
    };

    print(errorMessages[returnCode] ?? 'Failed to receive DHCP packet. Return code: $returnCode');
  }

  int callRecvDhcpPacket(Pointer<RawPacket> resultPointer) {
    return _recvDhcpPacket(resultPointer);
  }

  int callSendDhcpPacket(Pointer<RawPacket> resultPointer) {
    return _sendDhcpPacket(resultPointer);
  }
}

final DhcpCInterface dhcpCInterface = DhcpCInterface();
