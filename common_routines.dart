import 'dhcp_c_interface.dart';

bool isInvalidMac(String mac) => !RegExp(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$').hasMatch(mac);

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
