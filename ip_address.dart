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
