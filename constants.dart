const String DB_FILE_NAME = 'dhcp_leases.db';
const String CONFIG_FILE_NAME = 'config.yaml';
const String C_LIB_FILE_NAME = './dhcp_iface.so';

// Define DHCP option constants
const int OPTION_SUBNET_MASK = 1;
const int OPTION_TIME_OFFSET = 2;
const int OPTION_ROUTER = 3;
const int OPTION_NAME_SERVER = 5;
const int OPTION_DOMAIN_NAME_SERVER = 6;
const int OPTION_HOST_NAME = 12;
const int OPTION_BOOTFILE_SIZE = 13;
const int OPTION_DOMAIN_NAME = 15;
const int OPTION_ROOT_PATH = 17;
const int OPTION_IP_FORWARDING = 19;
const int OPTION_INTERFACE_MTU = 26;
const int OPTION_BROADCAST_ADDRESS = 28;
const int OPTION_NTP_SERVERS = 42;
const int OPTION_VENDOR_SPECIFIC_INFO = 43;
const int OPTION_NETBIOS_NAME_SERVER = 44;
const int OPTION_NETBIOS_NODE_TYPE = 47;
const int OPTION_REQUESTED_IP_ADDRESS = 50;
const int OPTION_IP_ADDRESS_LEASE_TIME = 51;
const int OPTION_DHCP_MESSAGE_TYPE = 53;
const int OPTION_SERVER_IDENTIFIER = 54;
const int OPTION_PARAMETER_REQUEST_LIST = 55;
const int OPTION_RENEWAL_TIME = 58;
const int OPTION_REBINDING_TIME = 59;
const int OPTION_CLIENT_IDENTIFIER = 61;
const int OPTION_TFTP_SERVER_NAME = 66;
const int OPTION_BOOTFILE_NAME = 67;
const int OPTION_DOMAIN_SEARCH = 119;
const int OPTION_CLASSLESS_STATIC_ROUTE = 121;
const int OPTION_VENDOR_SPECIFIC_INFO_224 = 224;
const int OPTION_END = 255;

// Define DHCP message type constants if not already defined
const int DHCP_DISCOVER = 1;
const int DHCP_OFFER = 2;
const int DHCP_REQUEST = 3;
const int DHCP_DECLINE = 4;
const int DHCP_ACK = 5;
const int DHCP_NAK = 6;
const int DHCP_RELEASE = 7;
const int DHCP_INFORM = 8;

// const int IFNAMSIZ = 16; // Define IFNAMSIZ with an appropriate value
