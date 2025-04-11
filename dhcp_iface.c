#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>

// #define IFNAMSIZ 16
#define MAX_PACKET_SIZE 4096

struct RawPacket {
  char iface_name[IFNAMSIZ];
  int udp_data_length;
  unsigned char udp_data[MAX_PACKET_SIZE];
};

static int persistent_sockfd_dhcp_send = -1;
static int persistent_sockfd_dhcp_recv = -1;
static int persistent_sockfd_dns_send = -1;
static int persistent_sockfd_dns_recv = -1;


void print_current_time(char * task) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  struct tm *tm_info = localtime(&ts.tv_sec);
  char time_buffer[64];
  strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

  printf("Task: %s, Current time: %s.%03ld\n", task, time_buffer, ts.tv_nsec / 1000000);
}

int setup_send_socket(int *sockfd, const char *iface_name) {
  struct ifreq ifr;

  if (*sockfd == -1) {
    *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (*sockfd < 0) {
      perror("socket");
      return -1;
    }
  }

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
  if (setsockopt(*sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)) < 0) {
    perror("setsockopt");
    return -2;
  }

  return 0;
}

int send_packet_with_iface(int *sockfd, struct RawPacket* pkt, int dest_port, int src_port) {
  unsigned char packet[MAX_PACKET_SIZE];
  struct ethhdr* eth_header = (struct ethhdr*)packet;
  struct iphdr* ip_header = (struct iphdr*)(eth_header + 1);
  struct udphdr* udp_header = (struct udphdr*)(ip_header + 1);
  unsigned char *data = (unsigned char *)(udp_header + 1);

  if (setup_send_socket(sockfd, pkt->iface_name) < 0) {
    return -1;
  }

  memcpy(data, pkt->udp_data, pkt->udp_data_length);
  int packet_length = pkt->udp_data_length + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

  // Set up the Ethernet header
  memcpy(eth_header->h_dest, data + 28, ETH_ALEN); // Copy the target MAC address to the destination MAC address
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, pkt->iface_name, IFNAMSIZ - 1);
  if (ioctl(*sockfd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -3;
  }
  memcpy(eth_header->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN); // Set source MAC address
  eth_header->h_proto = htons(ETH_P_IP); // Set the protocol type to IP

  // Set up the IP header
  ip_header->ihl = 5; // Internet Header Length
  ip_header->version = 4; // IPv4
  ip_header->tos = 0; // Type of Service
  ip_header->tot_len = htons(pkt->udp_data_length + sizeof(struct iphdr) + sizeof(struct udphdr)); // Total length
  ip_header->id = htons(54321); // Identification
  ip_header->frag_off = 0; // Fragment offset
  ip_header->ttl = 64; // Time to Live
  ip_header->protocol = IPPROTO_UDP; // Protocol
  ip_header->check = 0; // Checksum (calculated later)

  // Extract source and destination IPs from the data
  unsigned char* src_ip = data + 12; // Source IP is at offset 12 in the payload
  unsigned char* dest_ip = data + 16; // Destination IP is at offset 16 in the payload

  ip_header->saddr = *(uint32_t*)src_ip; // Source IP address
  ip_header->daddr = *(uint32_t*)dest_ip; // Destination IP address

  // Calculate the IP checksum
  unsigned short* ip_header_words = (unsigned short*)ip_header;
  unsigned int checksum = 0;
  for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
    checksum += ip_header_words[i];
  }
  while (checksum >> 16) {
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
  }
  ip_header->check = ~checksum;

  // Set up the UDP header
  udp_header->source = htons(src_port); // Send from source port
  udp_header->dest = htons(dest_port);   // Send to destination port
  udp_header->len = htons(pkt->udp_data_length + sizeof(struct udphdr)); // UDP length
  udp_header->check = 0; // Checksum (optional, can be 0 for UDP over IPv4)

  struct sockaddr_ll device = {0};
  device.sll_family = AF_PACKET;
  device.sll_protocol = htons(ETH_P_IP);
  device.sll_ifindex = if_nametoindex(pkt->iface_name);
  device.sll_halen = ETH_ALEN;
  memcpy(device.sll_addr, eth_header->h_dest, ETH_ALEN);

  if (sendto(*sockfd, packet, packet_length, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
    perror("sendto");
    return -4;
  }

  return 0;
}

int send_dhcp_packet_with_iface(struct RawPacket* dhcp_pkt) {
  return send_packet_with_iface(&persistent_sockfd_dhcp_send, dhcp_pkt, 68, 67);
}

int send_dns_packet_with_iface(struct RawPacket* dns_pkt) {
  return send_packet_with_iface(&persistent_sockfd_dns_send, dns_pkt, 53, 53);
}

void print_in_hex(struct RawPacket *result);


int setup_recv_socket(int *sockfd, int port) {
  struct sockaddr_in addr;

  if (*sockfd == -1) {
    *sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*sockfd < 0) {
      perror("socket");
      return -1;
    }

    int reuse = 1;
    setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    int on = 1;
    setsockopt(*sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(*sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
      perror("bind");
      close(*sockfd);
      *sockfd = -1;
      return -2;
    }
  }

  return 0;
}

int recv_packet_with_iface(int *sockfd, int port, struct RawPacket* result) {
  static char ctrl_buf[1024];
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct in_pktinfo *pktinfo;

  if (setup_recv_socket(sockfd, port) < 0) {
    return -1;
  }

  memset(&msg, 0, sizeof(msg));
  memset(result, 0, sizeof(*result));

  iov.iov_base = result->udp_data;
  iov.iov_len = MAX_PACKET_SIZE;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctrl_buf;
  msg.msg_controllen = sizeof(ctrl_buf);

  if ((result->udp_data_length = recvmsg(*sockfd, &msg, 0)) < 0) {
    perror("recvmsg");
    return -3;
  }

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
      pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
      if_indextoname(pktinfo->ipi_ifindex, result->iface_name);
      break;
    }
  }

  return 0;
}

int recv_dhcp_packet_with_iface(struct RawPacket* result) {
  return recv_packet_with_iface(&persistent_sockfd_dhcp_recv, 67, result);
}

int recv_dns_packet_with_iface(struct RawPacket* result) {
  return recv_packet_with_iface(&persistent_sockfd_dns_recv, 53, result);
}

void print_in_hex(struct RawPacket *result)
{
  // Print all data in result->data, output hexadecimal values and corresponding characters
  printf("Data in hexadecimal and corresponding characters:\n");
  for (int i = 0; i < result->udp_data_length; i++)
  {
    if (i % 16 == 0)
    { // New line every 16 bytes
      if (i != 0)
      { // If not the first line, print characters of the previous line
        printf("  ");
        for (int j = i - 16; j < i; j++)
        {
          if (result->udp_data[j] >= 32 && result->udp_data[j] <= 126)
          { // Only print visible characters
            printf("%c ", result->udp_data[j]);
          }
          else
          {
            printf(". "); // Use '.' for invisible characters
          }
        }
        printf("\n");
      }
      printf("%02x ", result->udp_data[i]); // Print hexadecimal value
    }
    else
    {
      printf("%02x ", result->udp_data[i]); // Print hexadecimal value
    }
  }
  // Print characters of the last line
  if (result->udp_data_length % 16 != 0)
  {
    printf("  ");
    for (int j = result->udp_data_length - (result->udp_data_length % 16); j < result->udp_data_length; j++)
    {
      if (result->udp_data[j] >= 32 && result->udp_data[j] <= 126)
      { // Only print visible characters
        printf("%c ", result->udp_data[j]);
      }
      else
      {
        printf(". "); // Use '.' for invisible characters
      }
    }
  }
  printf("\n");
}
