
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

// #define IFNAMSIZ 16
#define MAX_PACKET_SIZE 4096

struct RawDhcpPacket {
    char iface[IFNAMSIZ];
    int length;
    unsigned char data[MAX_PACKET_SIZE];
};

int send_dhcp_packet_with_iface(struct RawDhcpPacket* dhcp_pkt) {
  int sockfd;
  struct sockaddr_in addr;
  struct ifreq ifr;

  // Create a socket
  sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  // Set the interface to send the packet on
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dhcp_pkt->iface, IFNAMSIZ - 1);
  printf("Setting interface to %s\n", ifr.ifr_name);
  if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)) < 0) {
    perror("setsockopt");
    close(sockfd);
    return -2;
  }
  // Create a buffer for the packet, leaving space for Ethernet, IP, and UDP headers
  unsigned char packet[MAX_PACKET_SIZE];
  memset(packet, 0, sizeof(packet));

  struct ethhdr* eth_header = (struct ethhdr*)packet;
  struct iphdr* ip_header = (struct iphdr*)(eth_header + 1);
  struct udphdr* udp_header = (struct udphdr*)(ip_header + 1);
  unsigned char * dhcp_data = (unsigned char *)(udp_header + 1);
  
  // Copy the DHCP data into the packet after the Ethernet, IP, and UDP headers
  memcpy(dhcp_data, dhcp_pkt->data, dhcp_pkt->length);
  int packet_length = dhcp_pkt->length + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
  
  
  // set up the ethernet header
  memcpy(eth_header->h_dest, dhcp_data + 28, ETH_ALEN); // Copy the target MAC address to the destination MAC address
  // Get the MAC address of the interface
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    close(sockfd);
    return -3;
  }
  memcpy(eth_header->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN); // Set source MAC address
  eth_header->h_proto = htons(ETH_P_IP); // Set the protocol type to IP
  
  // Set up the IP header
  ip_header->ihl = 5; // Internet Header Length
  ip_header->version = 4; // IPv4
  ip_header->tos = 0; // Type of Service
  ip_header->tot_len = htons(dhcp_pkt->length + sizeof(struct iphdr) + sizeof(struct udphdr)); // Total length
  ip_header->id = htons(54321); // Identification
  ip_header->frag_off = 0; // Fragment offset
  ip_header->ttl = 64; // Time to Live
  ip_header->protocol = IPPROTO_UDP; // Protocol
  ip_header->check = 0; // Checksum (calculated later)

  // Extract yiaddr (your IP address) and server IP from the DHCP data
  unsigned char* yiaddr = dhcp_data + 16; // yiaddr is at offset 16 in the DHCP payload
  unsigned char* server_ip = dhcp_data + 20; // server IP (siaddr) is at offset 20 in the DHCP payload

  // Set the IP header source and destination addresses
  ip_header->saddr = *(uint32_t*)server_ip; // Server IP address
  ip_header->daddr = *(uint32_t*)yiaddr;    // Client IP address (yiaddr)


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
  udp_header->dest = htons(68);   // Send to dhcp client port   
  udp_header->source = htons(67); // Send from dhcp server port
  udp_header->len = htons(dhcp_pkt->length + sizeof(struct udphdr)); // UDP length
  udp_header->check = 0; // Checksum (optional, can be 0 for UDP over IPv4)

  // Extract the target MAC address (chaddr) from the DHCP packet
  struct sockaddr_ll device = {0};
  device.sll_family = AF_PACKET;
  device.sll_protocol = htons(ETH_P_IP);
  device.sll_ifindex = if_nametoindex(dhcp_pkt->iface);
  device.sll_halen = ETH_ALEN;
  memcpy(device.sll_addr, eth_header->h_dest, ETH_ALEN);


  // Update the sendto call to use the sockaddr_ll structure
  // printf("Sending packet, length: %d\n", packet_length);
  // Send the packet
  if (sendto(sockfd, packet, packet_length, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
    perror("sendto");
    close(sockfd);
    return -4;
  }

  close(sockfd);
  return 0;
}

void print_in_hex(struct RawDhcpPacket *result);

// Return DHCP packet and the interface name it was received on
int recv_dhcp_packet_with_iface(struct RawDhcpPacket* result) {
    int sockfd;
    struct sockaddr_in addr;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char ctrl_buf[1024];
    struct in_pktinfo *pktinfo;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // Allow port reuse for debugging
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    // Enable pktinfo retrieval
    int on = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(67);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -2;
    }

    memset(&msg, 0, sizeof(msg));
    memset(result, 0, sizeof(*result));

    iov.iov_base = result->data;
    iov.iov_len = MAX_PACKET_SIZE;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf;
    msg.msg_controllen = sizeof(ctrl_buf);

    if ((result->length = recvmsg(sockfd, &msg, 0)) < 0) {
        perror("recvmsg");
        close(sockfd);
        return -3;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
            if_indextoname(pktinfo->ipi_ifindex, result->iface);
            break;
        }
    }

    // print_in_hex(result);

    close(sockfd);
    return 0;
}

void print_in_hex(struct RawDhcpPacket *result)
{
  // Print all data in result->data, output hexadecimal values and corresponding characters
  printf("Data in hexadecimal and corresponding characters:\n");
  for (int i = 0; i < result->length; i++)
  {
    if (i % 16 == 0)
    { // New line every 16 bytes
      if (i != 0)
      { // If not the first line, print characters of the previous line
        printf("  ");
        for (int j = i - 16; j < i; j++)
        {
          if (result->data[j] >= 32 && result->data[j] <= 126)
          { // Only print visible characters
            printf("%c ", result->data[j]);
          }
          else
          {
            printf(". "); // Use '.' for invisible characters
          }
        }
        printf("\n");
      }
      printf("%02x ", result->data[i]); // Print hexadecimal value
    }
    else
    {
      printf("%02x ", result->data[i]); // Print hexadecimal value
    }
  }
  // Print characters of the last line
  if (result->length % 16 != 0)
  {
    printf("  ");
    for (int j = result->length - (result->length % 16); j < result->length; j++)
    {
      if (result->data[j] >= 32 && result->data[j] <= 126)
      { // Only print visible characters
        printf("%c ", result->data[j]);
      }
      else
      {
        printf(". "); // Use '.' for invisible characters
      }
    }
  }
  printf("\n");
}
