#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <resolv.h> // 用于DNS查询
#include <netdb.h>  // 用于gethostbyname
#include <yaml.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <time.h>
#include "dart_header.h"

#define DART_PROTOCOL 254
#define BUFFER_SIZE 65536
#define MAX_INTERFACES 10
#define MAC_CACHE_SIZE 100

// 定义接口配置结构体
typedef struct {
    char name[32];
    char ip_address[32];
    char domain[32];
    uint8_t mac_address[ETH_ALEN]; // 新增字段：MAC地址
} interface_config_t;

typedef struct {
    struct in_addr ip;
    uint8_t mac[ETH_ALEN];
    time_t timestamp;
} mac_cache_entry_t;

interface_config_t interfaces[MAX_INTERFACES];
int interface_count = 0;
mac_cache_entry_t mac_cache[MAC_CACHE_SIZE];
int mac_cache_count = 0;


void load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open config file");
        exit(1);
    }

    yaml_parser_t parser;
    yaml_token_t token;

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        exit(1);
    }

    yaml_parser_set_input_file(&parser, file);

    char current_key[32] = "";
    interface_config_t *current_interface = NULL;

    while (1) {
        yaml_parser_scan(&parser, &token);

        if (token.type == YAML_STREAM_END_TOKEN) {
            yaml_token_delete(&token);
            break;
        }

        if (token.type == YAML_KEY_TOKEN) {
            yaml_parser_scan(&parser, &token);
            if (token.type == YAML_SCALAR_TOKEN) {
                strncpy(current_key, (char *)token.data.scalar.value, sizeof(current_key) - 1);
            }
        } else if (token.type == YAML_VALUE_TOKEN) {
            yaml_parser_scan(&parser, &token);
            if (token.type == YAML_SCALAR_TOKEN) {
                if (strcmp(current_key, "name") == 0) {
                    if (interface_count >= MAX_INTERFACES) {
                        fprintf(stderr, "Too many interfaces in config\n");
                        exit(1);
                    }
                    current_interface = &interfaces[interface_count++];
                    strncpy(current_interface->name, (char *)token.data.scalar.value, sizeof(current_interface->name) - 1);
                } else if (strcmp(current_key, "domain") == 0 && current_interface) {
                    strncpy(current_interface->domain, (char *)token.data.scalar.value, sizeof(current_interface->domain) - 1);
                } else if (strcmp(current_key, "gateway") == 0 && current_interface) {
                    strncpy(current_interface->ip_address, (char *)token.data.scalar.value, sizeof(current_interface->ip_address) - 1);
                }
            }
        }

        yaml_token_delete(&token);
    }

    yaml_parser_delete(&parser);
    fclose(file);

    for (int i = 0; i < interface_count; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            exit(1);
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interfaces[i].name, sizeof(ifr.ifr_name) - 1);

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("Failed to get MAC address");
            close(sock);
            exit(1);
        }

        memcpy(interfaces[i].mac_address, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        close(sock);
    }
}

// 解析DART报文
dart_packet_t *parse_dart_packet(uint8_t *data, size_t length) {
    if (length < 3) {
        fprintf(stderr, "Invalid packet length\n");
        return NULL;
    }

    dart_packet_t *packet = (dart_packet_t *)malloc(sizeof(dart_packet_t));
    packet->protocol_number = data[0];
    packet->dest_addr_len = data[1];
    packet->src_addr_len = data[2];

    size_t offset = 3;
    packet->dest_addr = (char *)malloc(packet->dest_addr_len + 1);
    memcpy(packet->dest_addr, data + offset, packet->dest_addr_len);
    packet->dest_addr[packet->dest_addr_len] = '\0'; // 确保字符串以\0结尾
    offset += packet->dest_addr_len;

    packet->src_addr = (char *)malloc(packet->src_addr_len + 1);
    memcpy(packet->src_addr, data + offset, packet->src_addr_len);
    packet->src_addr[packet->src_addr_len] = '\0'; // 确保字符串以\0结尾

    return packet;
}

// 释放DART报文
void free_dart_packet(dart_packet_t *packet) {
    if (packet) {
        free(packet->dest_addr);
        free(packet->src_addr);
        free(packet);
    }
}

int get_matchest_iface(char *dest_addr) {
    int best_match_index = -1;
    size_t best_match_length = 0;

    for (int i = 0; i < interface_count; i++) {
        size_t iface_domain_len = strlen(interfaces[i].domain);
        size_t dest_addr_len = strlen(dest_addr);

        // 从后向前匹配
        if (dest_addr_len >= iface_domain_len &&
            strcmp(dest_addr + dest_addr_len - iface_domain_len, interfaces[i].domain) == 0) {
            if (iface_domain_len > best_match_length) {
                best_match_length = iface_domain_len;
                best_match_index = i;
            }
        }
    }

    return best_match_index;
}

// 计算IP头部校验和
uint16_t calculate_checksum(uint16_t *header, int length) {
    uint32_t sum = 0;

    // 累加所有16位字
    while (length > 1) {
        sum += *header++;
        length -= 2;
    }

    // 如果长度是奇数，处理最后一个字节
    if (length == 1) {
        sum += *(uint8_t *)header;
    }

    // 将高16位加到低16位
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    // 取反，得到校验和
    return (uint16_t)(~sum);
}

// Forwarder函数，返回下一跳IP地址
uint32_t next_hop_for(dart_packet_t *dart_packet) {
    if (!dart_packet || !dart_packet->dest_addr) {
        fprintf(stderr, "Invalid DART packet or destination address\n");
        return 0; // 返回0表示查询失败
    }

    printf("Performing DNS query for: %s\n", dart_packet->dest_addr);

    // 初始化DNS解析器
    struct __res_state res;
    if (res_ninit(&res) != 0) {
        fprintf(stderr, "Failed to initialize resolver\n");
        return 0; // 返回0表示查询失败
    }

    // 设置DNS服务器为127.0.0.1
    res.nsaddr_list[0].sin_addr.s_addr = inet_addr("127.0.0.1");
    res.nsaddr_list[0].sin_family = AF_INET;
    res.nsaddr_list[0].sin_port = htons(53); // DNS默认端口53
    res.nscount = 1;

    // 使用res_query进行DNS查询
    unsigned char query_buffer[BUFFER_SIZE];
    int query_len = res_query(dart_packet->dest_addr, C_IN, T_A, query_buffer, sizeof(query_buffer));
    if (query_len < 0) {
        fprintf(stderr, "DNS query failed for %s\n", dart_packet->dest_addr);
        res_nclose(&res);
        return 0; // 返回0表示查询失败
    }

    // 解析DNS响应
    ns_msg handle;
    if (ns_initparse(query_buffer, query_len, &handle) < 0) {
        fprintf(stderr, "Failed to parse DNS response for %s\n", dart_packet->dest_addr);
        res_nclose(&res);
        return 0; // 返回0表示查询失败
    }

    // 获取第一个A记录的IP地址
    uint32_t next_hop_ip = 0;
    int rr_count = ns_msg_count(handle, ns_s_an); // 获取回答部分的记录数
    for (int i = 0; i < rr_count; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            if (ns_rr_type(rr) == ns_t_a) { // 检查是否是A记录
                next_hop_ip = *(uint32_t *)ns_rr_rdata(rr);
                break;
            }
        }
    }

    if (next_hop_ip == 0) {
        fprintf(stderr, "No A record found for %s\n", dart_packet->dest_addr);
        res_nclose(&res);
        return 0; // 返回0表示查询失败
    }

    // 打印查询到的IP地址
    struct in_addr addr;
    addr.s_addr = next_hop_ip;
    printf("DNS query result: %s -> %s\n", dart_packet->dest_addr, inet_ntoa(addr));

    // 关闭DNS解析器
    res_nclose(&res);

    return next_hop_ip;
}

bool find_mac_in_cache(struct in_addr ip, uint8_t *mac) {
    time_t now = time(NULL);
    for (int i = 0; i < mac_cache_count; i++) {
        if (mac_cache[i].ip.s_addr == ip.s_addr) {
            if (difftime(now, mac_cache[i].timestamp) < 300) { // 缓存有效期300秒
                memcpy(mac, mac_cache[i].mac, ETH_ALEN);
                return true;
            } else {
                // 缓存过期，移除条目
                mac_cache[i] = mac_cache[--mac_cache_count];
                i--;
            }
        }
    }
    return false;
}

void add_mac_to_cache(struct in_addr ip, uint8_t *mac) {
    if (mac_cache_count < MAC_CACHE_SIZE) {
        mac_cache[mac_cache_count].ip = ip;
        memcpy(mac_cache[mac_cache_count].mac, mac, ETH_ALEN);
        mac_cache[mac_cache_count].timestamp = time(NULL);
        mac_cache_count++;
    } else {
        // 如果缓存已满，替换最旧的条目
        int oldest_index = 0;
        for (int i = 1; i < mac_cache_count; i++) {
            if (mac_cache[i].timestamp < mac_cache[oldest_index].timestamp) {
                oldest_index = i;
            }
        }
        mac_cache[oldest_index].ip = ip;
        memcpy(mac_cache[oldest_index].mac, mac, ETH_ALEN);
        mac_cache[oldest_index].timestamp = time(NULL);
    }
}

int get_mac_from_ip(struct in_addr ip, struct sockaddr_ll *mac_addr, const char *iface_name) {
    if (find_mac_in_cache(ip, mac_addr->sll_addr)) {
        return 0; // 从缓存中找到MAC地址
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct arpreq req;
    memset(&req, 0, sizeof(req));

    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr = ip;

    strncpy(req.arp_dev, iface_name, sizeof(req.arp_dev) - 1); // 使用传入的接口名称

    if (ioctl(sock, SIOCGARP, &req) < 0) {
        perror("Failed to get ARP entry");
        close(sock);
        return -1;
    }

    close(sock);

    if (req.arp_flags & ATF_COM) {
        memcpy(mac_addr->sll_addr, req.arp_ha.sa_data, ETH_ALEN);
        add_mac_to_cache(ip, mac_addr->sll_addr); // 将MAC地址添加到缓存
        return 0;
    } else {
        fprintf(stderr, "ARP entry not found for IP: %s\n", inet_ntoa(ip));
        return -1;
    }
}

int main() {
    load_config("config.yaml");

    printf("Loaded interfaces:\n");
    for (int i = 0; i < interface_count; i++) {
        printf("Interface: %s\n", interfaces[i].name);
        printf("  IP Address: %s\n", interfaces[i].ip_address);
        printf("  Domain: %s\n", interfaces[i].domain);
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_ll source_addr;
    socklen_t addr_len = sizeof(source_addr);

    printf("Listening for IP packets on raw socket (AF_PACKET)...\n");

    while (1) {
        ssize_t data_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&source_addr, &addr_len);
        if (data_len < 0) {
            perror("Failed to receive packet");
            continue;
        }

        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr)); // 跳过以太网头部

        // 检查是否是DART报文
        if (ip_header->protocol == DART_PROTOCOL) {
            printf("DART packet captured. Processing...\n");

            uint8_t *dart_data = buffer + sizeof(struct ethhdr) + (ip_header->ihl * 4); // 跳过以太网和IP头部
            size_t dart_data_len = data_len - sizeof(struct ethhdr) - (ip_header->ihl * 4);

            dart_packet_t *dart_packet = parse_dart_packet(dart_data, dart_data_len);
            if (dart_packet) {
                // 获取匹配的接口索引
                int iface_index = get_matchest_iface(dart_packet->dest_addr);
                if (iface_index >= 0) {
                    // 获取接口的IP和MAC地址
                    uint32_t local_ip = inet_addr(interfaces[iface_index].ip_address);
                    uint8_t *local_mac = interfaces[iface_index].mac_address;

                    // 修改目标IP地址
                    ip_header->daddr = next_hop_for(dart_packet);
                    // 修改源IP地址
                    ip_header->saddr = local_ip;

                    // 重新计算校验和
                    ip_header->check = 0; // 清空校验和字段
                    ip_header->check = calculate_checksum((uint16_t *)ip_header, ip_header->ihl * 4);

                    // 更新以太网帧头部
                    struct ethhdr *eth_header = (struct ethhdr *)buffer;

                    // 获取目标IP地址对应的MAC地址
                    struct sockaddr_ll target_mac;
                    memset(&target_mac, 0, sizeof(target_mac));
                    target_mac.sll_family = AF_PACKET;
                    target_mac.sll_protocol = htons(ETH_P_IP);
                    target_mac.sll_ifindex = source_addr.sll_ifindex; // 使用接收报文的接口

                    struct in_addr dest_ip;
                    dest_ip.s_addr = ip_header->daddr;

                    if (get_mac_from_ip(dest_ip, &target_mac, interfaces[iface_index].name) == 0) {
                        // 更新以太网帧头部的目标MAC地址
                        memcpy(eth_header->h_dest, target_mac.sll_addr, ETH_ALEN);

                        // 更新以太网帧头部的源MAC地址
                        memcpy(eth_header->h_source, local_mac, ETH_ALEN);
                    } else {
                        fprintf(stderr, "Failed to resolve MAC address for IP: %s\n", inet_ntoa(dest_ip));
                    }

                    // 打印修改后的目标IP地址
                    struct in_addr addr;
                    addr.s_addr = ip_header->daddr;
                    printf("Modified Destination IP: %s\n", inet_ntoa(addr));
                } else {
                    fprintf(stderr, "No matching interface found for destination: %s\n", dart_packet->dest_addr);
                }

                free_dart_packet(dart_packet);
            } else {
                fprintf(stderr, "Failed to parse DART packet\n");
            }
        } else {
            // printf("Non-DART packet captured. Passing to system.\n");
        }
    }

    close(sock);
    return 0;
}