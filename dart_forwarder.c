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

#define DART_PROTOCOL 254
#define BUFFER_SIZE 65536
#define MAX_INTERFACES 10

// 定义接口配置结构体
typedef struct {
    char name[32];
    char ip_address[32];
    char domain[32];
} interface_config_t;

interface_config_t interfaces[MAX_INTERFACES];
int interface_count = 0;

// 修改后的DART报文结构
typedef struct {
    uint8_t protocol_number; // 上层协议号
    uint8_t dest_addr_len;   // 目标地址长度
    uint8_t src_addr_len;    // 源地址长度
    char *dest_addr;         // 目标地址（改为char*）
    char *src_addr;          // 源地址（改为char*）
} dart_packet_t;

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

uint32_t matchest_iface_ip(char *dest_addr) {
    uint32_t best_match_ip = 0;
    size_t best_match_length = 0;

    for (int i = 0; i < interface_count; i++) {
        size_t iface_domain_len = strlen(interfaces[i].domain);
        size_t dest_addr_len = strlen(dest_addr);

        // 从后向前匹配
        if (dest_addr_len >= iface_domain_len &&
            strcmp(dest_addr + dest_addr_len - iface_domain_len, interfaces[i].domain) == 0) {
            if (iface_domain_len > best_match_length) {
                best_match_length = iface_domain_len;
                best_match_ip = inet_addr(interfaces[i].ip_address);
            }
        }
    }

    return best_match_ip;
}


// Forwarder函数，返回下一跳IP地址
uint32_t forwarder(dart_packet_t *dart_packet) {
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

int main() {
    load_config("config.yaml");

    printf("Loaded interfaces:\n");
    for (int i = 0; i < interface_count; i++) {
        printf("Interface: %s\n", interfaces[i].name);
        printf("  IP Address: %s\n", interfaces[i].ip_address);
        printf("  Domain: %s\n", interfaces[i].domain);
    }

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_socket < 0) {
        perror("Socket creation failed");
        return 1;
    }

    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    printf("Listening for IP packets...\n");

    while (1) {
        ssize_t data_len = recvfrom(raw_socket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&source_addr, &addr_len);
        if (data_len < 0) {
            perror("Failed to receive packet");
            continue;
        }

        struct iphdr *ip_header = (struct iphdr *)buffer;

        // 检查是否是DART报文
        if (ip_header->protocol == DART_PROTOCOL) {
            printf("DART packet captured. Processing...\n");

            uint8_t *dart_data = buffer + (ip_header->ihl * 4); // 跳过IP头部
            size_t dart_data_len = data_len - (ip_header->ihl * 4);

            dart_packet_t *dart_packet = parse_dart_packet(dart_data, dart_data_len);
            if (dart_packet) {
                // 获取下一跳IP地址
                uint32_t next_hop_ip = forwarder(dart_packet);
                uint32_t local_ip = matchest_iface_ip(dart_packet->dest_addr);

                // 修改目标IP地址
                ip_header->daddr = next_hop_ip;
                ip_header->saddr = local_ip;

                // 打印修改后的目标IP地址
                struct in_addr addr;
                addr.s_addr = next_hop_ip;
                printf("Modified Destination IP: %s\n", inet_ntoa(addr));

                free_dart_packet(dart_packet);
            } else {
                fprintf(stderr, "Failed to parse DART packet\n");
            }
        } else {
            // printf("Non-DART packet captured. Passing to system.\n");
        }
    }

    close(raw_socket);
    return 0;
}