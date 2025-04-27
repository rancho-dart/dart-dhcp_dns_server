#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

#define DART_PROTO 148
#define BUF_SIZE 4096

// DART协议头结构体
#pragma pack(push, 1)
typedef struct {
    uint8_t dst_len; 
    uint8_t dst[256];
    uint8_t src_len;
    uint8_t src[256];
    uint8_t proto;
} DartHeader;
#pragma pack(pop)

// 生成IP校验和
uint16_t checksum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(uint8_t *)(&answer) = *(uint8_t *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

// 处理捕获的数据包
void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    // 检查IP协议号
    if (ip_header->ip_p != DART_PROTO) return;

    // 解析DART头
    const u_char *dart_start = packet + sizeof(struct ether_header) + sizeof(struct ip);
    const u_char *p= dart_start;

    uint8_t dst_len = *p++;
    uint8_t *dst = (uint8_t *)p;
    p += dst_len;
    uint8_t src_len = *p++;
    uint8_t *src = (uint8_t *)p;
    p += src_len;
    uint8_t proto = *p++;

    if (proto != IPPROTO_ICMP) return;

    // 解析ICMP负载
    struct icmp *icmp_hdr = (struct icmp *)p;
    
    // 仅处理ICMP请求
    if (icmp_hdr->icmp_type != ICMP_ECHO) return;

    printf("[DART] Received request from: %.*s\n", 
           src_len, src);

    // 计算ICMP数据部分的长度
    int ip_header_len = ip_header->ip_hl * 4;
    int icmp_data_len = ntohs(ip_header->ip_len) - ip_header_len - sizeof(struct icmp);

    // 构造响应包 -----------------------------------
    uint8_t response[BUF_SIZE] = {0};
    
    // 1. 构造IP头
    struct ip *ip_resp = (struct ip *)response;
    ip_resp->ip_v = 4;
    ip_resp->ip_hl = 5;
    ip_resp->ip_tos = 0;
    ip_resp->ip_len = htons(sizeof(struct ip) + dst_len + src_len + 1 + 
                          sizeof(struct icmp) + icmp_data_len);
    ip_resp->ip_id = htons(12345);
    ip_resp->ip_off = 0;
    ip_resp->ip_ttl = 64;
    ip_resp->ip_p = DART_PROTO;
    ip_resp->ip_src = ip_header->ip_dst;
    ip_resp->ip_dst = ip_header->ip_src;
    ip_resp->ip_sum = checksum((uint16_t *)ip_resp, sizeof(struct ip));

    // 2. 构造DART头
    u_char *dart_resp = response + sizeof(struct ip);
    *dart_resp++ = src_len;
    memcpy(dart_resp, src, src_len);
    dart_resp += src_len;
    *dart_resp++ = dst_len;
    memcpy(dart_resp, dst, dst_len);
    dart_resp += dst_len;
    *dart_resp++ = IPPROTO_ICMP;

    // 3. 构造ICMP响应
    struct icmp *icmp_resp = (struct icmp *)dart_resp;
    icmp_resp->icmp_type = ICMP_ECHOREPLY;
    icmp_resp->icmp_code = 0;
    icmp_resp->icmp_id = icmp_hdr->icmp_id;
    icmp_resp->icmp_seq = icmp_hdr->icmp_seq;
    memcpy(icmp_resp->icmp_data, icmp_hdr->icmp_data, icmp_data_len); // 修改: 使用计算出的长度
    icmp_resp->icmp_cksum = checksum((uint16_t *)icmp_resp, 
                                    sizeof(struct icmp) + icmp_data_len);

    // 发送响应包
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket() error");
        return;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip_resp->ip_dst;

    if (sendto(sock, response, ntohs(ip_resp->ip_len), 0,
              (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto() error");
    } else {
        printf("[DART] Response sent to: %s\n", 
               inet_ntoa(dest_addr.sin_addr));
    }

    close(sock);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // 打开网络接口（需要sudo）
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    // 设置过滤规则
    struct bpf_program fp;
    char filter_exp[] = "ip proto 148";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile() error\n");
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter() error\n");
        return 1;
    }

    printf("DART Ping Server started on all interfaces...\n");
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
