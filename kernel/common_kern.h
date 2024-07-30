#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

#include <linux/bpf.h>
#include <netinet/in.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common.h"


#define BPF_LOG_LEVEL_ERROR 0
#define BPF_LOG_LEVEL_WARN  1
#define BPF_LOG_LEVEL_INFO  2
#define BPF_LOG_LEVEL_DEBUG 3

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_ERROR
#define BPF_ERROR(...) bpf_printk(__VA_ARGS__)
#else
#define BPF_ERROR(...)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_WARN
#define BPF_WARN(...) bpf_printk(__VA_ARGS__)
#else
#define BPF_WARN(...)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_INFO
#define BPF_INFO(...) bpf_printk(__VA_ARGS__)
#define BPF_LOG_KEY(header, key) bpf_print_key(header, key)
#else
#define BPF_INFO(...)
#define BPF_LOG_KEY(header, key)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_DEBUG
#define BPF_DEBUG(...)             bpf_printk(__VA_ARGS__)
#define BPF_DEBUG_IPV4(prefix, ip) bpf_print_ipv4(prefix, ip)
#define BPF_DEBUG_IPV6(prefix, ip) bpf_print_ipv6(prefix, ip)
#define BPF_DEBUG_MAC(prefix, mac) bpf_print_mac(prefix, mac)
#else
#define BPF_DEBUG(...)
#define BPF_DEBUG_IPV4(prefix, ip)
#define BPF_DEBUG_IPV6(prefix, ip)
#define BPF_DEBUG_MAC(prefix, mac)
#endif


// Helper macro to make the out-of-bounds check on a packet header
#define check_header(header_type, header_ptr, pkt) \
    header_type header_ptr = pkt->p; \
	pkt->p += sizeof(header_type); \
    if (pkt->p > pkt->data_end) { \
        BPF_WARN(#header_type" > data_end"); \
        return false; \
    }


// tcphdr from <linux/tcp.h> uses the host endianness, instead of the compiler endianness
struct tcp_flags {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	__u8 cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
};
#define TCP_FLAGS_OFFSET 13


struct packet_data {
    __u32 ifindex;
    void *data, *data_end;
    void *p;
};

struct l2_header {
    void *src_mac;
    __u16  vlan_id;
    __be16 pppoe_id;
    __u16  payload_len;
    __be16 proto;
    __u8   dsa_port;
};

struct l3_header {
    void *src_ip, *dest_ip;
    __sum16 *cksum;
    __u8 *ttl;
    __u8 family, proto;
};

struct l4_header {
	// Pointers for possible NAT adjustments
	__be16  *sport, *dport;
	__sum16 *cksum;

	// TCP Flags
	struct tcp_flags tcp_flags;
};


__always_inline static void bpf_print_ipv4(const char *prefix, void *ip_addr) {
    __u8 *ip = ip_addr;

    bpf_printk("%s%u.%u.%u.%u", prefix, ip[0], ip[1], ip[2], ip[3]);
}

__always_inline static void bpf_print_ipv6(const char *prefix, void *ip_addr) {
    __u16 *ip = ip_addr;

    bpf_printk("%s%x:%x:%x:%x:%x:%x:%x:%x", prefix,
        bpf_ntohs(ip[0]), bpf_ntohs(ip[1]), bpf_ntohs(ip[2]), bpf_ntohs(ip[3]), 
        bpf_ntohs(ip[4]), bpf_ntohs(ip[5]), bpf_ntohs(ip[6]), bpf_ntohs(ip[7]));
}

__always_inline static void bpf_print_mac(const char *prefix, void *mac_addr) {
    __u8 *mac = mac_addr;

    bpf_printk("%s%02x:%02x:%02x:%02x:%02x:%02x", prefix,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

__always_inline static void bpf_print_key(const char *header, struct flow_key *f_key) {
    bpf_printk("---------- %s ----------", header);
    bpf_printk("ifindex: %u", f_key->ifindex);

    if (f_key->vlan_id)
        bpf_printk("VLAN ID: %u", f_key->vlan_id);

    if (f_key->family == AF_INET) {
        bpf_print_ipv4("Src IPv4: ", &f_key->src_ip);
        bpf_print_ipv4("Dst IPv4: ", &f_key->dest_ip);
    }
    else {
        bpf_print_ipv6("Src IPv6: ", &f_key->src_ip);
        bpf_print_ipv6("Dst IPv6: ", &f_key->dest_ip);
    }

    if (f_key->proto == IPPROTO_TCP) {
        bpf_printk("TCP Src Port: %u", bpf_ntohs(f_key->src_port));
        bpf_printk("TCP Dst Port: %u", bpf_ntohs(f_key->dest_port));
    }
    else {
        bpf_printk("UDP Src Port: %u", bpf_ntohs(f_key->src_port));
        bpf_printk("UDP Dst Port: %u", bpf_ntohs(f_key->dest_port));
    }
}


#endif
