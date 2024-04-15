#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

#include <linux/bpf.h>
#include "../common.h"


#if defined(XDP_PROGRAM)
#define BPFW_CTX         xdp_md              // User accessible metadata for XDP packet hook

#define BPFW_PASS        XDP_PASS            // Let the package pass to the normal network stack
#define BPFW_DROP        XDP_DROP            // Drop the package
#define BPFW_REDIRECT    XDP_REDIRECT        // Redirect the package to another network interface

#elif defined(TC_PROGRAM)
#include <linux/pkt_cls.h>

#define BPFW_CTX         __sk_buff           // User accessible mirror of in-kernel sk_buff

#define BPFW_PASS        TC_ACT_UNSPEC       // Let the package pass to the normal network stack
#define BPFW_DROP        TC_ACT_SHOT         // Drop the package
#define BPFW_REDIRECT    TC_ACT_REDIRECT     // Redirect the package to another network interface

#endif


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


// Helper macro to make the out-of-bounds check on a packet header and drop the package on failure
#define parse_header(header_type, header_ptr, data_ptr, data_end) \
    header_type header_ptr = data_ptr; \
	data_ptr += sizeof(header_type); \
    if (data_ptr > data_end) { \
        BPF_WARN(#header_type" > data_end"); \
        return BPFW_PASS; \
    }


// Declare the VLAN header struct because it's only included in the kernel source header <linux/if_vlan.h>
struct vlan_hdr {
	__be16 h_vlan_TCI;					// priority and VLAN ID
	__be16 h_vlan_encapsulated_proto;	// packet type ID or len
};

// tcphdr from <linux/tcp.h> uses the host endianness, instead of the compiler endianness
struct tcp_flags {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	__u8 cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
};
#define TCP_FLAGS_OFFSET 13


void bpf_print_ipv4(const char *prefix, void *ip_addr) {
    __u8 *ip = ip_addr;

    bpf_printk("%s%u.%u.%u.%u", prefix, ip[0], ip[1], ip[2], ip[3]);
}

void bpf_print_ipv6(const char *prefix, void *ip_addr) {
    __u16 *ip = ip_addr;

    bpf_printk("%s%x:%x:%x:%x:%x:%x:%x:%x", prefix,
        bpf_ntohs(ip[0]), bpf_ntohs(ip[1]), bpf_ntohs(ip[2]), bpf_ntohs(ip[3]), 
        bpf_ntohs(ip[4]), bpf_ntohs(ip[5]), bpf_ntohs(ip[6]), bpf_ntohs(ip[7]));
}

void bpf_print_mac(const char *prefix, void *mac_addr) {
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
