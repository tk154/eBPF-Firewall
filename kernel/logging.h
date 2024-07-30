#ifndef BPFW_LOGGING_H
#define BPFW_LOGGING_H

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <netinet/in.h>


#define BPFW_LOG_LEVEL_ERROR   0
#define BPFW_LOG_LEVEL_WARN    1
#define BPFW_LOG_LEVEL_INFO    2
#define BPFW_LOG_LEVEL_DEBUG   3
#define BPFW_LOG_LEVEL_VERBOSE 4

#if BPFW_LOG_LEVEL >= BPFW_LOG_LEVEL_ERROR
    #define bpfw_error(format, ...) bpf_printk(format, ##__VA_ARGS__)
#else
    #define bpfw_error(format, ...)
#endif

#if BPFW_LOG_LEVEL >= BPFW_LOG_LEVEL_WARN
    #define bpfw_warn(format, ...) bpf_printk(format, ##__VA_ARGS__)
#else
    #define bpfw_warn(format, ...)
#endif

#if BPFW_LOG_LEVEL >= BPFW_LOG_LEVEL_INFO
    #define bpfw_info(format, ...)     bpf_printk(format, ##__VA_ARGS__)
    #define bpfw_info_key(header, key) bpf_log_key(header, key)
#else
    #define bpfw_info(format, ...)
    #define bpfw_info_key(header, key)
#endif

#if BPFW_LOG_LEVEL >= BPFW_LOG_LEVEL_DEBUG
    #define bpfw_debug(format, ...)     bpf_printk(format, ##__VA_ARGS__)
    #define bpfw_debug_ipv4(prefix, ip) bpf_log_ipv4(prefix, ip)
    #define bpfw_debug_ipv6(prefix, ip) bpf_log_ipv6(prefix, ip)
    #define bpfw_debug_mac(prefix, mac) bpf_log_mac(prefix, mac)
#else
    #define bpfw_debug(format, ...)
    #define bpfw_debug_ipv4(prefix, ip)
    #define bpfw_debug_ipv6(prefix, ip)
    #define bpfw_debug_mac(prefix, mac)
#endif

#if BPFW_LOG_LEVEL >= BPFW_LOG_LEVEL_VERBOSE
    #define bpfw_verbose(format, ...) bpf_printk(format, ##__VA_ARGS__)
#else
    #define bpfw_verbose(format, ...)
#endif


__always_inline static void bpf_log_ipv4(const char *prefix, void *ip_addr) {
    __u8 *ip = ip_addr;

    bpf_printk("%s%u.%u.%u.%u", prefix, ip[0], ip[1], ip[2], ip[3]);
}

__always_inline static void bpf_log_ipv6(const char *prefix, void *ip_addr) {
    __u16 *ip = ip_addr;

    bpf_printk("%s%x:%x:%x:%x:%x:%x:%x:%x", prefix,
        bpf_ntohs(ip[0]), bpf_ntohs(ip[1]), bpf_ntohs(ip[2]), bpf_ntohs(ip[3]), 
        bpf_ntohs(ip[4]), bpf_ntohs(ip[5]), bpf_ntohs(ip[6]), bpf_ntohs(ip[7]));
}

__always_inline static void bpf_log_mac(const char *prefix, void *mac_addr) {
    __u8 *mac = mac_addr;

    bpf_printk("%s%02x:%02x:%02x:%02x:%02x:%02x", prefix,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

__always_inline static void bpf_log_key(const char *header, struct flow_key *f_key) {
    bpf_printk("---------- %s ----------", header);
    bpf_printk("ifindex: %u", f_key->ifindex);

    if (f_key->vlan_id)
        bpf_printk("VLAN ID: %u", f_key->vlan_id);

    if (f_key->family == AF_INET) {
        bpf_log_ipv4("Src IPv4: ", &f_key->src_ip);
        bpf_log_ipv4("Dst IPv4: ", &f_key->dest_ip);
    }
    else {
        bpf_log_ipv6("Src IPv6: ", &f_key->src_ip);
        bpf_log_ipv6("Dst IPv6: ", &f_key->dest_ip);
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
