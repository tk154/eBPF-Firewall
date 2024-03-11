#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

#include <linux/bpf.h>


#if defined(XDP_PROGRAM)
#define BPFW_CTX         xdp_md              // User accessible metadata for XDP packet hook

#define BPFW_PASS        XDP_PASS            // Let the package pass to the normal network stack
#define BPFW_DROP        XDP_DROP            // Drop the package
#define BPFW_REDIRECT    XDP_REDIRECT        // Redirect the package to another network interface

#elif defined(TC_PROGRAM)
#include <linux/pkt_cls.h>

#define BPFW_CTX         __sk_buff           // User accessible mirror of in-kernel sk_buff

#define BPFW_PASS        TC_ACT_OK           // Let the package pass to the normal network stack
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
#else
#define BPF_INFO(...)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_DEBUG
#define BPF_DEBUG(...) bpf_printk(__VA_ARGS__)
#define BPF_DEBUG_IP(prefix, ip)   __bpf_debug_ip(prefix, ip)
#define BPF_DEBUG_MAC(prefix, mac) __bpf_debug_mac(prefix, mac)
#else
#define BPF_DEBUG(...)
#define BPF_DEBUG_IP(prefix, ip)
#define BPF_DEBUG_MAC(prefix, mac)
#endif


#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy(dest, src, n)
#endif

// Helper macro to make the out-of-bounds check on a packet header and drop the package on failure
#define parse_header(header_type, header_ptr, data_ptr, data_end) \
    header_type header_ptr = data_ptr; \
	data_ptr += sizeof(header_type); \
    if (data_ptr > data_end) { \
        BPF_WARN(#header_type" > data_end"); \
        return BPFW_DROP; \
    }


void __bpf_debug_ip(const char *prefix, __be32 ip_addr) {
    __u8 *ip = (__u8*)&ip_addr;
    __u64 ip_data[] = { ip[0], ip[1], ip[2], ip[3] };

    // Format IP address into a string buffer
    char ip_str[INET_ADDRSTRLEN];
    bpf_snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                    ip_data, sizeof(ip_data));

    BPF_DEBUG("%s%s", prefix, ip_str);
}

void __bpf_debug_mac(const char *prefix, __u8 *mac_addr) {
    __u64 mac_data[] = { mac_addr[0], mac_addr[1], mac_addr[2], 
                         mac_addr[3], mac_addr[4], mac_addr[5] };

    // Format MAC address into a string buffer
    char mac_str[18] = {};
    bpf_snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac_data, sizeof(mac_data));

    BPF_DEBUG("%s%s", prefix, mac_str);
}


#endif
