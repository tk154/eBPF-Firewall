#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

#include <linux/bpf.h>


#if defined(XDP_PROGRAM)
#define BPF_CTX         xdp_md              // User accessible metadata for XDP packet hook

#define BPF_PASS        XDP_PASS            // Let the package pass to the normal network stack
#define BPF_DROP        XDP_DROP            // Drop the package
#define BPF_REDIRECT    XDP_REDIRECT        // Redirect the package to another network interface

#elif defined(TC_PROGRAM)
#include <linux/pkt_cls.h>

#define BPF_CTX         __sk_buff           // User accessible mirror of in-kernel sk_buff

#define BPF_PASS        TC_ACT_OK           // Let the package pass to the normal network stack
#define BPF_DROP        TC_ACT_SHOT         // Drop the package
#define BPF_REDIRECT    TC_ACT_REDIRECT     // Redirect the package to another network interface

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
#else
#define BPF_DEBUG(...)
#endif

#define BPF_DEBUG_IP(s, ip)   BPF_DEBUG("%s%u.%u.%u.%u", s, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24);
#define BPF_DEBUG_MAC(s, mac) BPF_DEBUG("%s%02x:%02x:%02x:%02x:%02x:%02x", s, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy(dest, src, n)
#endif

// Helper macro to make the out-of-bounds check on a packet header and drop the package on failure
#define parse_header(header_type, header_ptr, data_ptr, data_end) \
    header_type header_ptr = data_ptr; \
	data_ptr += sizeof(header_type); \
    if (data_ptr > data_end) { \
        BPF_WARN(#header_type" > data_end"); \
        return BPF_DROP; \
    }

#endif
