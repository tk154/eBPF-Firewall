#ifndef COMMON_XDP_TC
#define COMMON_XDP_TC

#include <linux/bpf.h>

#ifndef TC_PROGRAM
/* XDP program */
#define BPF_PASS        XDP_PASS            // Let the package pass to the normal network stack
#define BPF_DROP        XDP_DROP            // Drop the package
#define BPF_REDIRECT    XDP_REDIRECT        // Redirect the package to another network interface

/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
#define BPF_CTX         xdp_md

#else
/* TC program */
#include <linux/pkt_cls.h>

#define BPF_PASS        TC_ACT_OK           // Let the package pass to the normal network stack
#define BPF_DROP        TC_ACT_SHOT         // Drop the package
#define BPF_REDIRECT    TC_ACT_REDIRECT     // Redirect the package to another network interface

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
#define BPF_CTX         __sk_buff
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy(dest, src, n)
#endif

#if DEBUG
#define BPF_DEBUG(...) bpf_printk(__VA_ARGS__)
#else
#define BPF_DEBUG(...)
#endif
#define BPF_DEBUG_IP(s, ip) BPF_DEBUG("%s%u.%u.%u.%u", s, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24);
#define BPF_DEBUG_MAC(s, mac) BPF_DEBUG("%s%02x:%02x:%02x:%02x:%02x:%02x", s, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

// Helper macro to make the out-of-bounds check on a packet header and drop the package on failure
#define parse_header(header_type, header_ptr, data_ptr, data_end) \
    header_type header_ptr = data_ptr; \
	data_ptr += sizeof(header_type); \
    if (data_ptr > data_end) { \
        BPF_DEBUG(#header_type" > data_end"); \
        return BPF_DROP; \
    }

// To suppress the "variable unused" warning
#define BPF_UNUSED(x) (void)x;

#endif
