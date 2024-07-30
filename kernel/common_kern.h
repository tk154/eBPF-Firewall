#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

#include "../common.h"
#include "logging.h"


// Helper macro to make the out-of-bounds check on a packet header
#define check_header(header_type, header_ptr, pkt) \
    header_type header_ptr = pkt->p; \
	pkt->p += sizeof(header_type); \
    if (pkt->p > pkt->data_end) { \
        bpfw_warn(#header_type" > data_end"); \
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


#endif
