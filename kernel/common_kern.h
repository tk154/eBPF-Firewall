#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

//#include <stdbool.h>

#include "../common.h"
#include "logging.h"


#define BIT(n) (1UL << (n))

#define GENMASK(h, l) \
    (((~0UL) << (l)) & (~0UL >> (sizeof(0UL) * 8 - 1 - (h))))

#define FIELD_PREP(mask, val) \
    (((val) << __builtin_ctzl(mask)) & (mask))

#define FIELD_GET(mask, val) \
    (((val) & (mask)) >> __builtin_ctzl(mask))

#define __packed __attribute__((packed))


// Helper macro to make the out-of-bounds check on a packet header
#define check_header(header_type, header_ptr, pkt) \
    header_type header_ptr = pkt->p; \
	pkt->p += sizeof(header_type); \
    if (pkt->p > pkt->data_end) { \
        bpfw_warn(#header_type" > data_end"); \
        return false; \
    }

#define parse_ethhdr(hdr_t, hdr_p, pkt, l2) \
	check_header(hdr_t, *hdr_p, pkt) \
	l2->src_mac = hdr_p->h_source; \
	l2->proto = hdr_p->h_proto;

#define push_ethhdr(hdr_t, hdr_p, pkt, next_h) \
	check_header(hdr_t, *hdr_p, pkt) \
	memcpy(hdr_p->h_source, next_h->src_mac,  ETH_ALEN); \
	memcpy(hdr_p->h_dest,   next_h->dest_mac, ETH_ALEN);


// tcphdr from <linux/tcp.h> uses the host endianness, instead of the compiler endianness
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
struct iphdr_ver_ihl {
    __u8 ihl:4, version:4;
};

struct tcphdr_flags {
	__u8 fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
};

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct iphdr_ver_ihl {
    __u8 version:4, ihl:4;
};

struct tcphdr_flags {
	__u8 cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
};
#endif
#define TCP_HEADER_FLAGS_OFFSET 13


struct packet_data {
    __u32 in_ifindex;
    __u32 out_ifindex;

    //bool in_dsa, out_dsa;

    void *data, *data_end;
    void *p;
};

struct l2_header {
    __u8   *src_mac;
    __u16  vlan_id;
    __be16 pppoe_id;
    __u16  payload_len;
    __be16 proto;
    __u8   dsa_port;
};

struct l3_header {
    __be32 *src_ip, *dest_ip;
    __sum16 *cksum;
    __u8 *ttl;
    __u8 offset, family, proto;
};

struct l4_header {
	// Pointers for possible NAT adjustments
	__be16  *src_port, *dest_port;
	__sum16 *cksum;

	// TCP Header Flags
	struct tcphdr_flags tcp_flags;
};

struct packet_header {
    struct l2_header l2;
    struct l3_header l3;
    struct l4_header l4;
};


#endif
