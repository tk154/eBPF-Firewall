#ifndef BPFW_COMMON_KERN_H
#define BPFW_COMMON_KERN_H

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
#define check_header(hdr, pkt) \
    do { \
        hdr = pkt->p; \
        pkt->p += sizeof(*hdr); \
        if (pkt->p > pkt->data_end) { \
            bpfw_warn(#hdr" > data_end"); \
            return false; \
        } \
    } while (0);

#define parse_ethhdr(hdr, pkt, l2) \
    do { \
        check_header(hdr, pkt) \
        l2->proto = hdr->h_proto; \
        l2->src_mac = hdr->h_source; \
    } while (0);

#define push_ethhdr(hdr, pkt, next) \
    do { \
        check_header(hdr, pkt) \
        memcpy(hdr->h_dest, next->dest_mac, ETH_ALEN); \
        memcpy(hdr->h_source, next->src_mac, ETH_ALEN); \
    } while (0);


// tcphdr from <linux/tcp.h> uses the host endianness, instead of the compiler endianness
/*#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
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
#define TCP_HEADER_FLAGS_OFFSET 13*/


struct flow {
	struct flow_key key;
	struct flow_value *value;
    void *map;
};

struct packet_data {
    void *data, *data_end;
    void *p;

    __u32 in_ifindex;
    __u32 out_ifindex;
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
    __u16 tot_len;
    __u8 offset, family, proto;
};

struct l4_header {
	// Pointers for possible NAT adjustments
	__be16  *src_port, *dest_port;
	__sum16 *cksum;

    __u16 payload_len;

	// TCP Header Flags
	//struct tcphdr_flags tcp_flags;
    __u8 tcp_flags;
};

struct packet_header {
    struct l2_header l2;
    struct l3_header l3;
    struct l4_header l4;
};


#endif
