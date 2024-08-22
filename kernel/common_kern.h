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
    struct {
        __u32 in, out;
    } ifindex;

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
