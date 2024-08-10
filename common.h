#ifndef BPFW_COMMON_H
#define BPFW_COMMON_H

#include <stddef.h>
#include <string.h>

#include <linux/types.h>
#include <linux/if_ether.h>
#include <sys/socket.h>


#define __packed __attribute__((packed))

#define STRINGIFY(x)  #x
#define MAP_NAME(map) STRINGIFY(map)           // Used to get the map name as a string (used for user space programs)

#define FLOW_MAP      flow_map
#define FLOW_MAP_NAME MAP_NAME(FLOW_MAP)

#define DSA_PROTO_MAX_LEN 8

#define DSA_TAG_SECTION		".rodata.dsa.tag"
#define DSA_SWITCH_SECTION	".bss.dsa.switch"

#define IPV4_ALEN 4
#define IPV6_ALEN 16


struct flow_key {
	__u32  ifindex;
	__u16  vlan_id;
	__be16 pppoe_id;
	__be16 src_port;
	__be16 dest_port;
	__u8   src_ip[IPV6_ALEN];
	__u8   dest_ip[IPV6_ALEN];
	__u8   dsa_port;
	__u8   family;
	__u8   proto;
};


struct next_hop {
	__u32  ifindex;
	__u16  vlan_id;
	__be16 pppoe_id;
	__u8   src_mac[ETH_ALEN];
	__u8   dest_mac[ETH_ALEN];
	__u8   dsa_port;
	__s8   l2_diff;
};

struct nat_entry {
	__sum16 l4_cksum_diff;
	__be16  src_port;
	__be16  dest_port;
	__u8 	src_ip[IPV6_ALEN];
	__u8 	dest_ip[IPV6_ALEN];
	__u8    rewrite_flag;
};

struct flow_value {
	struct next_hop next_h;
	struct nat_entry n_entry;
	__u8    src_mac[ETH_ALEN];
	__u32   idle;
	__sum16 ipv4_cksum_diff;
	__u8    action;
};


struct dsa_switch {
	__u32 ifindex;
	__u8  proto;
};

struct dsa_tag {
	char proto[DSA_PROTO_MAX_LEN];
	__u8 rx_size, tx_size;
};


struct vlanhdr {
	__be16 tci;
	__be16 proto;
};

struct pppoehdr {
	__u8 vertype;
	__u8 code;
	__be16 sid;
	__be16 length;
    __be16 proto;
} __packed;


#define DSA_PORT_SET	(1U << 7)

enum {
	ACTION_NONE,
	ACTION_PASS,
	ACTION_DROP,
	ACTION_REDIRECT,
	__ACTION_PASS
};

enum {
	REWRITE_SRC_IP    = (1U << 0),
	REWRITE_DEST_IP   = (1U << 1),
	REWRITE_SRC_PORT  = (1U << 2),
	REWRITE_DEST_PORT = (1U << 3)
};


__always_inline static void* ipcpy(void *dest, const void* src, __u8 family) {
    switch (family) {
        case AF_INET:
            return memcpy(dest, src, IPV4_ALEN);
        case AF_INET6:
            return memcpy(dest, src, IPV6_ALEN);
		default:
			return NULL;
    }
}


#endif
