#ifndef BPFW_COMMON_H
#define BPFW_COMMON_H

#include <stddef.h>
#include <string.h>

#include <linux/types.h>
#include <linux/if_ether.h>
#include <sys/socket.h>


#define STRINGIFY(x) 				 #x
#define BPFW_NAME(x) 				 STRINGIFY(x)  // Used to get the prog/map name as a string (used for user space programs)

#define BPFW_XDP_PROG				 bpfw_xdp
#define BPFW_TC_PROG				 bpfw_tc

#define XDP_PROG_NAME				 BPFW_NAME(BPFW_XDP_PROG)
#define TC_PROG_NAME				 BPFW_NAME(BPFW_TC_PROG)

#define BPFW_FLOW_MAP      		  	 bpfw_flows
#define FLOW_MAP_NAME 		  		 BPFW_NAME(BPFW_FLOW_MAP)
#define FLOW_MAP_DEFAULT_MAX_ENTRIES 1024

#define USERSPACE_TIME_SECTION 		 ".bss.time"

#define DSA_TAG_SECTION			  	 ".rodata.dsa.tag"
#define DSA_SWITCH_SECTION		  	 ".bss.dsa.switch"

#define DSA_PROTO_MAX_LEN 8

#define IPV4_ALEN 4
#define IPV6_ALEN 16


struct flow_key {
	__u32  ifindex;

	__u16  vlan_id;
	__be16 pppoe_id;

	__be16 src_port;
	__be16 dest_port;

	__u8   src_ip [IPV6_ALEN];
	__u8   dest_ip[IPV6_ALEN];

	__u8   dsa_port;
	__u8   family;
	__u8   proto;

	__u8   __pad;
};


struct next_hop {
	__u32  ifindex;

	__u16  vlan_id;
	__be16 pppoe_id;

	__u8   src_mac [ETH_ALEN];
	__u8   dest_mac[ETH_ALEN];

	__u8   dsa_port;

	__s8   l2_diff;
};

struct nat_entry {
	__sum16 l4_cksum_diff;

	__be16  src_port;
	__be16  dest_port;

	__u8 	src_ip [IPV6_ALEN];
	__u8 	dest_ip[IPV6_ALEN];

	__u8    rewrite_flag;
};

struct next_entry {
	struct next_hop hop;
	struct nat_entry nat;

	__sum16 ipv4_cksum_diff;
};

struct flow_value {
	__u64 time;
	__u8  src_mac[ETH_ALEN];
	__u8  state;

	struct next_entry next;
};


struct user_time {
	__u64 timeout;
	__u64 last_time;
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
	__u8   vertype;
	__u8   code;
	__be16 sid;
	__be16 length;
    __be16 proto;
};


#define DSA_PORT_SET	(1U << 7)

enum {
	STATE_NEW_FLOW,

	STATE_NONE,
	ACTION_NONE = STATE_NONE,

	STATE_PASS,
	ACTION_PASS = STATE_PASS,

	STATE_DROP,
	ACTION_DROP = STATE_DROP,

	STATE_FORWARD,
	ACTION_FORWARD = STATE_FORWARD,
};

enum {
	REWRITE_SRC_IP    = 1U << 0,
	REWRITE_DEST_IP   = 1U << 1,
	REWRITE_SRC_PORT  = 1U << 2,
	REWRITE_DEST_PORT = 1U << 3
};


static void *ipcpy(void *dest, const void* src, __u8 family) {
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
