#ifndef BPFW_COMMON_H
#define BPFW_COMMON_H

#include <linux/types.h>
#include <linux/if_ether.h>


#define STRINGIFY(x) #x
#define MAP_NAME(map) STRINGIFY(map)           // Used to get the map name as a string (used for user space programs)

#define FLOW_MAP         		flow_map
#define FLOW_MAP_NAME    		MAP_NAME(FLOW_MAP)


struct flow_key {
	//__u8 src_mac[ETH_ALEN];
	//__u8 dest_mac[ETH_ALEN];
    __u32  ifindex;
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u16  vlan_id;
	__u8   l4_proto;
};


struct next_hop {
	__u8  src_mac[ETH_ALEN];
	__u8  dest_mac[ETH_ALEN];
	__u32 ifindex;
	__u16 vlan_id;
};

struct nat_entry {
	__be32  src_ip;
	__be32  dest_ip;
	__be16  src_port;
	__be16  dest_port;
	__sum16 l4_cksum_diff;
	__u8    rewrite_flag;
};

struct flow_value {
	struct next_hop next_h;
	struct nat_entry n_entry;
	__u32 idle;
	__sum16 l3_cksum_diff;
	__u8 action;
};


enum {
	ACTION_NONE,
	ACTION_PASS,
	ACTION_DROP,
	ACTION_REDIRECT
};

enum {
	REWRITE_SRC_IP    = (1U << 0),
	REWRITE_DEST_IP   = (1U << 1),
	REWRITE_SRC_PORT  = (1U << 2),
	REWRITE_DEST_PORT = (1U << 3)
};


#endif
