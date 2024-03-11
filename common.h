#ifndef BPFW_COMMON_H
#define BPFW_COMMON_H

#include <linux/types.h>
#include <linux/if_ether.h>


#define STRINGIZE(x) #x
#define MAP_TO_STRING(map) STRINGIZE(map)           // Used to get the map name as a string (used for user space programs)

#define FLOW_MAP         		flow_map
#define FLOW_MAP_NAME    		MAP_TO_STRING(FLOW_MAP)


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
	__sum16 l3_cksum_diff;
	__u8 state, action;
	__u8 update;
};


enum {
	FLOW_NONE = 0,
	FLOW_OFFLOADED,
	FLOW_FINISHED
};

enum {
	ACTION_PASS = 1,
	ACTION_DROP,
	ACTION_REDIRECT
};

enum {
	REWRITE_SRC_IP    = 1,
	REWRITE_DEST_IP   = 2,
	REWRITE_SRC_PORT  = 4,
	REWRITE_DEST_PORT = 8
};


/**
 * Helper to swap the src and dest IP and the src and dest port of a flow key
 * @param f_key Pointer to the flow key
 * **/
static void reverse_flow_key(struct flow_key *f_key) {
	__be32 tmp_ip    = f_key->src_ip;
	f_key->src_ip    = f_key->dest_ip;
	f_key->dest_ip   = tmp_ip;

	__be16 tmp_port  = f_key->src_port;
	f_key->src_port  = f_key->dest_port;
	f_key->dest_port = tmp_port;
}


#endif
