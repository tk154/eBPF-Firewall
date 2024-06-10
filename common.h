#ifndef BPFW_COMMON_H
#define BPFW_COMMON_H

#include <linux/types.h>


#define STRINGIFY(x) #x
#define MAP_NAME(map) STRINGIFY(map)           // Used to get the map name as a string (used for user space programs)

#define FLOW_MAP         		flow_map
#define FLOW_MAP_NAME    		MAP_NAME(FLOW_MAP)


struct flow_key {
	__u32  ifindex;
	__u16  vlan_id;
	__be16 src_port;
	__be16 dest_port;
	__u8   src_ip[16];
	__u8   dest_ip[16];
	__u8   family;
	__u8   proto;
};


struct next_hop {
	__u32 ifindex;
	__u16 vlan_id;
	__u8  src_mac[6];
	__u8  dest_mac[6];
};

struct nat_entry {
	__sum16 l4_cksum_diff;
	__be16  src_port;
	__be16  dest_port;
	__u8 	src_ip[16];
	__u8 	dest_ip[16];
	__u8    rewrite_flag;
};

struct flow_value {
	struct next_hop next_h;
	struct nat_entry n_entry;
	__u32   idle;
	__sum16 ipv4_cksum_diff;
	__u8    action;
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


#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy(dest, src, n)
#endif

static void* ipcpy(void *dest, const void* src, __u8 family) {
    switch (family) {
        case AF_INET:
            return memcpy(dest, src, 4);
        case AF_INET6:
            return memcpy(dest, src, 16);
		default:
			return NULL;
    }
}


#endif
