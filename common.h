#ifndef COMMON_H
#define COMMON_H

#include <linux/if_ether.h>


#define STRINGIZE(x) #x
#define MAP_TO_STRING(map) STRINGIZE(map)           // Used to get the map name as a string (used for user space programs)


#define CONNTRACK_MAP         		conntrack_map
#define CONNTRACK_MAP_NAME    		MAP_TO_STRING(CONNTRACK_MAP)

struct conntrack_key {
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u8 protocol;
};

typedef __u8 conntrack_state;


#define NAT_MAP         		nat_map
#define NAT_MAP_NAME    		MAP_TO_STRING(NAT_MAP)

struct nat_key {
	__u8 src_mac[ETH_ALEN];
	__u8 dest_mac[ETH_ALEN];
    __u32 ifindex;
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u16 vlan_id;
	__u8 protocol;
};

struct nat_value {
	__u8 src_mac[ETH_ALEN];
	__u8 dest_mac[ETH_ALEN];
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
};


#endif
