#ifndef COMMON_H
#define COMMON_H

#include <linux/if_ether.h>


#define STRINGIZE(x) #x
#define MAP_TO_STRING(map) STRINGIZE(map)           // Used to get the map name as a string (used for user space programs)


#define CONN_MAP         		conn_map
#define CONN_MAP_NAME    		MAP_TO_STRING(CONN_MAP)


struct conn_key {
	//__u8 src_mac[ETH_ALEN];
	//__u8 dest_mac[ETH_ALEN];
    //__u32 ifindex;
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	//__u16 vlan_id;
	__u8 protocol;
};


struct conntrack_entry {
	__u64 packets;
	__u64 bytes;
	__u8 state;
};

/*struct nat_entry {
	//__u8 src_mac[ETH_ALEN];
	//__u8 dest_mac[ETH_ALEN];
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u8 rewrite_flag;
};*/

struct conn_value {
	//struct conn_key c_key;
	struct conntrack_entry ct_entry;
	//struct nat_entry n_entry;
	//__u8 target;
};

enum {
	CONN_NEW = 0,
	CONN_ESTABLISHED,
	CONN_FIN
};

/*enum {
	REWRITE_SRC_IP    = 1,
	REWRITE_DEST_IP   = 2,
	REWRITE_SRC_PORT  = 4,
	REWRITE_DEST_PORT = 8,
};

enum {
	TARGET_ACCEPT = 0,
	TARGET_DROP
};*/


#endif
