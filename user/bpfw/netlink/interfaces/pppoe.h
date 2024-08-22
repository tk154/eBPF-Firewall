#ifndef BPFW_PPPOE_H
#define BPFW_PPPOE_H

#include <linux/if_ether.h>


struct pppoe {
    __u32 ifindex;

    __u16 id;
    __u8  address[ETH_ALEN];
    __u32 device;
};

int pppoe_get_device(void *peer_ip6, struct pppoe *pppoe);


#endif
