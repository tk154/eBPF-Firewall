#ifndef BPFW_PPPOE_H
#define BPFW_PPPOE_H

#include <linux/if_ether.h>


struct pppoe_device {
    __u32 ifindex;
    __u16 id;
    __u8  address[ETH_ALEN];
    __u32 device;
};


int get_pppoe_device(struct pppoe_device *pppoe, __u8 *ipv6);


#endif
