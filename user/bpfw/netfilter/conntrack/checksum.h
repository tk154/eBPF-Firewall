#ifndef BPFW_CONNTRACK_CHECKSUM_H
#define BPFW_CONNTRACK_CHECKSUM_H

#include <linux/types.h>


/* Modified versions originally from include/net/checksum.h */

static __sum16 csum_add(__sum16 csum, const __be16 *add, size_t len) {
	__u16 res = (__u16)csum;

	for (size_t i = 0; i < len; i++) {
		res += (__u16)add[i];
		res += res < (__u16)add[i];
	}

	return (__sum16)res;
}

static __sum16 csum_sub(__sum16 csum, const __be16 *sub, size_t len) {
	__be16 sub_neg[len];
	
	for (size_t i = 0; i < len; i++)
		sub_neg[i] = ~sub[i];

	return csum_add(csum, sub_neg, len);
}

static void csum_replace(__sum16 *csum, const __be16 *old, const __be16 *new, size_t len) {
	*csum = ~csum_add(csum_sub(~(*csum), old, len), new, len);
}


#endif
