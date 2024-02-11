#ifndef BPFW_CONNTRACK_CHECKSUM_H
#define BPFW_CONNTRACK_CHECKSUM_H

#include <linux/types.h>


/* From include/net/checksum.h */

static inline __wsum csum_add(__wsum csum, __wsum addend) {
	__u32 res = (__u32)csum + (__u32)addend;
	return (__wsum)(res + (res < (__u32)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend) {
	return csum_add(csum, ~addend);
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
	__u16 res = (__u16)csum + (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
	return csum16_add(csum, ~addend);
}

static inline __sum16 csum_fold(__wsum csum) {
	csum = (csum & 0xFFFF) + (csum >> 16);
	csum = (csum & 0xFFFF) + (csum >> 16);

	return (__u16)~csum;
}

static inline __wsum csum_unfold(__sum16 n) {
	return (__wsum)n;
}

static inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to) {
	__wsum tmp = csum_sub(~csum_unfold(*sum), (__wsum)from);
	*sum = csum_fold(csum_add(tmp, (__wsum)to));
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new) {
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}


#endif
