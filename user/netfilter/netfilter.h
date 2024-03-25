#ifndef BPFW_NETFILTER_H
#define BPFW_NETFILTER_H


/**
 * Reads timeout values from /proc/sys/net/netfilter/<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
int read_netfilter_sysfs_timeout(const char *filename, unsigned int *timeout);


#endif
