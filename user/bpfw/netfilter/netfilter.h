#ifndef BPFW_NETFILTER_H
#define BPFW_NETFILTER_H


/**
 * Reads timeout values from /proc/sys/net/netfilter/<filename>
 * @param filename The timeout value to read
 * @param timeout Where to store the timeout value
 * @returns 0 on success, errno otherwise
 * **/
int netfilter_sysfs_read(const char *filename, unsigned int *value);
int netfilter_sysfs_write(const char *filename, unsigned int value);


#endif
