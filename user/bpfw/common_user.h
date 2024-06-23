#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H

#include <stdio.h>

#include <linux/bpf.h>

#include <arpa/inet.h>
#include <net/if.h>

#include "../../common.h"


struct flow_key_value {
    struct flow_key key;
    struct flow_value value;
};

struct cmd_args {
    enum bpf_prog_type prog_type;
    __u32 xdp_flags;
    char* prog_path;
    char** if_names;
    unsigned int if_count;
    unsigned int map_poll_sec;
};


extern int fw_log_level;

#define FW_LOG_LEVEL_ERROR   0
#define FW_LOG_LEVEL_WARN    1
#define FW_LOG_LEVEL_INFO    2
#define FW_LOG_LEVEL_DEBUG   3
#define FW_LOG_LEVEL_VERBOSE 4

#define FW_ERROR(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_ERROR) \
        fprintf(stderr, format, ##__VA_ARGS__); } while (0)

#define FW_WARN(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_WARN) \
        fprintf(stderr, format, ##__VA_ARGS__); } while (0)

#define FW_INFO(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_INFO) \
        printf(format, ##__VA_ARGS__); } while (0)

#define FW_DEBUG(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_DEBUG) \
        printf(format, ##__VA_ARGS__); } while (0)

#define FW_VERBOSE(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_VERBOSE) \
        printf(format, ##__VA_ARGS__); } while (0)


static void log_key(int l_level, const char *prefix, struct flow_key *f_key) {
    if (fw_log_level < l_level)
        return;

    char ifname[IF_NAMESIZE];
    if_indextoname(f_key->ifindex, ifname);

    size_t ip_str_len = f_key->family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char src_ip[ip_str_len], dest_ip[ip_str_len];

    inet_ntop(f_key->family, &f_key->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(f_key->family, &f_key->dest_ip, dest_ip, sizeof(dest_ip));

    char *proto = f_key->proto == IPPROTO_TCP ? "tcp" : "udp";

    printf("%s%s", prefix, ifname);

    if (f_key->vlan_id)
        printf(" vlan=%hu", f_key->vlan_id);

    if (f_key->pppoe_id)
        printf(" pppoe=0x%hx", ntohs(f_key->pppoe_id));

    printf(" %s %s %hu %s %hu\n", proto,
        src_ip, ntohs(f_key->src_port), dest_ip, ntohs(f_key->dest_port));
}


#endif
