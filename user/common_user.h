#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H

#include <stdio.h>

#include <arpa/inet.h>
#include <linux/bpf.h>

#include "../common.h"


struct flow_key_value {
    struct flow_key key;
    struct flow_value value;
};

struct cmd_args {
    enum bpf_prog_type prog_type;
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


static void log_key(struct flow_key *f_key, const char* prefix) {
    if (fw_log_level >= FW_LOG_LEVEL_DEBUG) {
        char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &f_key->src_ip, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &f_key->dest_ip, dest_ip, sizeof(dest_ip));

        FW_DEBUG("%s%u %hhu %s %hu %s %hu\n", prefix, f_key->ifindex, f_key->l4_proto,
            src_ip, ntohs(f_key->src_port), dest_ip, ntohs(f_key->dest_port));
    }
}


#endif
