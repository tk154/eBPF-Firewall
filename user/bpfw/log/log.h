#ifndef BPFW_LOGGING_H
#define BPFW_LOGGING_H

#include "../common_user.h"


enum bpfw_log_level {
    BPFW_LOG_LEVEL_ERROR,
    BPFW_LOG_LEVEL_WARN,
    BPFW_LOG_LEVEL_INFO,
    BPFW_LOG_LEVEL_DEBUG,
    BPFW_LOG_LEVEL_VERBOSE
};


#define BPFW_DEFAULT_LOG_LEVEL BPFW_LOG_LEVEL_INFO

#define bpfw_error(format, ...)   bpfw_log(BPFW_LOG_LEVEL_ERROR,   format, ##__VA_ARGS__)
#define bpfw_warn(format, ...)    bpfw_log(BPFW_LOG_LEVEL_WARN,    format, ##__VA_ARGS__)
#define bpfw_info(format, ...)    bpfw_log(BPFW_LOG_LEVEL_INFO,    format, ##__VA_ARGS__)
#define bpfw_debug(format, ...)   bpfw_log(BPFW_LOG_LEVEL_DEBUG,   format, ##__VA_ARGS__)
#define bpfw_verbose(format, ...) bpfw_log(BPFW_LOG_LEVEL_VERBOSE, format, ##__VA_ARGS__)

#define bpfw_errno(prefix, error, ...) bpfw_log_errno(BPFW_LOG_LEVEL_ERROR, error, prefix, ##__VA_ARGS__)

#define bpfw_error_ifindex(prefix, ifindex, error, ...)   bpfw_log_ifindex(BPFW_LOG_LEVEL_ERROR,   ifindex, error, prefix, ##__VA_ARGS__)
#define bpfw_warn_ifindex(prefix, ifindex, error, ...)    bpfw_log_ifindex(BPFW_LOG_LEVEL_WARN,    ifindex, error, prefix, ##__VA_ARGS__)
#define bpfw_debug_ifindex(prefix, ifindex, error, ...)   bpfw_log_ifindex(BPFW_LOG_LEVEL_DEBUG,   ifindex, error, prefix, ##__VA_ARGS__)
#define bpfw_verbose_ifindex(prefix, ifindex, error, ...) bpfw_log_ifindex(BPFW_LOG_LEVEL_VERBOSE, ifindex, error, prefix, ##__VA_ARGS__)

#define bpfw_error_ip(prefix, ip, family, error, ...) bpfw_log_ip(BPFW_LOG_LEVEL_ERROR, ip, family, error, prefix, ##__VA_ARGS__)
#define bpfw_warn_ip(prefix, ip, family, error, ...)  bpfw_log_ip(BPFW_LOG_LEVEL_WARN,  ip, family, error, prefix, ##__VA_ARGS__)
#define bpfw_debug_ip(prefix, ip, family, error, ...) bpfw_log_ip(BPFW_LOG_LEVEL_DEBUG, ip, family, error, prefix, ##__VA_ARGS__)

#define bpfw_warn_ip_on_ifindex(prefix, ip, family, ifindex, error, ...)  bpfw_log_ip_on_ifindex(BPFW_LOG_LEVEL_WARN, ip, family, ifindex, error, prefix, ##__VA_ARGS__)
#define bpfw_debug_ip_on_ifindex(prefix, ip, family, ifindex, error, ...) bpfw_log_ip_on_ifindex(BPFW_LOG_LEVEL_DEBUG, ip, family, ifindex, error, prefix, ##__VA_ARGS__)

#define bpfw_debug_key(prefix, f_key, ...)             bpfw_log_key(BPFW_LOG_LEVEL_DEBUG, f_key, prefix, ##__VA_ARGS__)
#define bpfw_debug_action(prefix, action, ...)         bpfw_log_action(BPFW_LOG_LEVEL_DEBUG, action, prefix, ##__VA_ARGS__)
#define bpfw_verbose_nat(prefix, n_entry, family, ...) bpfw_log_nat(BPFW_LOG_LEVEL_VERBOSE, n_entry, family, prefix, ##__VA_ARGS__)
#define bpfw_verbose_next_hop(prefix, next_h, ...)     bpfw_log_next_hop(BPFW_LOG_LEVEL_VERBOSE, next_h, prefix, ##__VA_ARGS__)
#define bpfw_verbose_route_type(prefix, rtm_type, ...) bpfw_log_route_type(BPFW_LOG_LEVEL_VERBOSE, rtm_type, prefix, ##__VA_ARGS__)
#define bpfw_debug_rule(prefix, target, name, ...)     bpfw_log_rule(BPFW_LOG_LEVEL_DEBUG, prefix, target, name, prefix, ##__VA_ARGS__)


void bpfw_set_log_level(enum bpfw_log_level level);
void bpfw_log(enum bpfw_log_level level, const char* format, ...);
void bpfw_log_errno(enum bpfw_log_level level, int error, const char *prefix, ...);

void bpfw_log_ifindex(enum bpfw_log_level level, __u32 ifindex, int error, const char *prefix, ...);
void bpfw_log_ip(enum bpfw_log_level level, const void *ip, __u8 family, int error, const char *prefix, ...);
void bpfw_log_ip_on_ifindex(unsigned int log_level, const void *ip, __u8 family, __u32 ifindex, int error, const char *prefix, ...);

void bpfw_log_key(enum bpfw_log_level level, struct flow_key *f_key, const char *prefix, ...);
void bpfw_log_action(enum bpfw_log_level level, __u8 action, const char *prefix, ...);
void bpfw_log_nat(enum bpfw_log_level level, struct nat_entry *n_entry, __u8 family, const char *prefix, ...);
void bpfw_log_next_hop(enum bpfw_log_level level, struct next_hop *next_h, const char *prefix, ...);
void bpfw_log_route_type(enum bpfw_log_level level, unsigned char rtm_type, const char *prefix, ...);
void bpfw_log_rule(enum bpfw_log_level level, const char *target, const char *name, const char *prefix, ...);


#endif
