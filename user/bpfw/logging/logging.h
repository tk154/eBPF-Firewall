#ifndef BPFW_LOGGING_H
#define BPFW_LOGGING_H

#include "../common_user.h"


#define BPFW_LOG_ERROR   0
#define BPFW_LOG_WARN    1
#define BPFW_LOG_INFO    2
#define BPFW_LOG_DEBUG   3
#define BPFW_LOG_VERBOSE 4

#define bpfw_error(format, ...)   bpfw_log(BPFW_LOG_ERROR,   format, ##__VA_ARGS__)
#define bpfw_warn(format, ...)    bpfw_log(BPFW_LOG_WARN,    format, ##__VA_ARGS__)
#define bpfw_info(format, ...)    bpfw_log(BPFW_LOG_INFO,    format, ##__VA_ARGS__)
#define bpfw_debug(format, ...)   bpfw_log(BPFW_LOG_DEBUG,   format, ##__VA_ARGS__)
#define bpfw_verbose(format, ...) bpfw_log(BPFW_LOG_VERBOSE, format, ##__VA_ARGS__)


#define bpfw_error_ifindex(prefix, ifindex, suffix, error) bpfw_log_ifindex(BPFW_LOG_ERROR, prefix, ifindex, suffix, error)
#define bpfw_warn_ifindex(prefix, ifindex, suffix, error)  bpfw_log_ifindex(BPFW_LOG_WARN, prefix, ifindex, suffix, error)
#define bpfw_verbose_ifindex(prefix, ifindex, suffix, error)  bpfw_log_ifindex(BPFW_LOG_VERBOSE, prefix, ifindex, suffix, error)

#define bpfw_error_ip(prefix, ip, family, error) bpfw_log_ip(BPFW_LOG_ERROR, prefix, ip, family, error)
#define bpfw_warn_ip(prefix, ip, family, error)  bpfw_log_ip(BPFW_LOG_WARN, prefix, ip, family, error)
#define bpfw_debug_ip(prefix, ip, family, error) bpfw_log_ip(BPFW_LOG_DEBUG, prefix, ip, family, error)

#define bpfw_warn_ip_on_ifindex(prefix, ip, family, ifindex, error) bpfw_log_ip_on_ifindex(BPFW_LOG_WARN, prefix, ip, family, ifindex, error)


#define bpfw_debug_key(prefix, f_key)             bpfw_log_key(BPFW_LOG_DEBUG, prefix, f_key)
#define bpfw_debug_action(prefix, action)         bpfw_log_action(BPFW_LOG_DEBUG, prefix, action)
#define bpfw_verbose_nat(prefix, n_entry, family) bpfw_log_nat(BPFW_LOG_VERBOSE, prefix, n_entry, family)
#define bpfw_verbose_next_hop(prefix, next_h)     bpfw_log_next_hop(BPFW_LOG_VERBOSE, prefix, next_h)
#define bpfw_verbose_route_type(prefix, rtm_type) bpfw_log_route_type(BPFW_LOG_VERBOSE, prefix, rtm_type)
#define bpfw_debug_rule(target, name)             bpfw_log_rule(BPFW_LOG_DEBUG, target, name)


void bpfw_set_log_level(unsigned int log_level);
void bpfw_log(unsigned int log_level, const char* format, ...);

void bpfw_log_ifindex(unsigned int log_level, const char *prefix, __u32 ifindex, const char *suffix, int error);
void bpfw_log_ip(unsigned int log_level, const char *prefix, void *ip, __u8 family, int error);
void bpfw_log_ip_on_ifindex(unsigned int log_level, const char *prefix, void *ip, __u8 family, __u32 ifindex, int error);

void bpfw_log_key(unsigned int log_level, const char *prefix, struct flow_key *f_key);
void bpfw_log_action(unsigned int log_level, const char *prefix, __u8 action);
void bpfw_log_nat(unsigned int log_level, const char *prefix, struct nat_entry *n_entry, __u8 family);
void bpfw_log_next_hop(unsigned int log_level, const char *prefix, struct next_hop *next_h);
void bpfw_log_route_type(unsigned int log_level, const char *prefix, unsigned char rtm_type);
void bpfw_log_rule(unsigned int log_level, const char *target, const char *name);


#endif
