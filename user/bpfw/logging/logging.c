#include "logging.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <linux/rtnetlink.h>


static unsigned int bpfw_log_level = BPFW_LOG_INFO;

#define LOG_FUNC_HEAD \
    if (bpfw_log_level < log_level) \
        return; \
    \
    FILE *stdlog = log_level >= BPFW_LOG_INFO ? stdout : stderr;

#define LOG_ERROR_TAIL \
    if (error) \
        fprintf(stdlog, ": %s (-%d).", strerror(error), error); \
    \
    putc('\n', stdlog); \


void bpfw_set_log_level(unsigned int log_level) {
    bpfw_log_level = log_level;
}

void bpfw_log(unsigned int log_level, const char* format, ...) {
    LOG_FUNC_HEAD

    va_list args;
    va_start(args, format);
    vfprintf(stdlog, format, args);
    va_end(args);
}

void bpfw_log_ifindex(unsigned int log_level, const char *prefix, __u32 ifindex, const char *suffix, int error) {
    LOG_FUNC_HEAD

    char ifname[IF_NAMESIZE];
    if_indextoname(ifindex, ifname);

    fputs(prefix, stdlog);
    fputs(ifname, stdlog);
    fputs(suffix, stdlog);

    LOG_ERROR_TAIL
}

void bpfw_log_ip(unsigned int log_level, const char *prefix, void *ip, __u8 family, int error) {
    LOG_FUNC_HEAD

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(family, ip, ip_str, sizeof(ip_str));

    fputs(prefix, stdlog);
    fputs(ip_str, stdlog);

    LOG_ERROR_TAIL
}

void bpfw_log_ip_on_ifindex(unsigned int log_level, const char *prefix, void *ip, __u8 family, __u32 ifindex, int error) {
    LOG_FUNC_HEAD

    char ifname[IF_NAMESIZE];
    if_indextoname(ifindex, ifname);

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(family, ip, ip_str, sizeof(ip_str));

    fprintf(stdlog, "%s%s on %s", prefix, ip_str, ifname);

    LOG_ERROR_TAIL
}

void bpfw_log_key(unsigned int log_level, const char* prefix, struct flow_key *f_key) {
    LOG_FUNC_HEAD

    char ifname[IF_NAMESIZE];
    if_indextoname(f_key->ifindex, ifname);

    char src_ip[INET6_ADDRSTRLEN], dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(f_key->family, &f_key->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(f_key->family, &f_key->dest_ip, dest_ip, sizeof(dest_ip));

    const char *proto = f_key->proto == IPPROTO_TCP ? "tcp" : "udp";

    fputs(prefix, stdlog);
    fputs(ifname, stdlog);

    if (f_key->dsa_port)
        fprintf(stdlog, "@p%hhu", f_key->dsa_port & ~DSA_PORT_SET);

    if (f_key->vlan_id)
        fprintf(stdlog, " vlan=%hu", f_key->vlan_id);

    if (f_key->pppoe_id)
        fprintf(stdlog, " pppoe=0x%hx", ntohs(f_key->pppoe_id));

    fprintf(stdlog, " %s %s %hu %s %hu\n", proto,
        src_ip, ntohs(f_key->src_port), dest_ip, ntohs(f_key->dest_port));
}

void bpfw_log_nat(unsigned int log_level, const char *prefix, struct nat_entry *n_entry, __u8 family) {
    if (!n_entry->rewrite_flag)
        return;

    LOG_FUNC_HEAD

    fputs(prefix, stdlog);

    if (n_entry->rewrite_flag & REWRITE_SRC_IP) {
        char src_ip[family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];
        inet_ntop(family, &n_entry->src_ip, src_ip, sizeof(src_ip));
        fprintf(stdlog, " %s", src_ip);
    }
    else
        fputs(" -", stdlog);

    if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
        fprintf(stdlog, " %hu", ntohs(n_entry->src_port));
    else
        fputs(" -", stdlog);

    if (n_entry->rewrite_flag & REWRITE_DEST_IP) {
        char dest_ip[family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];
        inet_ntop(family, &n_entry->dest_ip, dest_ip, sizeof(dest_ip));
        fprintf(stdlog, " %s", dest_ip);
    }
    else
        fputs(" -", stdlog);

    if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
        fprintf(stdlog, " %hu", ntohs(n_entry->dest_port));
    else
        fputs(" -", stdlog);

    putc('\n', stdlog);
}

void bpfw_log_next_hop(unsigned int log_level, const char *prefix, struct next_hop *next_h) {
    LOG_FUNC_HEAD

    char ifname[IF_NAMESIZE];
    if_indextoname(next_h->ifindex, ifname);

    fputs(prefix, stdlog);
    fputs(ifname, stdlog);

    if (next_h->dsa_port & DSA_PORT_SET)
        fprintf(stdlog, "@p%hhu", next_h->dsa_port & ~DSA_PORT_SET);

    if (next_h->vlan_id)
        fprintf(stdlog, " vlan=%hu", next_h->vlan_id);

    if (next_h->pppoe_id)
        fprintf(stdlog, " pppoe=0x%hx", ntohs(next_h->pppoe_id));

    fprintf(stdlog, " %02x:%02x:%02x:%02x:%02x:%02x\n",
        next_h->src_mac[0], next_h->src_mac[1], next_h->src_mac[2],
        next_h->src_mac[3], next_h->src_mac[4], next_h->src_mac[5]);
}

void bpfw_log_route_type(unsigned int log_level, const char *prefix, unsigned char rtm_type) {
    LOG_FUNC_HEAD

    fputs(prefix, stdlog);

    switch (rtm_type) {
	    case RTN_UNICAST:
            fputs("Unicast\n", stdlog);
            break;
	    case RTN_LOCAL:
            fputs("Local\n", stdlog);
            break;
	    case RTN_BROADCAST:
            fputs("Broadcast\n", stdlog);
            break;
	    case RTN_ANYCAST:
            fputs("Anycast\n", stdlog);
            break;
	    case RTN_MULTICAST:
            fputs("Multicast\n", stdlog);
            break;
	    case RTN_BLACKHOLE:
            fputs("Blackhole\n", stdlog);
            break;
	    case RTN_UNREACHABLE:
            fputs("Unreachable\n", stdlog);
            break;
	    case RTN_PROHIBIT:
            fputs("Prohibit\n", stdlog);
            break;
	    case RTN_THROW:
            fputs("Throw\n", stdlog);
            break;
	    case RTN_NAT:
            fputs("Nat\n", stdlog);
            break;
	    case RTN_XRESOLVE:
            fputs("External resolver\n", stdlog);
            break;
        default:
            fputs("Unknown\n", stdlog);
    }   
}

void bpfw_log_action(unsigned int log_level, const char *prefix, __u8 action) {
    LOG_FUNC_HEAD

    fputs(prefix, stdlog);

    switch (action) {
        case ACTION_PASS:
            fputs("Pass\n", stdlog);
            break;

        case ACTION_DROP:
            fputs("Drop\n", stdlog);
            break;

        case ACTION_REDIRECT:
            fputs("Redirect\n", stdlog);
            break;

        case __ACTION_PASS:
            fputs("Pass (?)\n", stdlog);
            break;

        default:
            fputs("None\n", stdlog);
    }
}

void bpfw_log_rule(unsigned int log_level, struct flow_key_value *flow, __u32 iif, const char *target, const char *name) {
    LOG_FUNC_HEAD

    char iifname[IF_NAMESIZE];
    if_indextoname(iif, iifname);

    size_t ip_str_len = flow->key.family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char src_ip[ip_str_len], dest_ip[ip_str_len];

    inet_ntop(flow->key.family, &flow->key.src_ip, src_ip, sizeof(src_ip));
    inet_ntop(flow->key.family, &flow->key.dest_ip, dest_ip, sizeof(dest_ip));

    if (target)
        bpfw_debug("%s (%s): ", target, name);
    else
        bpfw_debug("%s: ", name);

    bpfw_debug("%s %02x:%02x:%02x:%02x:%02x:%02x "
               "%s %s %hu %s %hu\n", iifname,
        flow->value.src_mac[0], flow->value.src_mac[1], flow->value.src_mac[2],
        flow->value.src_mac[3], flow->value.src_mac[4], flow->value.src_mac[5],
        flow->key.proto == IPPROTO_TCP ? "tcp" : "udp",
        src_ip, ntohs(flow->key.src_port), dest_ip, ntohs(flow->key.dest_port));
}
