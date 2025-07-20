#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/rtnetlink.h>


static enum bpfw_log_level log_level = BPFW_DEFAULT_LOG_LEVEL;

#define LOG_HEAD(level, format)                                             \
    if (log_level < level) return;                                          \
    FILE *log_file = level >= BPFW_LOG_LEVEL_INFO ? stdout : stderr;        \
    do {                                                                    \
        va_list args;                                                       \
        va_start(args, format);                                             \
        vfprintf(log_file, format, args);                                   \
        va_end(args);                                                       \
    } while (0);                            

#define LOG_ERROR(error) \
    if (error) fprintf(log_file, ": %s (-%d).\n", strerror(error), error);   \
    else fputc('\n', log_file);


void bpfw_set_log_level(enum bpfw_log_level level) {
    log_level = level;
}

void bpfw_log(unsigned int level, const char* format, ...) {
    LOG_HEAD(level, format)
}

void bpfw_log_errno(enum bpfw_log_level level, int error, const char *prefix, ...) {
    LOG_HEAD(level, prefix)
    fprintf(log_file, ": %s (-%d).\n", strerror(error), error); 
}


void bpfw_log_ifindex(enum bpfw_log_level level, __u32 ifindex, int error, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    char ifname[IF_NAMESIZE] = "?";
    if_indextoname(ifindex, ifname);
    fputs(ifname, log_file);

    LOG_ERROR(error)
}

void bpfw_log_ip(enum bpfw_log_level level, const void *ip, __u8 family, int error, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(family, ip, ip_str, sizeof(ip_str));

    fputs(prefix, log_file);
    fputs(ip_str, log_file);

    LOG_ERROR(error)
}

void bpfw_log_ip_on_ifindex(enum bpfw_log_level level, const void *ip, __u8 family, __u32 ifindex, int error, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    char ifname[IF_NAMESIZE], ip_str[INET6_ADDRSTRLEN];;
    if_indextoname(ifindex, ifname);
    inet_ntop(family, ip, ip_str, sizeof(ip_str));

    fprintf(log_file, "%s%s on %s", prefix, ip_str, ifname);

    LOG_ERROR(error)
}


void bpfw_log_key(enum bpfw_log_level level, struct flow_key *f_key, const char *prefix, ...) {
    char ifname[IF_NAMESIZE], src_ip_str[INET6_ADDRSTRLEN], dest_ip_str[INET6_ADDRSTRLEN];
    const char *proto = f_key->proto == IPPROTO_TCP ? "tcp" : "udp";
    __be32 *dest_ip = flow_ip_get_dest(&f_key->ip, f_key->family);
    __be32 *src_ip = flow_ip_get_src(&f_key->ip, f_key->family);

    LOG_HEAD(level, prefix)

    if_indextoname(f_key->ifindex, ifname);
    inet_ntop(f_key->family, src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(f_key->family, dest_ip, dest_ip_str, sizeof(dest_ip_str));

    fputs(ifname, log_file);

    if (f_key->dsa_port)
        fprintf(log_file, "@p%hhu", f_key->dsa_port & ~DSA_PORT_SET);

    if (f_key->vlan_id)
        fprintf(log_file, " vlan=%hu", f_key->vlan_id);

    if (f_key->pppoe_id)
        fprintf(log_file, " pppoe=0x%hx", ntohs(f_key->pppoe_id));

    fprintf(log_file, " %s %s %hu %s %hu\n", proto,
        src_ip_str, ntohs(f_key->src_port), dest_ip_str, ntohs(f_key->dest_port));
}

void bpfw_log_nat(enum bpfw_log_level level, struct nat_entry *n_entry, __u8 family, const char *prefix, ...) {
    if (!n_entry->rewrite_flag)
        return;

    LOG_HEAD(level, prefix)
    char src_ip[INET6_ADDRSTRLEN], dest_ip[INET6_ADDRSTRLEN];

    if (n_entry->rewrite_flag & REWRITE_SRC_IP) {
        inet_ntop(family, &n_entry->src_ip, src_ip, sizeof(src_ip));
        fprintf(log_file, "%s ", src_ip);
    }
    else
        fputs("- ", log_file);

    if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
        fprintf(log_file, "%hu ", ntohs(n_entry->src_port));
    else
        fputs("- ", log_file);

    if (n_entry->rewrite_flag & REWRITE_DEST_IP) {
        inet_ntop(family, &n_entry->dest_ip, dest_ip, sizeof(dest_ip));
        fprintf(log_file, "%s ", dest_ip);
    }
    else
        fputs("- ", log_file);

    if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
        fprintf(log_file, "%hu ", ntohs(n_entry->dest_port));
    else
        fputs("- ", log_file);

    putc('\n', log_file);
}

void bpfw_log_next_hop(enum bpfw_log_level level, struct next_hop *next_h, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    char ifname[IF_NAMESIZE] = "?";
    if_indextoname(next_h->ifindex, ifname);
    fputs(ifname, log_file);

    if (next_h->dsa_port & DSA_PORT_SET)
        fprintf(log_file, "@p%hhu", next_h->dsa_port & ~DSA_PORT_SET);

    if (next_h->vlan_id)
        fprintf(log_file, " vlan=%hu", next_h->vlan_id);

    if (next_h->pppoe_id)
        fprintf(log_file, " pppoe=0x%hx", ntohs(next_h->pppoe_id));

    fprintf(log_file, " %02x:%02x:%02x:%02x:%02x:%02x\n",
        next_h->dest_mac[0], next_h->dest_mac[1], next_h->dest_mac[2],
        next_h->dest_mac[3], next_h->dest_mac[4], next_h->dest_mac[5]);
}

void bpfw_log_route_type(enum bpfw_log_level level, unsigned char rtm_type, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    switch (rtm_type) {
	    case RTN_UNICAST:
            fputs("Unicast\n", log_file);
            break;
	    case RTN_LOCAL:
            fputs("Local\n", log_file);
            break;
	    case RTN_BROADCAST:
            fputs("Broadcast\n", log_file);
            break;
	    case RTN_ANYCAST:
            fputs("Anycast\n", log_file);
            break;
	    case RTN_MULTICAST:
            fputs("Multicast\n", log_file);
            break;
	    case RTN_BLACKHOLE:
            fputs("Blackhole\n", log_file);
            break;
	    case RTN_UNREACHABLE:
            fputs("Unreachable\n", log_file);
            break;
	    case RTN_PROHIBIT:
            fputs("Prohibit\n", log_file);
            break;
	    case RTN_THROW:
            fputs("Throw\n", log_file);
            break;
	    case RTN_NAT:
            fputs("Nat\n", log_file);
            break;
	    case RTN_XRESOLVE:
            fputs("External resolver\n", log_file);
            break;
        default:
            fputs("Unknown\n", log_file);
    }   
}

void bpfw_log_action(enum bpfw_log_level level, __u8 action, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    switch (action) {
        case ACTION_FORWARD:
            fputs("Forward\n", log_file);
            break;

        case ACTION_DROP:
            fputs("Drop\n", log_file);
            break;

        case ACTION_PASS:
        case ACTION_NONE:
            fputs("Pass\n", log_file);
            break;

        default:
            fputs("Unknown\n", log_file);
    }
}

void bpfw_log_rule(enum bpfw_log_level level, const char *target, const char *name, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    if (target)
        fprintf(log_file, "%s (%s)", target, name);
    else
        fputs(name, log_file);

    putc('\n', log_file);
}
