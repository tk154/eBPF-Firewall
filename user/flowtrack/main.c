#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <linux/in.h>
#include <net/if.h>

#include <bpf/bpf.h>

#include "../../common.h"


struct cmd_args {
    bool print_nat, print_hop;
    bool action_only, redirect_only;
};

struct flow_key_value {
    struct flow_key   key;
    struct flow_value value;
};


int print_ifname(__u32 ifindex) {
    char ifname[IF_NAMESIZE];
    if_indextoname(ifindex, ifname);

    return fputs(ifname, stdout);
}

int print_vlan(__u16 vlan_id) {
    return printf(" vlan=%hu", vlan_id);
}

int print_idle(__u32 idle) {
    return printf(" %u", idle);
}

int print_l4_proto(__u8 l4_proto) {
    switch (l4_proto) {
        case IPPROTO_TCP:
            return fputs(" tcp", stdout);
        case IPPROTO_UDP:
            return fputs(" udp", stdout);
        default:
            return 0;
    }
}

int print_ip(__be32 ip, const char *prefix) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    return printf(" %s=%s", prefix, ip_str);
}

int print_port(__be16 port, const char *prefix) {
    return printf(" %s=%hu", prefix, ntohs(port));
}

int print_mac(__u8 *mac, const char *prefix) {
    return printf(" %s=%02x:%02x:%02x:%02x:%02x:%02x",
        prefix, mac[0], mac[1],mac[2], mac[3], mac[4], mac[5]);
}

int print_action(__u8 action) {
    switch (action) {
        case ACTION_PASS:
            return fputs(" [PASS]", stdout);
        case ACTION_DROP:
            return fputs(" [DROP]", stdout);
        case ACTION_REDIRECT:
            return fputs(" [REDIRECT]", stdout);
        default:
            return 0;
    }
}


void print_base(struct flow_key_value *flow) {
    print_ifname(flow->key.ifindex);

    if (flow->key.vlan_id)
        print_vlan(flow->key.vlan_id);

    print_idle(flow->value.idle);
    print_l4_proto(flow->key.l4_proto);

    print_ip(flow->key.src_ip, "src");
    print_ip(flow->key.dest_ip, "dst");
    print_port(flow->key.src_port, "sport");
    print_port(flow->key.dest_port, "dport");

    print_action(flow->value.action);
}

void print_nat(struct nat_entry *n_entry) {
    fputs(" |", stdout);

    if (n_entry->rewrite_flag & REWRITE_SRC_IP)
        print_ip(n_entry->src_ip, "snat");

    if (n_entry->rewrite_flag & REWRITE_DEST_IP)
        print_ip(n_entry->dest_ip, "dnat");

    if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
        print_port(n_entry->src_port, "spat");

    if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
        print_port(n_entry->dest_port, "dpat");
}

void print_hop(struct next_hop *next_h) {
    fputs(" | ", stdout);
    print_ifname(next_h->ifindex);

    if (next_h->vlan_id)
        print_vlan(next_h->vlan_id);

    print_mac(next_h->src_mac, "smac");
    print_mac(next_h->dest_mac, "dmac");
}

int print_endline() {
    return putchar('\n');
}

int print_flows(struct cmd_args *args) {
    char flow_map_path[32];
    snprintf(flow_map_path, sizeof(flow_map_path), "/sys/fs/bpf/%s", FLOW_MAP_NAME);

    int flow_map_fd = bpf_obj_get(flow_map_path);
    if (flow_map_fd < 0) {
        fprintf(stderr, "Error opening BPF object %s: %s (-%d).\n",
            flow_map_path, strerror(errno), errno);

        return EXIT_FAILURE;
    }

    struct flow_key_value flow;
    int rc = bpf_map_get_next_key(flow_map_fd, NULL, &flow.key);

    while (rc == 0) {
        if (bpf_map_lookup_elem(flow_map_fd, &flow.key, &flow.value) != 0) {
            fprintf(stderr, "Error looking up flow entry: %s (-%d).\n",
                strerror(errno), errno);

            return EXIT_FAILURE;
        }

        if (args->action_only   && flow.value.action == ACTION_NONE ||
            args->redirect_only && flow.value.action != ACTION_REDIRECT)
                goto get_next_key;

        print_base(&flow);

        if (args->print_nat && flow.value.n_entry.rewrite_flag)
            print_nat(&flow.value.n_entry);

        if (args->print_hop && flow.value.action == ACTION_REDIRECT)
            print_hop(&flow.value.next_h);

        print_endline();

get_next_key:
        rc = bpf_map_get_next_key(flow_map_fd, &flow.key, &flow.key);
    }

    if (rc != -ENOENT) {
        fprintf(stderr, "Error retrieving flow key: %s (-%d).\n",
            strerror(errno), errno);
        
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


void check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    struct option options[] = {
        { "nat",      no_argument, 0, 'n' },
        { "hop",      no_argument, 0, 'h' },
        { "action",   no_argument, 0, 'a' },
        { "redirect", no_argument, 0, 'r' },
        { 0,          0,           0,  0  }
    };

    int opt, opt_index;
    while ((opt = getopt_long(argc, argv, "nhar", options, &opt_index)) != -1) {
        switch (opt) {
            case 'n': args->print_nat = true; break;
            case 'h': args->print_hop = true; break;
            case 'a': args->action_only = true; break;
            case 'r': args->redirect_only = true; break;
        }
    }
}

int main(int argc, char* argv[]) {
    struct cmd_args args = {};
    check_cmd_args(argc, argv, &args);

    return print_flows(&args);
}
