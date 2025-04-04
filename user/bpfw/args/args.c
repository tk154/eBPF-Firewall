#include "args.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>

#include "../common_user.h"
#include "../log/log.h"

#define DEFAULT_BPF_MAP_POLL_SEC    5
#define DEFAULT_BPF_MAP_MAX_ENTRIES FLOW_MAP_DEFAULT_MAX_ENTRIES

#define DEFAULT_TCP_FLOW_TIMEOUT    30
#define DEFAULT_UDP_FLOW_TIMEOUT    30


static void print_usage(char* prog) {
    bpfw_error("Usage: %s <bpf_object_path> [network_interface(s)[:hook]...] [options]\n\n", prog);

    bpfw_error("Options:\n");
    bpfw_error("  -a, --auto-attach    Automatically attach the BPF program to all appropriate network interface.\n");
    bpfw_error("                       This is implicitly set if no network interfaces are given.\n");
    bpfw_error("  -d, --dsa            Try to attach the BPF program to the DSA switch, if there is one.\n");
    bpfw_error("                       This needs to be specified together with --auto-attach (-a).\n");
    bpfw_error("  -h, --hook           The hook where to attach the BPF program. For possible hooks, see below.\n");
    bpfw_error("  -i, --interval       BPF map poll interval in seconds (Default: %u).\n", DEFAULT_BPF_MAP_POLL_SEC);
    bpfw_error("  -l, --log-level      Log level, can be error, warning, info, debug, verbose (Default: info).\n");
    bpfw_error("  -m, --max-flows      Maximum BPF map flow entries (Default: %u).\n", DEFAULT_BPF_MAP_MAX_ENTRIES);
    bpfw_error("  -t, --tcp-timeout    BPF offload timeout for TCP flows in seconds (Default: %u).\n", DEFAULT_TCP_FLOW_TIMEOUT);
    bpfw_error("  -u, --udp-timeout    BPF offload timeout for UDP flows in seconds (Default: %u).\n\n", DEFAULT_UDP_FLOW_TIMEOUT);

    bpfw_error("Hooks:\n");
    bpfw_error("  tc            TC hoook\n");
    bpfw_error("  xdp           XDP hook\n");
    bpfw_error("  xdpgeneric    Generic/SKB XDP hook\n");
    bpfw_error("  xdpnative     Native/Driver XDP hook\n");
    bpfw_error("  xdpoffload    XDP offloaded into hardware\n\n");
    bpfw_error("If you don't specify a hook, the following attach order is tried:\n");
    bpfw_error("  xdpoffload -> xdpnative -> tc -> xdpgeneric\n\n");

    bpfw_error("When you specify a network interface, you can also override its hook after a colon.\n");
}


static char *strscpy(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n - 1);
    dest[n - 1] = '\0';

    return dest;
}

static unsigned int parse_decimal(char* number) {
    unsigned long decimal = strtoul(number, NULL, 10);
    return decimal <= UINT_MAX ? decimal : 0;
}

static __u32 parse_map_poll_sec(char *number) {
    __u32 map_poll_sec = parse_decimal(number);
    if (!map_poll_sec)
        bpfw_error("Couldn't parse BPF map poll interval value '%s'.\n\n", number);

    return map_poll_sec;
}

static __u32 parse_map_max_entries(char *number) {
    __u32 map_max_entries = parse_decimal(number);
    if (!map_max_entries)
        bpfw_error("Couldn't parse max flow entries value '%s'.\n\n", number);

    return map_max_entries;
}

static __u32 parse_flow_timeout_tcp(char *number) {
    __u32 flow_timeout_tcp = parse_decimal(number);
    if (!flow_timeout_tcp)
        bpfw_error("Couldn't parse TCP flow timeout value '%s'.\n\n", number);

    return flow_timeout_tcp;
}

static __u32 parse_flow_timeout_udp(char *number) {
    __u32 flow_timeout_udp = parse_decimal(number);
    if (!flow_timeout_udp)
        bpfw_error("Couldn't parse UDP flow timeout value '%s'.\n\n", number);

    return flow_timeout_udp;
}


static enum bpf_hook parse_hook(char* prog_hook) {
    size_t arg_len;

    if (!strcmp(prog_hook, "tc"))
        return BPF_HOOK_TC;
    if (!strcmp(prog_hook, "xdp"))
        return BPF_HOOK_XDP;

    arg_len = strlen(prog_hook);
    if (arg_len < 4)
        goto unknown_hook;

    if (!strncmp(prog_hook, "xdpgeneric", arg_len))
        return BPF_HOOK_XDP_GENERIC;
    if (!strncmp(prog_hook, "xdpnative",  arg_len))
        return BPF_HOOK_XDP_NATIVE;
    if (!strncmp(prog_hook, "xdpoffload", arg_len))
        return BPF_HOOK_XDP_OFFLOAD;

unknown_hook:
    bpfw_error("Unknown hook '%s'.\n\n", prog_hook);
    return 0;
}

static bool parse_log_level(char* log_level) {
    size_t arg_len = strlen(log_level);

    if (!strncmp(log_level, "error", arg_len))
        bpfw_set_log_level(BPFW_LOG_LEVEL_ERROR);
    else if (!strncmp(log_level, "warning", arg_len))
        bpfw_set_log_level(BPFW_LOG_LEVEL_WARN);
    else if (!strncmp(log_level, "info", arg_len))
        bpfw_set_log_level(BPFW_LOG_LEVEL_INFO);
    else if (!strncmp(log_level, "debug", arg_len))
        bpfw_set_log_level(BPFW_LOG_LEVEL_DEBUG);
    else if (!strncmp(log_level, "verbose", arg_len))
        bpfw_set_log_level(BPFW_LOG_LEVEL_VERBOSE);
    else {
        bpfw_error("Unknown log level '%s'.\n\n", log_level);
        return false;
    }

    return true;
}

static bool parse_interfaces(struct map *iface_hooks, char **if_names, unsigned int if_count) {
    char ifname[IF_NAMESIZE];
    struct list_entry *entry;
    const char *delim = ":";
    enum bpf_hook hook;
    int err, i;
    char *tok;

    for (i = 0; i < if_count; i++) {
        tok = strtok(if_names[i], delim);
        strscpy(ifname, tok, IF_NAMESIZE);

        tok = strtok(NULL, delim);
        if (tok) {
            hook = parse_hook(tok);
            if (!hook)
                return false;
        }
        else
            hook = BPF_HOOK_AUTO;

        err = map_insert_entry(iface_hooks, ifname, &hook);
        if (err) {
            if (err == -EEXIST)
                bpfw_error("Duplicate interface: %s\n\n", ifname);
            else
                bpfw_errno("Error creating iface_hooks map entry for %s", err, ifname);

            return false;
        }
    }

    return true;
}


// Checks if the given arguments are valid and determines the BPF hook
static bool parse_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    unsigned int if_count;
    int opt, opt_index;
    char **if_names;

    struct option options[] = {
        { "auto-attach", no_argument,       0, 'a' },
        { "dsa",         no_argument,       0, 'd' },
        { "hook",        required_argument, 0, 'h' },
        { "interval",    required_argument, 0, 'i' },
        { "log-level",   required_argument, 0, 'l' },
        { "max-flows",   required_argument, 0, 'm' },
        { "tcp-timeout", required_argument, 0, 't' },
        { "udp-timeout", required_argument, 0, 'u' },
        { 0,             0,                 0,  0  }
    };

    while ((opt = getopt_long(argc, argv, "adh:i:l:m:t:u:", options, &opt_index)) != -1) {
        switch (opt) {
            case 'a':
                args->auto_attach = true;
            break;

            case 'd':
                args->dsa = true;
            break;

            case 'h':
                // Check the hook argument
                args->hook = parse_hook(optarg);
                if (!args->hook)
                    return false;
            break;

            case 'i':
                args->map.poll_sec = parse_map_poll_sec(optarg);
                if (!args->map.poll_sec)
                    return false;
            break;

            case 'l':
                if (!parse_log_level(optarg))
                    return false;
            break;

            case 'm':
                args->map.max_entries = parse_map_max_entries(optarg);
                if (!args->map.max_entries)
                    return false;
            break;

            case 't':
                args->flow_timeout.tcp = parse_flow_timeout_tcp(optarg);
                if (!args->flow_timeout.tcp)
                    return false;
            break;

            case 'u':
                args->flow_timeout.udp = parse_flow_timeout_udp(optarg);
                if (!args->flow_timeout.udp)
                    return false;
            break;

            case '?':
                return false;
        }
    }

    // Check if the BPF object is provided in the command line
    if (argc - optind < 1) {
        bpfw_error("Missing BPF object file path.\n\n");
        return false;
    }

    args->bpf_obj_path = argv[optind];
    if_count = argc - optind - 1;

    if (if_count > 0) {
        if_names = &argv[optind + 1];

        if (!parse_interfaces(args->iface_hooks, if_names, if_count))
            return false;

        if (args->dsa && !args->auto_attach) {
            bpfw_error("--dsa (-d) can only be specified together with --auto-attach (-a).\n\n");
            return false;
        }
    }
    else
        args->auto_attach = true;

    return true;
}

bool check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    args->iface_hooks = map_create(IF_NAMESIZE, sizeof(enum bpf_hook));
    args->hook = BPF_HOOK_AUTO;

    args->auto_attach = false;
    args->dsa = false;

    args->map.poll_sec    = DEFAULT_BPF_MAP_POLL_SEC;
    args->map.max_entries = DEFAULT_BPF_MAP_MAX_ENTRIES;

    args->flow_timeout.tcp = DEFAULT_TCP_FLOW_TIMEOUT;
    args->flow_timeout.udp = DEFAULT_UDP_FLOW_TIMEOUT;

    // Check if the arguments are provided correctly
    if (!parse_cmd_args(argc, argv, args)) {
        print_usage(argv[0]);
        map_delete(args->iface_hooks);

        return false;
    }

    return true;
}

void free_cmd_args(struct cmd_args *args) {
    map_delete(args->iface_hooks);
}
