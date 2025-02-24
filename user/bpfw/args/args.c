#include "args.h"

#include <getopt.h>
#include <limits.h>
#include <stdlib.h>

#include "../common_user.h"
#include "../log/log.h"

#define NUM_REQUIRED_ARGS   1

#define DEFAULT_BPF_MAP_POLL_SEC    5
#define DEFAULT_BPF_MAP_MAX_ENTRIES FLOW_MAP_DEFAULT_MAX_ENTRIES

#define DEFAULT_TCP_FLOW_TIMEOUT    30
#define DEFAULT_UDP_FLOW_TIMEOUT    30


static void print_usage(char* prog) {
    bpfw_error("Usage: %s <hook> <bpf_object_path> [network_interface(s)...] [options]\n\n", prog);

    bpfw_error("Hooks:\n");
    bpfw_error("  tc            TC hoook\n");
    bpfw_error("  xdp           XDP hook\n");
    bpfw_error("  xdpgeneric    Generic/SKB XDP hook\n");
    bpfw_error("  xdpnative     Native/Driver XDP hook\n");
    bpfw_error("  xdpoffload    XDP offloaded into hardware\n\n");

    bpfw_error("Options:\n");
    bpfw_error("  -d, --dsa            Try to attach the BPF program to the DSA switch, if there is one.\n");
    bpfw_error("  -i, --interval       BPF map poll interval in seconds (Default: %u).\n", DEFAULT_BPF_MAP_POLL_SEC);
    bpfw_error("  -l, --log-level      Log level, can be error, warning, info, debug, verbose (Default: info).\n");
    bpfw_error("  -m, --max-flows      Maximum BPF map flow entries (Default: %u).\n", DEFAULT_BPF_MAP_MAX_ENTRIES);
    bpfw_error("  -t, --tcp-timeout    BPF offload timeout for TCP flows in seconds (Default: %u).\n", DEFAULT_TCP_FLOW_TIMEOUT);
    bpfw_error("  -u, --udp-timeout    BPF offload timeout for UDP flows in seconds (Default: %u).\n\n", DEFAULT_UDP_FLOW_TIMEOUT);
}

static unsigned int parse_decimal(char* number) {
    unsigned long value = strtoul(number, NULL, 10);
    return value <= UINT_MAX ? value : 0;
}

static enum bpf_hook parse_hook(char* prog_hook) {
    size_t arg_len = strlen(prog_hook);

    if (strcmp(prog_hook, "tc") == 0)
        return BPF_HOOK_TC;
    if (strcmp(prog_hook, "xdp") == 0)
        return BPF_HOOK_XDP;

    if (strncmp(prog_hook, "xdpgeneric", arg_len) == 0)
        return BPF_HOOK_XDP_GENERIC;
    if (strncmp(prog_hook, "xdpnative",  arg_len) == 0)
        return BPF_HOOK_XDP_NATIVE;
    if (strncmp(prog_hook, "xdpoffload", arg_len) == 0)
        return BPF_HOOK_XDP_OFFLOAD;

    return 0;
}

static bool parse_log_level(char* log_level) {
    size_t arg_len = strlen(log_level);

    if (strncmp(log_level, "error", arg_len) == 0)
        bpfw_set_log_level(BPFW_LOG_ERROR);
    else if (strncmp(log_level, "warning", arg_len) == 0)
        bpfw_set_log_level(BPFW_LOG_WARN);
    else if (strncmp(log_level, "info", arg_len) == 0)
        bpfw_set_log_level(BPFW_LOG_INFO);
    else if (strncmp(log_level, "debug", arg_len) == 0)
        bpfw_set_log_level(BPFW_LOG_DEBUG);
    else if (strncmp(log_level, "verbose", arg_len) == 0)
        bpfw_set_log_level(BPFW_LOG_VERBOSE);
    else
        return false;

    return true;
}

static bool parse_interfaces(struct list_entry **if_hooks, char **if_names, unsigned int if_count) {
    struct list_entry *entry;
    struct if_hook *if_hook;
    const char *delim = ":";
    char *if_name, *hook;

    for (unsigned int i = 0; i < if_count; i++) {
        entry = list_new_entry(if_hooks, sizeof(struct if_hook));
        if (!entry)
            goto error;

        if (!*if_hooks)
            *if_hooks = entry;

        if_hook = entry->data;

        if_name = strtok(if_names[i], delim);
        strncpy(if_hook->ifname, if_name, IF_NAMESIZE - 1);
        if_hook->ifname[IF_NAMESIZE - 1] = '\0';

        hook = strtok(NULL, delim);
        if (hook) {
            if_hook->hook = parse_hook(hook);
            if (!if_hook->hook)
                goto error;
        }
        else
            if_hook->hook = BPF_HOOK_AUTO;
    }

    return true;

error:
    list_delete(*if_hooks);
    return false;
}

// Checks if the given arguments are valid and determines the BPF hook
static bool parse_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    unsigned int if_count;
    int opt, opt_index;
    char **if_names;

    struct option options[] = {
        { "all",         no_argument,       0, 'a' },
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
                args->auto = true;
            break;

            case 'd':
                args->dsa = true;
            break;

            case 'h':
                // Check the hook argument
                args->hook = parse_hook(argv[optind]);
                if (!args->hook)
                    return false;
            break;

            case 'i':
                args->map.poll_sec = parse_decimal(optarg);
                if (!args->map.poll_sec)
                    return false;
            break;

            case 'l':
                if (!parse_log_level(optarg))
                    return false;
            break;

            case 'm':
                args->map.max_entries = parse_decimal(optarg);
                if (!args->map.max_entries)
                    return false;

            case 't':
                args->flow_timeout.tcp = parse_decimal(optarg);
                if (!args->flow_timeout.tcp)
                    return false;
            break;

            case 'u':
                args->flow_timeout.udp = parse_decimal(optarg);
                if (!args->flow_timeout.udp)
                    return false;
            break;

            case '?':
                return false;
        }
    }

    // Check if the BPF object is provided in the command line
    if (argc - optind < NUM_REQUIRED_ARGS)
        return false;

    args->bpf_obj_path = argv[optind + 1];

    if_count = argc - optind - 2;
    if (if_count > 0) {
        if_names = &argv[optind + 2];
        return parse_interfaces(&args->if_hooks, if_names, if_count);
    }

    return true;
}

bool check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    args->if_hooks = NULL;
    args->hook = BPF_HOOK_AUTO;

    args->auto = false;
    args->dsa = false;

    args->map.poll_sec    = DEFAULT_BPF_MAP_POLL_SEC;
    args->map.max_entries = DEFAULT_BPF_MAP_MAX_ENTRIES;

    args->flow_timeout.tcp = DEFAULT_TCP_FLOW_TIMEOUT;
    args->flow_timeout.udp = DEFAULT_UDP_FLOW_TIMEOUT;

    // Check if the arguments are provided correctly
    if (!parse_cmd_args(argc, argv, args)) {
        print_usage(argv[0]);
        return false;
    }

    return true;
}

void free_cmd_args(struct cmd_args *args) {
    list_delete(args->if_hooks);
    args->if_hooks = NULL;
}
