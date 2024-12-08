#include "arguments.h"

#include <getopt.h>
#include <stdlib.h>

#include "../common_user.h"
#include "../logging/logging.h"

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
    return strtoul(number, NULL, 10);
}

static enum bpfw_hook parse_hook(char* prog_hook) {
    // Check the hook argument
    size_t arg_len = strlen(prog_hook);

    if (strcmp(prog_hook, "tc") == 0)
        return BPFW_HOOK_TC;
    else if (strcmp(prog_hook, "xdp") == 0)
        return BPFW_HOOK_XDP;
    else if (strncmp(prog_hook, "xdpgeneric", arg_len) == 0)
        return BPFW_HOOK_XDP_GENERIC;
    else if (strncmp(prog_hook, "xdpnative",  arg_len) == 0)
        return BPFW_HOOK_XDP_NATIVE;
    else if (strncmp(prog_hook, "xdpoffload", arg_len) == 0)
        return BPFW_HOOK_XDP_OFFLOAD;

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

// Checks if the given arguments are valid and determines the BPF hook
static bool parse_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    struct option options[] = {
        { "dsa",         no_argument,       0, 'd' },
        { "interval",    required_argument, 0, 'i' },
        { "log-level",   required_argument, 0, 'l' },
        { "max-flows",   required_argument, 0, 'm' },
        { "tcp-timeout", required_argument, 0, 't' },
        { "udp-timeout", required_argument, 0, 'u' },
        { 0,             0,                 0,  0  }
    };

    int opt, opt_index;
    while ((opt = getopt_long(argc, argv, "di:l:m:t:u:", options, &opt_index)) != -1) {
        switch (opt) {
            case 'd':
                args->dsa = true;
            break;

            case 'i':
                args->map_poll_sec = parse_decimal(optarg);
                if (!args->map_poll_sec)
                    return false;
            break;

            case 'l':
                if (!parse_log_level(optarg))
                    return false;
            break;

            case 'm':
                args->map_max_entries = parse_decimal(optarg);
                if (!args->map_max_entries)
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

    // Check if BPF hook and object are provided in the command line
    if (argc - optind < 2)
        return false;

    // Check the hook argument
    args->hook = parse_hook(argv[optind]);
    if (!args->hook)
        return false;

    args->obj_path = argv[optind + 1];
    args->if_count = argc - optind - 2;

    if (args->if_count > 0)
        args->if_names = &argv[optind + 2];

    return true;
}

bool check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    args->dsa = false;

    args->map_poll_sec    = DEFAULT_BPF_MAP_POLL_SEC;
    args->map_max_entries = DEFAULT_BPF_MAP_MAX_ENTRIES;

    args->flow_timeout.tcp = DEFAULT_TCP_FLOW_TIMEOUT;
    args->flow_timeout.udp = DEFAULT_UDP_FLOW_TIMEOUT;

    // Check if the arguments are provided correctly
    if (!parse_cmd_args(argc, argv, args)) {
        print_usage(argv[0]);
        return false;
    }

    return true;
}
