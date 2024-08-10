#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <signal.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>

#include "common_user.h"
#include "flowtrack.h"
#include "logging/logging.h"

#define DEFAULT_BPF_MAP_POLL_SEC    5
#define DEFAULT_BPF_MAP_MAX_ENTRIES 1024

#define DEFAULT_TCP_FLOW_TIMEOUT    30
#define DEFAULT_UDP_FLOW_TIMEOUT    30


struct flowtrack_handle* flowtrack_h;

struct cmd_args args = {
    .dsa = false,

    .map_poll_sec    = DEFAULT_BPF_MAP_POLL_SEC,
    .map_max_entries = DEFAULT_BPF_MAP_MAX_ENTRIES,

    .tcp_flow_timeout = DEFAULT_TCP_FLOW_TIMEOUT,
    .udp_flow_timeout = DEFAULT_UDP_FLOW_TIMEOUT
};


static void print_usage(char* prog) {
    bpfw_error("Usage: %s <hook> <bpf_object_path> [network_interface(s)...] [options]\n\n", prog);

    bpfw_error("Hooks:\n");
    bpfw_error("  xdp           XDP hook\n");
    bpfw_error("  xdpgeneric    Generic/SKB XDP hook\n");
    bpfw_error("  xdpnative     Native/Driver XDP hook\n");
    bpfw_error("  xdpoffload    XDP offloaded into hardware\n");
    bpfw_error("  tc            TC hoook\n\n");

    bpfw_error("Options:\n");
    bpfw_error("  -d  --dsa            Try to attach the BPF program to the DSA switch, if there is one.\n");
    bpfw_error("  -i, --interval       BPF map poll interval in seconds (Default: %u).\n", DEFAULT_BPF_MAP_POLL_SEC);
    bpfw_error("  -l, --log-level      Log level, can be error, warning, info, debug, verbose (Default: info).\n");
    bpfw_error("  -m, --max-flows      Maximum BPF map flow entries (Default: %u).\n", DEFAULT_BPF_MAP_MAX_ENTRIES);
    bpfw_error("  -t, --tcp-timeout    BPF offload timeout for TCP flows in seconds (Default: %u).\n", DEFAULT_TCP_FLOW_TIMEOUT);
    bpfw_error("  -u, --udp-timeout    BPF offload timeout for UDP flows in seconds (Default: %u).\n", DEFAULT_UDP_FLOW_TIMEOUT);
}

// Checks if the given arguments are valid and determines the BPF hook
static bool check_cmd_args(int argc, char* argv[]) {
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
                args.dsa = true;
            break;

            case 'i':
                args.map_poll_sec = strtoul(optarg, NULL, 10);
                if (!args.map_poll_sec)
                    return false;
            break;

            case 'l':
                size_t arg_len = strlen(optarg);

                if (strncmp(optarg, "error", arg_len) == 0)
                    bpfw_set_log_level(BPFW_LOG_ERROR);
                else if (strncmp(optarg, "warning", arg_len) == 0)
                    bpfw_set_log_level(BPFW_LOG_WARN);
                else if (strncmp(optarg, "info", arg_len) == 0)
                    bpfw_set_log_level(BPFW_LOG_INFO);
                else if (strncmp(optarg, "debug", arg_len) == 0)
                    bpfw_set_log_level(BPFW_LOG_DEBUG);
                else if (strncmp(optarg, "verbose", arg_len) == 0)
                    bpfw_set_log_level(BPFW_LOG_VERBOSE);
                else
                    return false;
            break;

            case 'm':
                args.map_max_entries = strtoul(optarg, NULL, 10);
                if (!args.map_max_entries)
                    return false;

            case 't':
                args.tcp_flow_timeout = strtoul(optarg, NULL, 10);
                if (!args.tcp_flow_timeout)
                    return false;
            break;

            case 'u':
                args.udp_flow_timeout = strtoul(optarg, NULL, 10);
                if (!args.udp_flow_timeout)
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
    char* prog_hook = argv[optind];
    size_t arg_len = strlen(prog_hook);

    if (strcmp(prog_hook, "xdp") == 0)
        args.hook = BPFW_HOOK_XDP;
    else if (strncmp(prog_hook, "xdpgeneric", arg_len) == 0)
        args.hook = BPFW_HOOK_XDP_GENERIC;
    else if (strncmp(prog_hook, "xdpnative",  arg_len) == 0)
        args.hook = BPFW_HOOK_XDP_NATIVE;
    else if (strncmp(prog_hook, "xdpoffload", arg_len) == 0)
        args.hook = BPFW_HOOK_XDP_OFFLOAD;
    else if (strcmp(prog_hook, "tc") == 0)
        args.hook = BPFW_HOOK_TC;
    else
        return false;

    args.obj_path = argv[optind + 1];
    args.if_count = argc - optind - 2;

    if (args.if_count > 0)
        args.if_names = &argv[optind + 2];

    return true;
}

// Interrupt and terminate signal handler
static void signal_handler(int sig) {
    // On SIGINT or SIGTERM, the main loop should exit
    bpfw_info("\nUnloading ...\n");

    flowtrack_destroy(flowtrack_h, &args);
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {
    // Check if the arguments are provided correctly
    if (!check_cmd_args(argc, argv)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    flowtrack_h = flowtrack_init(&args);
    if (!flowtrack_h)
        return EXIT_FAILURE;

    // Catch CTRL+C and SIGTERM with the handler to exit the main loop
    struct sigaction act;
    act.sa_handler = signal_handler;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    bpfw_info("Successfully loaded BPF program. Press CTRL+C to unload.\n");

    while (1) {
        sleep(args.map_poll_sec);

        if (flowtrack_update(flowtrack_h) != 0) {
            flowtrack_destroy(flowtrack_h, &args);
            return EXIT_FAILURE;
        }
    }
}
