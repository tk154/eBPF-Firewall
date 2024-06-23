#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <signal.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>

#include <linux/if_link.h>

#include "common_user.h"
#include "flowtrack.h"

#define BPF_DEFAULT_MAP_POLL_SEC 2


int fw_log_level = FW_LOG_LEVEL_INFO;
struct flowtrack_handle* flowtrack_h;

struct cmd_args args = {
    .map_poll_sec = BPF_DEFAULT_MAP_POLL_SEC
};


static void print_usage(char* prog) {
    FW_ERROR("Usage: %s hook bpf_object_path [network_interface(s)...] [options]\n\n", prog);

    FW_ERROR("Hooks:\n");
    FW_ERROR("  xdp       \tXDP hook\n");
    FW_ERROR("  xdpgeneric\tGeneric/SKB XDP hook\n");
    FW_ERROR("  xdpdrv    \tDriver/Native XDP hook\n");
    FW_ERROR("  xdpoffload\tXDP offloaded into hardware\n");
    FW_ERROR("  tc        \tTC hoook\n\n");

    FW_ERROR("Options:\n");
    FW_ERROR("  -i, --interval \tBPF map poll interval in seconds (Default: %u)\n", BPF_DEFAULT_MAP_POLL_SEC);
    FW_ERROR("  -l, --log-level\tLog level, can be error, warning, info, debug, verbose (Default: info)\n");
}

// Checks if the given arguments are valid and determines the BPF hook
static bool check_cmd_args(int argc, char* argv[]) {
    struct option options[] = {
        { "interval",  required_argument, 0, 'i' },
        { "log-level", required_argument, 0, 'l' },
        { 0,           0,                 0,  0  }
    };

    int opt, opt_index;
    while ((opt = getopt_long(argc, argv, "i:l:", options, &opt_index)) != -1) {
        switch (opt) {
            case 'i':
                char *endptr = NULL;
                args.map_poll_sec = strtoul(optarg, &endptr, 10);
                if (optarg == endptr)
                    return false;
            break;

            case 'l':
                size_t arg_len = strlen(optarg);

                if (strncmp(optarg, "error", arg_len) == 0)
                    fw_log_level = FW_LOG_LEVEL_ERROR;
                else if (strncmp(optarg, "warning", arg_len) == 0)
                    fw_log_level = FW_LOG_LEVEL_WARN;
                else if (strncmp(optarg, "info", arg_len) == 0)
                    fw_log_level = FW_LOG_LEVEL_INFO;
                else if (strncmp(optarg, "debug", arg_len) == 0)
                    fw_log_level = FW_LOG_LEVEL_DEBUG;
                else if (strncmp(optarg, "verbose", arg_len) == 0)
                    fw_log_level = FW_LOG_LEVEL_VERBOSE;
                else
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
    int xdp_cmp = strcmp(prog_hook, "xdp");

    if (xdp_cmp >= 0) {
        args.prog_type = BPF_PROG_TYPE_XDP;

        if (xdp_cmp > 0) {
            size_t arg_len = strlen(prog_hook);

            if (strncmp(prog_hook, "xdpgeneric", arg_len) == 0)
                args.xdp_flags = XDP_FLAGS_SKB_MODE;
            else if (strncmp(prog_hook, "xdpdrv", arg_len) == 0)
                args.xdp_flags = XDP_FLAGS_DRV_MODE;
            else if (strncmp(prog_hook, "xdpoffload", arg_len) == 0)
                args.xdp_flags = XDP_FLAGS_HW_MODE;
            else
                return false;
        }
    }
    else if (strcmp(prog_hook, "tc") == 0)
        args.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    else
        return false;

    args.prog_path = argv[optind + 1];
    args.if_count  = argc - optind - 2;

    if (args.if_count > 0)
        args.if_names = &argv[optind + 2];

    return true;
}

// Interrupt and terminate signal handler
static void signal_handler(int sig) {
    // On SIGINT or SIGTERM, the main loop should exit
    FW_INFO("\nUnloading ...\n");

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

    FW_INFO("Successfully loaded BPF program. Press CTRL+C to unload.\n");

    while (1) {
        sleep(args.map_poll_sec);

        if (flowtrack_update(flowtrack_h) != 0) {
            flowtrack_destroy(flowtrack_h, &args);
            return EXIT_FAILURE;
        }
    }
}
