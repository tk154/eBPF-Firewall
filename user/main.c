#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <signal.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common_user.h"
#include "../common.h"

#include "bpf_loader/bpf_loader.h"
#include "conntrack/conntrack.h"

#define BPF_DEFAULT_MAP_POLL_SEC 5


int fw_log_level = FW_LOG_LEVEL_INFO;

struct cmd_args {
    enum bpf_prog_type prog_type;
    char* prog_path;
    char** if_names;
    unsigned int if_count;
    unsigned int map_poll_sec;
};

// Wether to exit the main loop and the program
static bool exitLoop = false;

// Interrupt and terminate signal handler
static void signal_handler(int sig) {
    // On SIGINT or SIGTERM, the main loop should exit
    exitLoop = true;
}

// Checks if the given arguments are valid and determines the BPF hook
static bool check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    struct option options[] = {
        { "interval",  required_argument, 0, 'i' },
        { "log-level", required_argument, 0, 'l' },
        { 0,           0,                 0,  0  }
    };

    int opt, opt_index;
    while ((opt = getopt_long(argc, argv, "i:l:", options, &opt_index)) != -1) {
        switch (opt) {
            case 'i':
                long sec = strtol(optarg, NULL, 10);
                if (sec <= 0 || sec > UINT_MAX)
                    return false;

                args->map_poll_sec = sec;
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

    // Check if hook, BPF object and network interface(s) are provided in the command line
    if (argc - optind < 3)
        return false;

    // Check the hook argument
    char* prog_hook = argv[optind];
    if (strcmp(prog_hook, "xdp") == 0)
        args->prog_type = BPF_PROG_TYPE_XDP;
    else if (strcmp(prog_hook, "tc") == 0)
        args->prog_type = BPF_PROG_TYPE_SCHED_CLS;
    else
        return false;

    args->prog_path =  argv[optind + 1];
    args->if_names  = &argv[optind + 2];
    args->if_count  =  argc - optind - 2;

    return true;
}

int main(int argc, char* argv[]) {
    struct cmd_args args;
    args.map_poll_sec = BPF_DEFAULT_MAP_POLL_SEC;

    // Check if the arguments are provided correctly
    if (!check_cmd_args(argc, argv, &args)) {
        FW_ERROR("Usage: %s {xdp|tc} bpf_object_path network_interface(s)... [options]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load the BPF object (including program and maps) into the kernel
    FW_INFO("Loading BPF program into kernel ...\n");
    struct bpf_object_program* bpf = bpf_load_program(args.prog_path, args.prog_type);
    if (!bpf)
        return EXIT_FAILURE;

    // Read the conntrack info and save it inside the BPF conntrack map
    int rc = conntrack_init(bpf->obj);
    if (rc != 0)
        goto bpf_unload_program;

    FW_INFO("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    rc = bpf_ifs_attach_program(bpf->prog, args.if_names, args.if_count);
    if (rc != 0)
        goto conntrack_destroy;

    // Catch CTRL+C and SIGTERM with the handler to exit the main loop
    struct sigaction act;
    act.sa_handler = signal_handler;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    FW_INFO("Successfully loaded BPF program. Press CTRL+C to unload.\n");

    do {
        sleep(args.map_poll_sec);

        if (exitLoop)
            break;

        // Update the conntrack info
        update_conntrack(bpf->obj);
    } while (!exitLoop);

    FW_INFO("\nUnloading ...\n");

bpf_detach_program:
    // Detach the program from the specified interface names
    bpf_ifs_detach_program(bpf->prog, args.if_names, args.if_count);

conntrack_destroy:
    // De-Init conntrack
    conntrack_destroy();

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(bpf);

    return rc;
}
