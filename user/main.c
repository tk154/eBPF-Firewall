#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <signal.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../common.h"
#include "bpf_loader/bpf_loader.h"
#include "conntrack/conntrack.h"


// Wether to exit the main loop and the program
bool exitLoop = false;

// Interrupt signal handler
void interrupt_handler(int sig) {
    // On SIGINT, the main loop should exit
    exitLoop = true;
}

// Checks if the given arguments are valid and determines the BPF hook
bool check_cmd_args(int argc, char* argv[], enum bpf_prog_type* prog_type,
                    char** prog_path, char*** ifnames, unsigned int* if_count)
{
    // Check if the hook is provided in the command line
    if (argc < 2) {
        fputs("Missing hook argument: Must be either xdp or tc.\n", stderr);
        return false;
    }

    // Check if the BPF program/object path is provided in the command line
    if (argc < 3) {
        fputs("Missing BPF object path.\n", stderr);
        return false;
    }

    // Check if network interface(s) are provided in the command line
    if (argc < 4) {
        fputs("Missing network interface(s).\n", stderr);
        return false;
    }
    

    char* prog_hook = argv[1];

    // Check the hook argument
    if (strcmp(prog_hook, "xdp") == 0)
        *prog_type = BPF_PROG_TYPE_XDP;
    else if (strcmp(prog_hook, "tc") == 0)
        *prog_type = BPF_PROG_TYPE_SCHED_CLS;
    else {
        fprintf(stderr, "Hook '%s' is not allowed: Must be either xdp or tc.\n", prog_hook);
        return false;
    }

    *prog_path =  argv[2];
    *ifnames   = &argv[3];
    *if_count  = argc - 3;

    return true;
}

int main(int argc, char* argv[]) {
    enum bpf_prog_type prog_type;
    char *prog_path, **ifnames;
    unsigned int if_count;

    // Check if the arguments are provided correctly
    if (!check_cmd_args(argc, argv, &prog_type, &prog_path, &ifnames, &if_count))
        return EXIT_FAILURE;

    // Load the BPF object (including program and maps) into the kernel
    puts("Loading BPF program into kernel ...");
    struct bpf_object_program* bpf = bpf_load_program(prog_path, prog_type);
    if (!bpf)
        return EXIT_FAILURE;

    // Read the conntrack info and save it inside the BPF conntrack map
    int rc = conntrack_init(bpf->obj);
    if (rc != 0)
        goto bpf_unload_program;

    printf("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    rc = bpf_ifs_attach_program(bpf->prog, ifnames, if_count);
    if (rc != 0)
        goto conntrack_destroy;

    // Catch CTRL+C with the handler to exit the main loop
    struct sigaction act;
    act.sa_handler = interrupt_handler;
    sigaction(SIGINT, &act, NULL);

    puts("Successfully loaded BPF program. Press CTRL+C to unload.");

    while (!exitLoop) {
        // Update the conntrack info
        update_conntrack(bpf->obj);
        sleep(2);
    }

    puts("\nUnloading ...");

bpf_detach_program:
    // Detach the program from the specified interface names
    bpf_ifs_detach_program(bpf->prog, ifnames, if_count);

conntrack_destroy:
    conntrack_destroy();

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(bpf);

    return rc;
}
