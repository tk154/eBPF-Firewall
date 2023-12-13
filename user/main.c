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

/**
 * Interrupt signal handler
 * @param sig Occured signal
**/
void interrupt_handler(int sig) {
    // On SIGINT, the main loop should exit
    exitLoop = true;
}

/**
 * Checks if the given arguments are valid and determines the BPF hook
 * @param argc The number of given arguments
 * @param argv The given arguments
 * @returns The bpf_prog_type for the given hook, -1 if the hook or BPF program path is missing
 * or the hook is not xdp or tc
 * **/
int check_cmd_args(int argc, char* argv[], enum bpf_prog_type* prog_type) {
    // Check if the hook is provided in the command line
    if (argc < 2) {
        fputs("Missing hook argument: Must be either xdp or tc.\n", stderr);
        return false;
    }

    // Check if the BPF program path is provided in the command line
    if (argc < 3) {
        fputs("Missing BPF program path.\n", stderr);
        return false;
    }
    
    // Check the hook argument
    if (strcmp(argv[1], "xdp") == 0)
        *prog_type = BPF_PROG_TYPE_XDP;
    else if (strcmp(argv[1], "tc") == 0)
        *prog_type = BPF_PROG_TYPE_SCHED_CLS;
    else {
        fprintf(stderr, "Hook '%s' is not allowed: Must be either xdp or tc.\n", argv[1]);
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    enum bpf_prog_type prog_type;

    // Check if the arguments are provided correctly
    if (!check_cmd_args(argc, argv, &prog_type))
        return EXIT_FAILURE;

    char* prog_hook = argv[1];
    char* prog_path = argv[2];

    char** ifnames = &argv[3];
    unsigned int if_count = argc - 3;

    // Load the BPF object (including program and maps) into the kernel
    puts("Loading BPF program into kernel ...");
    struct bpf_object_program* bpf = bpf_load_program(prog_path, prog_type);
    if (!bpf)
        return EXIT_FAILURE;

    // Read the conntrack info and save it inside the BPF conntrack map
    int rc = conntrack_init(bpf->obj);
    if (rc != 0)
        goto bpf_unload_program;

    printf("Attaching BPF program to %s hook ...\n", prog_hook);

    // Attach the program to the specified interface names
    rc = if_count == 0 ? bpf_attach_program(bpf->prog) : bpf_ifs_attach_program(bpf->prog, ifnames, if_count);
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
    if_count == 0 ? bpf_detach_program(bpf->prog) : bpf_ifs_detach_program(bpf->prog, ifnames, if_count);

conntrack_destroy:
    conntrack_destroy();

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(bpf);

    return rc;
}
