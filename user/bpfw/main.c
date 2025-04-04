#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <signal.h>
#include <stdlib.h>

#include "common_user.h"
#include "args/args.h"
#include "flowtrack/flowtrack.h"

#include "log/log.h"


struct cmd_args args;
struct flowtrack_handle *flowtrack_h;

// Interrupt and terminate signal handler
static void signal_handler(int sig) {
    // On SIGINT or SIGTERM, the main loop should exit
    bpfw_info("\nUnloading ...\n");

    flowtrack_destroy(flowtrack_h, &args);
    free_cmd_args(&args);

    exit(EXIT_SUCCESS);
}

static void setup_signal_handler() {
    // Catch CTRL+C and SIGTERM with the handler to exit the main loop
    struct sigaction act;
    act.sa_handler = signal_handler;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}


int main(int argc, char* argv[]) {
    // Check if the arguments are provided correctly
    if (!check_cmd_args(argc, argv, &args))
        goto error;

    flowtrack_h = flowtrack_init(&args);
    if (!flowtrack_h)
        goto free_cmd_args;

    setup_signal_handler();

    bpfw_info("Successfully loaded BPF program. Press CTRL+C to unload.\n");

    if (flowtrack_loop(flowtrack_h) != BPFW_RC_OK)
        goto flowtrack_destroy;

    return EXIT_SUCCESS;

flowtrack_destroy:
    flowtrack_destroy(flowtrack_h, &args);

free_cmd_args:
    free_cmd_args(&args);

error:
    return EXIT_FAILURE;
}
