#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <signal.h>
#include <stdlib.h>

#include "common_user.h"
#include "arguments/arguments.h"
#include "flowtrack/flowtrack.h"
#include "logging/logging.h"


struct cmd_args args;
struct flowtrack_handle* flowtrack_h;

// Interrupt and terminate signal handler
static void signal_handler(int sig) {
    // On SIGINT or SIGTERM, the main loop should exit
    bpfw_info("\nUnloading ...\n");

    flowtrack_destroy(flowtrack_h, &args);
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {
    // Check if the arguments are provided correctly
    if (!check_cmd_args(argc, argv, &args))
        return EXIT_FAILURE;

    flowtrack_h = flowtrack_init(&args);
    if (!flowtrack_h)
        return EXIT_FAILURE;

    // Catch CTRL+C and SIGTERM with the handler to exit the main loop
    struct sigaction act;
    act.sa_handler = signal_handler;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    bpfw_info("Successfully loaded BPF program. Press CTRL+C to unload.\n");

    if (flowtrack_loop(flowtrack_h) != BPFW_RC_OK) {
        flowtrack_destroy(flowtrack_h, &args);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
