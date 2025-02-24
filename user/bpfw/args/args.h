#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include "../common_user.h"
#include "../list/list.h"


struct cmd_args {
    char *bpf_obj_path;

    struct list_entry *if_hooks;
    enum bpf_hook hook;
    bool auto_attach, dsa;

    struct map_settings map;
    struct flow_timeout flow_timeout;
};

bool check_cmd_args(int argc, char* argv[], struct cmd_args *args);
void free_cmd_args(struct cmd_args *args);

#endif
