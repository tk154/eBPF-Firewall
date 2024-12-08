#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include "../common_user.h"


struct cmd_args {
    char* obj_path;
    enum bpfw_hook hook;

    char** if_names;
    unsigned int if_count;

    bool dsa;

    __u32 map_poll_sec;
    __u32 map_max_entries;

    struct flow_timeout flow_timeout;
};

bool check_cmd_args(int argc, char* argv[], struct cmd_args *args);


#endif
