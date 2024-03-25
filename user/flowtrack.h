#ifndef BPFW_FLOWTRACK_H
#define BPFW_FLOWTRACK_H

#include "common_user.h"


int flowtrack_init(struct cmd_args *args);
void flowtrack_destroy(struct cmd_args *args);

int flowtrack_update();


#endif
