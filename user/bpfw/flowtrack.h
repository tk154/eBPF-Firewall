#ifndef BPFW_FLOWTRACK_H
#define BPFW_FLOWTRACK_H

#include "common_user.h"


struct flowtrack_handle;

struct flowtrack_handle* flowtrack_init(struct cmd_args *args);
void flowtrack_destroy(struct flowtrack_handle* flowtrack_h, struct cmd_args *args);

int flowtrack_update(struct flowtrack_handle* flowtrack_h);


#endif
