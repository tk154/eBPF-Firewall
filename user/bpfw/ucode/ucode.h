#ifndef BPFW_UCODE_H
#define BPFW_UCODE_H

#include "../common_user.h"


struct ucode_handle;

struct ucode_handle *ucode_init();
int ucode_match_rule(struct ucode_handle *ucode_h, struct flow_key_value *flow);
void ucode_destroy(struct ucode_handle *ucode_h);


#endif
