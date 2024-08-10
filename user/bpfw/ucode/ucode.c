#include "ucode.h"

#include <errno.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <ucode/compiler.h>
#include <ucode/lib.h>
#include <ucode/vm.h>

#include "../logging/logging.h"


#define MULTILINE_STRING(...) #__VA_ARGS__

static const char *program_code = MULTILINE_STRING(
	{%
		function if_get_zone(i) {
			for (let z in fw4.zones())
				if (i in z.match_devices)
					return z;

			return null;
		}
		
		function match_rule(rule) {
			let final_verdicts = ["accept", "reject", "drop"];

			return
				(!rule.family  	  ||   family == rule.family) &&
				(!rule.saddrs_pos ||  (src_ip in rule.saddrs_pos)) &&
				(!rule.saddrs_neg || !(src_ip in rule.saddrs_neg)) &&
				/* saddrs_masked */
				(!rule.daddrs_pos ||  (dest_ip in rule.daddrs_pos)) &&
				(!rule.daddrs_neg || !(dest_ip in rule.daddrs_neg)) &&
				/* daddrs_masked */
				(rule.proto.any   ||   proto == rule.proto.name) &&
				(!rule.sports_pos ||  (src_port in rule.sports_pos)) &&
				(!rule.sports_neg || !(src_port in rule.sports_neg)) &&
				(!rule.dports_pos ||  (dest_port in rule.dports_pos)) &&
				(!rule.dports_neg || !(dest_port in rule.dports_neg)) &&
				(!rule.smacs_pos  ||  (smac in rule.smacs_pos)) &&
				(!rule.smacs_neg  || !(smac in rule.smacs_neg)) &&
				(!rule.target     ||  (rule.target in final_verdicts));
		}

		function drop_input() {
			for (let rule in fw4.rules("input"))
				if (match_rule(rule))
					return { name: `rule '${rule.name}'`, target: rule.target };

			iif_zone = if_get_zone(iif);
			if (!iif_zone)
				return { name: "default policy", target: fw4.input_policy() };

			for (let rule in fw4.rules(`input_${iif_zone.name}`))
				if (match_rule(rule))
					return { name: `rule '${rule.name}'`, target: rule.target };

			return { name: `zone '${iif_zone.name}'`, target: iif_zone.input };
		}

		function drop_forward() {
			oif_zone = if_get_zone(oif);

			for (let rule in fw4.rules("forward"))
				if (rule.dest.any || oif_zone == rule.dest.zone)
					if (match_rule(rule))
						return { name: `rule '${rule.name}'`, target: rule.target };

			iif_zone = if_get_zone(iif);
			if (!iif_zone)
				return { name: "default policy", target: fw4.forward_policy() };

			for (let rule in fw4.rules(`forward_${iif_zone.name}`))
				if (rule.dest.any || oif_zone == rule.dest.zone)
					if (match_rule(rule))
						return { name: `rule '${rule.name}'`, target: rule.target };

			return { name: `zone '${iif_zone.name}'`, target: iif_zone.forward };
		}
		
		fw4 = require("fw4");
		fw4.load(true);

		return oif ? drop_forward() : drop_input();
	%}
);


struct ucode_handle {
	uc_program_t *program;
	uc_parse_config_t config;
};

struct ucode_handle *ucode_init() {
    struct ucode_handle *ucode_h = malloc(sizeof(struct ucode_handle));
    if (!ucode_h) {
        bpfw_error("Error allocating ucode handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

	memset(&ucode_h->config, 0, sizeof(ucode_h->config));
	ucode_h->config.strict_declarations = false;
	ucode_h->config.lstrip_blocks = true;
	ucode_h->config.trim_blocks = true;

	/* create a source buffer containing the program code */
	uc_source_t *src = uc_source_new_buffer("Match rule", strdup(program_code), strlen(program_code));

	/* compile source buffer into function */
	char *syntax_error = NULL;
	ucode_h->program = uc_compile(&ucode_h->config, src, &syntax_error);

	/* release source buffer */
	uc_source_put(src);

	/* check if compilation failed */
	if (!ucode_h->program) {
		bpfw_error("Failed to compile ucode program: %s.\n", syntax_error);
		goto free;
	}

	/* initialize default module search path */
	uc_search_path_init(&ucode_h->config.module_search_path);

	return ucode_h;

free:
	free(ucode_h);

	return NULL;
}

static void vm_add_objects(uc_value_t *vm_scope, struct flow_key_value *flow, __u32 iif) {
	char iifname[IF_NAMESIZE];
	if_indextoname(iif, iifname);
	ucv_object_add(vm_scope, "iif", ucv_string_new(iifname));

	if (flow->value.action == ACTION_REDIRECT) {
		char oifname[IF_NAMESIZE];
		if_indextoname(flow->value.next_h.ifindex, oifname);
		ucv_object_add(vm_scope, "oif", ucv_string_new(oifname));
	}

	__u8 family = flow->key.family == AF_INET ? 4 : 6;
	ucv_object_add(vm_scope, "family", ucv_uint64_new(family));

	size_t ip_str_len = flow->key.family == AF_INET ?
		INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
	char src_ip[ip_str_len], dest_ip[ip_str_len];
	inet_ntop(flow->key.family, &flow->key.src_ip, src_ip, sizeof(src_ip));
	inet_ntop(flow->key.family, &flow->key.dest_ip, dest_ip, sizeof(dest_ip));
	ucv_object_add(vm_scope, "src_ip", ucv_string_new(src_ip));
	ucv_object_add(vm_scope, "dest_ip", ucv_string_new(dest_ip));

	char* proto = flow->key.proto == IPPROTO_TCP ? "tcp" : "udp";
	ucv_object_add(vm_scope, "proto", ucv_string_new(proto));

	char src_port[6], dest_port[6];
	snprintf(src_port, sizeof(src_port), "%hu", ntohs(flow->key.src_port));
	snprintf(dest_port, sizeof(dest_port), "%hu", ntohs(flow->key.dest_port));
	ucv_object_add(vm_scope, "src_port", ucv_string_new(src_port));
	ucv_object_add(vm_scope, "dest_port", ucv_string_new(dest_port));

	char src_mac[18];
	snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
		flow->value.src_mac[0], flow->value.src_mac[1], flow->value.src_mac[2],
		flow->value.src_mac[3], flow->value.src_mac[4], flow->value.src_mac[5]);
	ucv_object_add(vm_scope, "src_mac", ucv_string_new(src_mac));
}

int ucode_match_rule(struct ucode_handle *ucode_h, struct flow_key_value *flow, __u32 iif) {
	/* initialize VM context */
	uc_vm_t vm = {};
	uc_vm_init(&vm, &ucode_h->config);

	/* load standard library into global VM scope */
	uc_stdlib_load(uc_vm_scope_get(&vm));

	/* add global variables to VM scope */
	vm_add_objects(uc_vm_scope_get(&vm), flow, iif);

	/* execute compiled program function */
	uc_value_t *last_expression_result = NULL;
	int rc = uc_vm_execute(&vm, ucode_h->program, &last_expression_result);

	/* handle return status */
	switch (rc) {
		case STATUS_OK:
			uc_value_t *name_obj   = ucv_object_get(last_expression_result, "name", NULL);
			uc_value_t *target_obj = ucv_object_get(last_expression_result, "target", NULL);
			char *name   = ucv_string_get(name_obj);
			char *target = ucv_string_get(target_obj);

			flow->value.action =
				(!target || strcmp(target, "drop") != 0) ? ACTION_PASS : ACTION_DROP;

			if (!target || strcmp(target, "pass") == 0) {
				__u8 old_action = flow->value.action;
				flow->value.action =
					old_action == ACTION_REDIRECT ? __ACTION_PASS : ACTION_PASS;
			}
			else if (strcmp(target, "reject") == 0)
				flow->value.action = ACTION_PASS;
			else if (strcmp(target, "drop") == 0)
				flow->value.action = ACTION_DROP;
			else {
				bpfw_error("Error: Unknown Firewall target %s.\n", target);
				rc = BPFW_RC_ERROR;
			}
			
			bpfw_debug_rule(flow, iif, target, name);
			rc = BPFW_RC_OK;
		break;

		case STATUS_EXIT:
			rc = (int)ucv_int64_get(last_expression_result);
			bpfw_error("The ucode program exited with code: %d.\n", rc);
			rc = BPFW_RC_ERROR;
		break;

		case ERROR_COMPILE:
			bpfw_error("A compilation error occurred while running the ucode program.\n");
			rc = BPFW_RC_ERROR;
		break;

		case ERROR_RUNTIME:
			bpfw_error("A runtime error occurred while running the ucode program.\n");
			rc = BPFW_RC_ERROR;
		break;
	}

	/* free last expression result */
	ucv_put(last_expression_result);

	/* free VM context */
	uc_vm_free(&vm);

	return rc;
}

void ucode_destroy(struct ucode_handle *ucode_h) {
	/* release program */
	uc_program_put(ucode_h->program);

	/* free search module path vector */
	uc_search_path_free(&ucode_h->config.module_search_path);

	free(ucode_h);
}
