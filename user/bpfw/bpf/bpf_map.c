#include "bpf_common.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


struct bpf_map {
    int fd;
    char name[];
};


int bpf_map_lookup_entry(struct bpf_map *map, const void *key, void *value) {
    if (bpf_map_lookup_elem(map->fd, key, value) != 0) {
        bpfw_error("Error looking up '%s' map entry: %s (-%d).\n",
            map->name, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int bpf_map_update_entry(struct bpf_map *map, const void *key, const void *value) {
    // Update the BPF entry
    if (bpf_map_update_elem(map->fd, key, value, BPF_EXIST) != 0) {
        bpfw_error("Error updating '%s' map entry: %s (-%d).\n",
            map->name, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int bpf_map_delete_entry(struct bpf_map *map, const void *key) {
    if (bpf_map_delete_elem(map->fd, key) != 0) {
        bpfw_error("Error deleting '%s' map entry: %s (-%d).\n",
            map->name, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int __bpf_map_next_entry(struct bpf_map *map, const void *key, void *next_key, void *value) {
    int rc = bpf_map_get_next_key(map->fd, key, next_key);

    switch (rc) {
        case 0:
            return bpf_map_lookup_entry(map, next_key, value);

        case -ENOENT:
            return -EOF;

        default:
            bpfw_error("Error retrieving '%s' map key: %s (-%d).\n",
                map->name, strerror(errno), errno);
            return BPFW_RC_ERROR;
    }
}

int bpf_map_first_entry(struct bpf_map *map, void *key, void *value) {
    return __bpf_map_next_entry(map, NULL, key, value);
}

int bpf_map_next_entry(struct bpf_map *map, void *key, void *value) {
    return __bpf_map_next_entry(map, key, key, value);
}


int bpf_set_map_max_entries(struct bpf_handle *bpf, const char *map_name, __u32 new_max_entries) {
    struct bpf_map *map = bpf_object__find_map_by_name(bpf->obj, map_name);
    if (!map) {
        bpfw_error("Error: Couldn't find BPF map %s.\n", map_name);
        return BPFW_RC_ERROR;
    }

    if (bpf_map__set_max_entries(map, new_max_entries) != 0) {
        bpfw_error("Error setting %s max entries: %s (-%d).\n",
            map_name, strerror(errno), errno);

        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

struct bpf_map *bpf_get_map(struct bpf_handle *bpf, const char *map_name) {
    size_t map_name_size = strlen(map_name) + 1;
    struct bpf_map *map;

    map = malloc(sizeof(*map) + map_name_size);
    if (!map) {
        bpfw_error("Error allocating BPF map handle: %s (-%d).\n",
            strerror(errno), errno);
        goto error;
    }

    // Get the file descriptor of the BPF flow map
    map->fd = bpf_object__find_map_fd_by_name(bpf->obj, map_name);
    if (map->fd < 0) {
        bpfw_error("Error: Couldn't find BPF map %s.\n", map_name);
        goto free;
    }

    strcpy(map->name, map_name);

    return map;

free:
    free(map);
error:
    return NULL;
}

void bpf_free_map(struct bpf_map *map) {
    free(map);
}
