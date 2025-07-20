#ifndef BPFW_MAP_H
#define BPFW_MAP_H

#include <stddef.h>


struct map;

struct map *map_create(size_t key_size, size_t value_size);
void map_delete(struct map *map);

int map_insert_entry(struct map *map, const void *key, const void *data);
int map_delete_entry(struct map *map, const void *key);

int map_find_entry(struct map *map, const void *key);
int map_lookup_entry(struct map *map, const void *key, void *data);

int map_first_entry(struct map *map, void *key, void *value);
int map_next_entry(struct map *map, void *key, void *value);
int map_prev_entry(struct map *map, void *key, void *value);


#define map_for_each_entry(map, key, value, block)      \
    do {                                                \
        int err = map_first_entry(map, key, value);     \
        while (!err) {                                  \
            block;                                      \
            err = map_next_entry(map, key, value);      \
        }                                               \
    } while (0);


#endif
