#include "map.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>


struct map_entry {
    struct map_entry *next;
    __u8 data[];
};

struct map {
    struct map_entry *head;
    size_t key_size, value_size;
};


static struct map_entry *map_find_entry(struct map *map, const void *key, struct map_entry **last_entry) {
    struct map_entry *curr = map->head, *last = NULL;

    while (curr) {
        if (!memcmp(curr->data, key, map->key_size))
            goto out;

        last = curr;
        curr = curr->next;
    }

out:
    *last_entry = last;
    return curr;
}


struct map *map_create(size_t key_size, size_t value_size) {
    struct map *map = malloc(sizeof(*map));
    if (!map)
        return NULL;

    map->head = NULL;
    map->key_size = key_size;
    map->value_size = value_size;

    return map;
}

void map_delete(struct map *map) {
    struct map_entry *curr = map->head, *next;

    while (curr) {
        next = curr->next;
        free(curr);

        curr = next;
    }

    free(map);
}


int map_insert_entry(struct map *map, const void *key, const void *value) {
    struct map_entry *entry, *last;

    entry = map_find_entry(map, key, &last);
    if (entry)
        return -EEXIST;

    entry = malloc(sizeof(*entry) + map->key_size + map->value_size);
    if (!entry)
        return -ENOMEM;

    memcpy(entry->data, key, map->key_size);
    memcpy(entry->data + map->key_size, value, map->value_size);

    entry->next = NULL;

    if (last)
        last->next = entry;

    if (!map->head)
        map->head = entry;

    return 0;
}

int map_delete_entry(struct map *map, const void *key) {
    struct map_entry *entry, *last;

    entry = map_find_entry(map, key, &last);
    if (!entry)
        return -ENOENT;

    if (last)
        last->next = entry->next;

    if (entry == map->head)
        map->head = entry->next;

    free(entry);
    return 0;
}


int map_lookup_entry(struct map *map, const void *key, void *value) {
    struct map_entry *entry, *last;

    entry = map_find_entry(map, key, &last);
    if (!entry)
        return -ENOENT;

    memcpy(value, entry->data + map->key_size, map->value_size);
    return 0;
}

int map_first_entry(struct map *map, void *key, void *value) {
    struct map_entry *entry = map->head;
    if (!entry)
        return -EOF;

    memcpy(key, entry->data, map->key_size);
    memcpy(value, entry->data + map->key_size, map->value_size);

    return 0;
}

int map_next_entry(struct map *map, void *key, void *value) {
    struct map_entry *entry, *last, *next;

    entry = map_find_entry(map, key, &last);
    if (!entry)
        return -ENOENT;

    next = entry->next;
    if (!next)
        return -EOF;

    memcpy(key, next->data, map->key_size);
    memcpy(value, next->data + map->key_size, map->value_size);

    return 0;
}

int map_prev_entry(struct map *map, void *key, void *value) {
    struct map_entry *entry, *last;

    entry = map_find_entry(map, key, &last);
    if (!entry)
        return -ENOENT;

    if (!last)
        return -EOF;

    memcpy(key, last->data, map->key_size);
    memcpy(value, last->data + map->key_size, map->value_size);

    return 0;
}
