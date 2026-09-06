#ifndef OPENSNOOP_CONFIG_H
#define OPENSNOOP_CONFIG_H

#include <stddef.h>

#define EXECUTABLE_NAME_LENGTH 16
#define MAXIMUM_INCLUDE_ENTRIES 256

struct executable_name {
    char value[EXECUTABLE_NAME_LENGTH];
};

struct opensnoop_config {
    struct executable_name *includes;
    size_t include_counts;
    size_t include_capacity;
};

int config_load(const char *path, struct opensnoop_config *config);
void config_destroy(struct opensnoop_config *config);

#endif
