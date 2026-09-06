#include "config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ini.h>

static bool executable_exists(const struct opensnoop_config *config, const char *value) {
	for (size_t i = 0; i < config->include_count; i++) {
		if (strcmp(config->includes[i].value, value) == 0) {
			return true;
		}
	}

	return false;
}

static int extend_include_capacity(struct opensnoop_config *config) {
	if (config->include_count < config->include_capacity) {
		return 0;
	}

	size_t new_capacity = config->include_capacity ? config->include_capacity * 2 : 8;
	if (new_capacity > MAXIMUM_INCLUDE_ENTRIES) {
		fprintf(stderr, "Include entries reached to maximum\n");
		return -1;
	}

	struct executable_name *new_includes = realloc(config->includes, new_capacity * sizeof(*config->includes));
	if (!new_includes) {
		perror("realloc");
		return -1;
	}

	config->includes = new_includes;
	config->include_capacity = new_capacity;

	return 0;
}

static int add_executable(struct opensnoop_config *config, const char *value) {
	size_t length = strlen(value);
	if (length == 0) {
		fprintf(stderr, "Executable name cannot be empty\n");
		return -1;
	}
	if (length > EXECUTABLE_NAME_LENGTH) {
		fprintf(stderr, "Executable name: %s is too long\n", value);
		return -1;
	}

	if (executable_exists(config, value)) {
		return 0;
	}

	if (extend_include_capacity(config) != 0) {
		return -1;
	}

	struct executable_name *entry = &config->includes[config->include_count];
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->value, value, length);
	config->include_count++;

	return 0;
}

static int handle_config_entry(void *context, const char *section, const char *name, const char *value) {
	struct opensnoop_config *config = (struct opensnoop_config *)context;

	if (strcmp("opensnoop", section) != 0) {
		fprintf(stderr, "Unknown section: %s\n", section);
		return -1;
	}

	if (strcmp("include", name) != 0) {
		fprintf(stderr, "Unknown name: %s\n", name);
		return -1;
	}

	return add_executable(config, value) == 0;
}

void config_destroy(struct opensnoop_config *config) {
	if (!config) {
		return;
	}

	free(config->includes);

	config->includes = NULL;
	config->include_count = 0;
	config->include_capacity = 0;
}

int config_load(const char *path, struct opensnoop_config *config) {
	struct opensnoop_config temp_config = {0};

	int ret = ini_parse(path, handle_config_entry, &temp_config);
	if (ret < 0) {
		fprintf(stderr, "Unable to read %s\n", path);
		return -1;
	}

	if (ret > 0) {
		fprintf(stderr, "Invalid config at line %d of %s\n", ret, path);
		config_destroy(&temp_config);
		return -1;
	}

	if (temp_config.include_count == 0) {
		fprintf(stderr, "No executables configured in %s\n", path);
		config_destroy(&temp_config);
		return -1;
	}

	*config = temp_config;
	return 0;
}
