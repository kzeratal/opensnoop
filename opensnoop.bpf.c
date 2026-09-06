#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, char[16]);
	__type(value, __u8);
} included_executables SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	char command[16];
	if (bpf_get_current_comm(&command, sizeof(command)) != 0) {
		return 0;
	}

	if (!bpf_map_lookup_elem(&included_executables, command)) {
		return 0;
	}

	const char *filename_ptr = (const char *)ctx->args[1];
	char filename[256];
	if (bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr) < 0) {
		return 0;
	}

	bpf_printk("%s attempts to open %s\n", command, filename);
	return 0;
}
