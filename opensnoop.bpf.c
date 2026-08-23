#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	char command[16];
	bpf_get_current_comm(&command, sizeof(command));
	if (__builtin_memcmp(command, "nvim", 5) != 0) {
		return 0;
	}

	char filename[256];
	const char *filename_ptr = (const char *)(void *)ctx->args[1];
	bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);

	bpf_printk("Nvim just opened %s\n", filename);
	return 0;
}
