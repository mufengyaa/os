#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define path_size 256

struct event {
	int pid_;
	char path_name_[path_size];
	int n_;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps"); // 环形缓冲区


SEC("tracepoint/syscalls/sys_enter_openat")
int do_syscall_trace(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	char filename[path_size];
	struct task_struct *task = (struct task_struct *)bpf_get_current_task(),
			   *real_parent;
	if (task == NULL) {
		bpf_printk("task\n");
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	int pid = bpf_get_current_pid_tgid() >> 32, tgid;

	bpf_probe_read_str(e->path_name_, sizeof(e->path_name_),
			   (void *)(ctx->args[1]));

	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (fdt == NULL) {
		bpf_printk("fdt\n");
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	unsigned int i = 0, count = 0, n = BPF_CORE_READ(fdt, max_fds);

	e->n_ = n;
	e->pid_ = pid;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
