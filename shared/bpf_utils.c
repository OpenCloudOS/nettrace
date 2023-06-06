#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <sys_utils.h>
#include <bpf/btf.h>

#include "bpf_utils.h"

int
perf_output_cond(int fd, perf_buffer_sample_fn callback,
		 perf_buffer_lost_fn lost_cb,
		 bool *stop)
{
#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
	struct perf_buffer *pb;
	int err;

	pb = perf_buffer__new(fd, 1024, callback, lost_cb, NULL, NULL);
#else
	struct perf_buffer_opts pb_opts = {
		.sample_cb = callback,
		.lost_cb = lost_cb,
	};
	struct perf_buffer *pb;
	int err;

	pb = perf_buffer__new(fd, 1024, &pb_opts);
#endif

	err = libbpf_get_error(pb);
	if (err) {
		printf("failed to setup perf_buffer: %d\n", err);
		return err;
	}

	while ((err = perf_buffer__poll(pb, 1000)) >= 0)
		if (stop && *stop)
			break;
	return 0;
}

int compat_bpf_attach_kprobe(int fd, char *name, bool ret)
{
	struct perf_event_attr attr = {};
	char buf[1024], target[128];
	int id, err, i = 0;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	sprintf(target, "%s%s", ret ? "ret_" : "", name);

	/* replace '.' with '_' in the event name, as it don't support
	 * '.' in the kprobe event name.
	 */
	while (target[i] != '\0') {
		if (target[i] == '.')
			target[i] = '_';
		i++;
	}

	sprintf(buf, "/sys/kernel/debug/tracing/events/kprobes/%s/id",
		target);

	if (file_exist(buf))
		goto exist;

	sprintf(buf, "(echo '%c:%s %s' >> /sys/kernel/debug/tracing/kprobe_events) 2>&1",
		ret ? 'r' : 'p', target, name);
	if (simple_exec(buf)) {
		pr_warn("failed to create kprobe: %s\n", target);
		return -1;
	}
	sprintf(buf, "/sys/kernel/debug/tracing/events/kprobes/%s/id",
		target);
exist:;
	int efd = open(buf, O_RDONLY, 0);
	if (efd < 0) {
		pr_warn("failed to open event %s\n", name);
		return -1;
	}
	
	err = read(efd, buf, sizeof(buf));
	if (err < 0 || err >= sizeof(buf)) {
		pr_warn("read from '%s' failed '%s'\n", target, strerror(errno));
		return -1;
	}

	close(efd);

	buf[err] = 0;
	id = atoi(buf);
	attr.config = id;

	efd = syscall(SYS_perf_event_open, &attr, -1, 0, -1, 0);
	if (efd < 0) {
		pr_warn("event %d fd %d err %s\n", id, efd, strerror(errno));
		return -1;
	}
	ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);

	return 0;
}

static struct btf *local_btf;
const struct btf_type *btf_get_type(char *name)
{
	const struct btf_type *t;
	int id;

	if (!local_btf)
		local_btf= btf__load_vmlinux_btf();

	id = btf__find_by_name(local_btf, name);
	if (id < 0)
		return NULL;

	t = btf__type_by_id(local_btf, id);
	return t;
}

int btf_get_arg_count(char *name)
{
	const struct btf_type *t;

	t = btf_get_type(name);
	if (!t)
		return -ENOENT;

	t = btf__type_by_id(local_btf, t->type);
	if (!t)
		return -ENOENT;

	return btf_vlen(t);
}
