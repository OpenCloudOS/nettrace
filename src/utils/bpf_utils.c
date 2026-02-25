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
#include <string.h>
#include <dirent.h>

#include "sys_utils.h"
#include <bpf/btf.h>

#include "bpf_utils.h"

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

	sprintf(buf, "/sys/kernel/tracing/events/kprobes/%s/id",
		target);

	if (file_exist(buf))
		goto exist;

	sprintf(buf, "(echo '%c:%s %s' >> /sys/kernel/tracing/kprobe_events) 2>&1",
		ret ? 'r' : 'p', target, name);
	if (simple_exec(buf)) {
		pr_warn("failed to create kprobe: %s\n", target);
		return -1;
	}
	sprintf(buf, "/sys/kernel/tracing/events/kprobes/%s/id",
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
struct btf_module_cache {
	char module[256];
	struct btf *btf;
	struct btf_module_cache *next;
};

static struct btf_module_cache *module_btf_cache;
static bool module_btf_loaded;

static int btf_prepare()
{
	if (!local_btf) {
		local_btf = btf__load_vmlinux_btf();
		if (libbpf_get_error(local_btf)) {
			local_btf = NULL;
			return -ENOENT;
		}
	}

	return 0;
}

static void btf_release_module_cache()
{
	struct btf_module_cache *cache;
	struct btf_module_cache *tmp;

	cache = module_btf_cache;
	while (cache) {
		tmp = cache->next;
		if (cache->btf)
			btf__free(cache->btf);
		free(cache);
		cache = tmp;
	}

	module_btf_cache = NULL;
	module_btf_loaded = false;
}

void btf_release_cache(void)
{
	btf_release_module_cache();
	if (local_btf) {
		btf__free(local_btf);
		local_btf = NULL;
	}
}

static int btf_load_all_module_btf()
{
	struct btf_module_cache *cache;
	struct dirent *ent;
	struct btf *btf;
	DIR *dir;
	int loaded = 0;

	if (module_btf_loaded)
		return 0;

	dir = opendir("/sys/kernel/btf");
	if (!dir)
		return -ENOENT;

	while ((ent = readdir(dir))) {
		if (ent->d_name[0] == '.' ||
		    strcmp(ent->d_name, "vmlinux") == 0)
			continue;

		cache = calloc(1, sizeof(*cache));
		if (!cache)
			continue;

		snprintf(cache->module, sizeof(cache->module), "%s", ent->d_name);
		btf = btf__load_module_btf(ent->d_name, local_btf);
		if (libbpf_get_error(btf))
			btf = NULL;
		if (btf)
			loaded++;

		cache->btf = btf;
		cache->next = module_btf_cache;
		module_btf_cache = cache;
	}

	closedir(dir);
	module_btf_loaded = true;
	return loaded ? 0 : -ENOENT;
}

static const struct btf_type *btf_find_func_type(struct btf *btf, const char *name)
{
	const struct btf_type *t;
	int id;

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (id < 0)
		return NULL;

	t = btf__type_by_id(btf, id);
	return t;
}

const struct btf_type *btf_get_type_ext(char *name, struct btf **type_btf)
{
	struct btf_module_cache *cache;
	const struct btf_type *t;

	if (type_btf)
		*type_btf = NULL;

	if (btf_prepare())
		return NULL;

	t = btf_find_func_type(local_btf, name);
	if (t) {
		if (type_btf)
			*type_btf = local_btf;
		return t;
	}

	btf_load_all_module_btf();
	for (cache = module_btf_cache; cache; cache = cache->next) {
		if (!cache->btf)
			continue;

		t = btf_find_func_type(cache->btf, name);
		if (!t)
			continue;

		if (type_btf)
			*type_btf = cache->btf;
		return t;
	}

	return NULL;
}

const struct btf_type *btf_get_type(char *name)
{
	return btf_get_type_ext(name, NULL);
}

int btf_get_arg_count(char *name)
{
	const struct btf_type *t;
	struct btf *type_btf;

	t = btf_get_type_ext(name, &type_btf);
	if (!t)
		return -ENOENT;

	t = btf__type_by_id(type_btf, t->type);
	if (!t || !btf_is_func_proto(t))
		return -ENOENT;

	return btf_vlen(t);
}

static bool btf_param_type_match(struct btf *btf, __u32 type_id,
				 const char *struct_name)
{
	const struct btf_type *t;
	const char *name;
	int id;

	if (!type_id || !struct_name || !struct_name[0])
		return false;

	id = btf__resolve_type(btf, type_id);
	if (id < 0)
		return false;

	t = btf__type_by_id(btf, id);
	if (!t)
		return false;

	if (btf_is_ptr(t)) {
		id = btf__resolve_type(btf, t->type);
		if (id < 0)
			return false;

		t = btf__type_by_id(btf, id);
		if (!t)
			return false;
	}

	if (!btf_is_struct(t) && !btf_is_fwd(t))
		return false;

	name = btf__name_by_offset(btf, t->name_off);
	if (!name || !name[0])
		return false;

	return strcmp(name, struct_name) == 0;
}

int btf_get_trace_param_index(char *name, const char *struct_name)
{
	const struct btf_type *func_type, *func_proto;
	const struct btf_param *params;
	struct btf *type_btf;
	int i, nr;

	if (!struct_name || !struct_name[0])
		return -EINVAL;

	func_type = btf_get_type_ext(name, &type_btf);
	if (!func_type)
		return -ENOENT;

	func_proto = btf__type_by_id(type_btf, func_type->type);
	if (!func_proto || !btf_is_func_proto(func_proto))
		return -ENOENT;

	nr = btf_vlen(func_proto);
	params = btf_params(func_proto);
	for (i = 0; i < nr; i++) {
		if (btf_param_type_match(type_btf, params[i].type, struct_name))
			return i;
	}

	return -ENOENT; /* not found */
}
