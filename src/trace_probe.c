#include <sys/sysinfo.h>
#include <parse_sym.h>

#include "trace.h"
#include "progs/kprobe.skel.h"
#include "analysis.h"

#define MAX_CPU_COUNT 1024

const char *kprobe_type = "/sys/bus/event_source/devices/kprobe/type";

struct list_head cpus[MAX_CPU_COUNT];
trace_ops_t probe_ops;
static struct kprobe *skel;

static void probe_trace_attach_manual(char *prog_name, char *func,
				      bool retprobe)
{
	struct bpf_program *prog;
	bool legacy;
	int err;

	prog = bpf_pbn(skel->obj, prog_name);
	if (!prog) {
		pr_verb("failed to find prog %s\n", prog_name);
		return;
	}

	bpf_program__set_autoattach(prog, false);
	legacy = !file_exist(kprobe_type);

again:
	if (!legacy)
		err = libbpf_get_error(bpf_program__attach_kprobe(prog,
				       retprobe, func));
	else
		err = compat_bpf_attach_kprobe(bpf_program__fd(prog),
					       func, retprobe);

	if (err && !legacy) {
		pr_verb("retring to attach in legacy mode, prog=%s, func=%s\n",
			prog_name, func);
		legacy = true;
		goto again;
	}

	if (err) {
		pr_err("failed to manually attach program prog=%s, func=%s\n",
		       prog_name, func);
		return;
	}

	pr_verb("manually attach prog %s success\n", prog_name);
}

static int probe_trace_attach()
{
	bool auto_attach = false;
	char kret_name[128];
	trace_t *trace;

again:
	trace_for_each(trace) {
		if ((auto_attach && !(trace->status & TRACE_ATTACH_MANUAL)) ||
		    (!auto_attach && (trace->status & TRACE_ATTACH_MANUAL))) {
			probe_trace_attach_manual(trace->prog, trace->name, false);
			if (!trace_is_ret(trace))
				continue;

			sprintf(kret_name, "ret%s", trace->prog);
			probe_trace_attach_manual(kret_name, trace->name, true);
		}
	}

	if (!auto_attach && kprobe__attach(skel)) {
		/* failed to auto attach, attach manually */
		auto_attach = true;
		pr_warn("failed to auto attach kprobe, trying manual attach...\n");
		goto again;
	}

	return 0;
}

/* In kprobe, we only enable the monitor for the traces with "any" rule */
static void probe_check_monitor()
{
	trace_t *trace;

	if (trace_ctx.mode != TRACE_MODE_MONITOR)
		return;

	trace_for_each(trace) {
		if (!trace_is_func(trace) || trace_is_invalid(trace))
			continue;

		/* kprobe don't support to monitor function exit */
		if (trace->monitor == TRACE_MONITOR_EXIT) {
			pr_debug("disabled monitor_exit for kprobe\n");
			trace_set_invalid_reason(trace, "monitor");
		}
	}
}

static int probe_trace_load()
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = trace_ctx.args.btf_path,
	);
	int i = 0;

	skel = kprobe__open_opts(&opts);
	if (!skel) {
		pr_err("failed to open kprobe-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is opened successfully\n");

	/* set the max entries of perf event map to current cpu count */
	bpf_map__set_max_entries(skel->maps.m_event, get_nprocs_conf());
	bpf_func_init(skel, BPF_PROG_TYPE_KPROBE);

	trace_ctx.obj = skel->obj;
	if (trace_pre_load() || kprobe__load(skel)) {
		pr_err("failed to load kprobe-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");

	bpf_set_config(skel, bss, trace_ctx.bpf_args);

	for (; i < ARRAY_SIZE(cpus); i++)
		INIT_LIST_HEAD(&cpus[i]);

	return 0;
err:
	return -1;
}

static bool is_trace_supported(trace_t *trace)
{
	struct kprobe *tmp = kprobe__open();
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_program(prog, tmp->obj) {
		if (strcmp(trace->prog, bpf_program__name(prog)) != 0)
			bpf_program__set_autoload(prog, false);
	}
	err = kprobe__load(tmp);
	kprobe__destroy(tmp);

	if (err)
		pr_verb("kernel feature probe failed for trace: %s\n",
			trace->prog);
	else
		pr_debug("kernel feature probe success for trace: %s\n",
			 trace->prog);

	return err == 0;
}

static void probe_trace_feat_probe()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (!trace->probe || !trace_is_usable(trace))
			continue;
		if (!is_trace_supported(trace))
			trace_set_invalid(trace);
	}
}

void probe_trace_close()
{
	if (skel)
		kprobe__destroy(skel);
	skel = NULL;
}

static struct list_head *entry_head(u32 key)
{
	/* simple hash function to avoid collision */
	return &cpus[key % MAX_CPU_COUNT];
}

static analyzer_result_t probe_analy_exit(trace_t *trace, analy_exit_t *e)
{
	struct list_head *head;
	u32 key = e->event.pid;
	analy_entry_t *pos;

	head = entry_head(key);
	if (list_empty(head)) {
		pr_debug("no entry found for exit: %s pid=%d (list empty)\n",
			 trace->name, key);
		goto out;
	}

	/* the entry is added to the head, so the lastest added entry will be
	 * matched first.
	 */
	list_for_each_entry(pos, head, ret_list) {
		if (pos->event->func == e->event.func &&
		    pos->event->pid == key)
			goto found;
	}
	pr_debug("no entry found for exit: %s pid: %d; func: %d, "
		 "last_func: %d\n", trace->name, key,
		 e->event.func, pos->event->func);
	goto out;
found:
	pos->status |= ANALY_ENTRY_RETURNED;
	pos->priv = e->event.val;
	list_del(&pos->ret_list);
	put_fake_analy_ctx(pos->fake_ctx);
	e->entry = pos;
	pos->status &= ~ANALY_ENTRY_ONLIST;
	pr_debug("found exit for entry: %s(%x) pid=%d with return "
		 "value %llx, ctx:%llx:%u\n", trace->name, pos->event->key,
		 key, e->event.val, PTR2X(pos->ctx),
		 pos->ctx->refs);
out:
	return RESULT_CONT;
}

static analyzer_result_t probe_analy_entry(trace_t *trace, analy_entry_t *e)
{
	struct list_head *head;

	if (!trace_is_ret(trace)) {
		pr_debug("entry found for %s(%llx), ctx:%llx:%d\n", trace->name,
			 (u64)e->event->key, PTR2X(e->ctx),
			 e->ctx->refs);
		goto out;
	}
	head = entry_head(e->event->pid);
	list_add(&e->ret_list, head);
	get_fake_analy_ctx(e->fake_ctx);
	pr_debug("mounted entry %s(%llx) pid %d, ctx:%llx:%d\n", trace->name,
		 (u64)e->event->key, e->event->pid, PTR2X(e->ctx),
		 e->ctx->refs);
	e->status |= ANALY_ENTRY_ONLIST;

out:
	return RESULT_CONT;
}

static void probe_trace_ready()
{
	bpf_set_config_field(skel, bss, bpf_args_t, ready, true);
}

#ifdef __F_STACK_TRACE
static void probe_print_stack(int key)
{
	if (key <= 0)
	{
		pr_info("Call Stack Error! Invalid stack id:%d.\n", key);
		return;
	}

	int map_fd = bpf_map__fd(skel->maps.m_stack);
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};
	struct sym_result *sym;
	int i = 0;

	if (bpf_map_lookup_elem(map_fd, &key, ip)) {
		pr_info("Call Stack Error!\n");
		return;
	}

	pr_info("Call Stack:\n");
	for (; i < PERF_MAX_STACK_DEPTH && ip[i]; i++) {
		sym = sym_parse(ip[i]);
		if (!sym)
			break;
		pr_info("    -> %s\n", sym->desc);
	}
	pr_info("\n");
}
#else
static void probe_print_stack(int key) { }
#endif

static bool probe_trace_supported()
{
	return true;
}

analyzer_t probe_analyzer = {
	.mode = TRACE_MODE_CTX_MASK | TRACE_MODE_TINY_MASK,
	.analy_entry = probe_analy_entry,
	.analy_exit = probe_analy_exit,
};

trace_ops_t probe_ops = {
	.trace_attach = probe_trace_attach,
	.trace_load = probe_trace_load,
	.trace_close = probe_trace_close,
	.trace_ready = probe_trace_ready,
	.trace_feat_probe = probe_trace_feat_probe,
	.trace_supported = probe_trace_supported,
	.print_stack = probe_print_stack,
	.prepare_traces = probe_check_monitor,
	.analyzer = &probe_analyzer,
};
