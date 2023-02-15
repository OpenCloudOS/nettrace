#include <sys/sysinfo.h>
#include <parse_sym.h>

#include "trace.h"
#include "progs/kprobe.skel.h"
#include "analysis.h"
#include "nettrace.h"
#include "analysis.h"

#define MAX_CPU_COUNT 1024

const char *kprobe_type = "/sys/bus/event_source/devices/kprobe/type";

struct list_head cpus[MAX_CPU_COUNT];
trace_ops_t probe_ops;
static struct kprobe *skel;

#define probe_program(obj, name)	\
	bpf_object__find_program_by_name(obj, name)

static void probe_trace_attach_manual(char *prog_name, char *func,
				      bool retprobe)
{
	struct bpf_program *prog;
	bool legacy;
	int err;

	prog = probe_program(skel->obj, prog_name);
	if (!prog) {
		pr_err("failed to find prog %s\n", prog_name);
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
		pr_warn("retring to attach in legacy mode, prog=%s, func=%s\n",
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
	char kret_name[128];
	trace_t *trace;
	int err;

	trace_for_each(trace) {
		if (!(trace->status & TRACE_ATTACH_MANUAL))
			continue;

		probe_trace_attach_manual(trace->prog, trace->name, false);
		if (!trace_is_ret(trace))
			continue;

		sprintf(kret_name, "ret%s", trace->prog);
		probe_trace_attach_manual(kret_name, trace->name, true);
	}
	return kprobe__attach(skel);
}

static int probe_trace_pre_load()
{
	char kret_name[128], regex[128], *func;
	struct bpf_program *prog;
	bool manual, autoload;
	trace_t *trace;

	/* disable all programs that is not enabled or invalid */
	trace_for_each(trace) {
		autoload = !trace_is_invalid(trace) &&
			   trace_is_enable(trace);

		if (autoload)
			goto check_ret;

		prog = probe_program(skel->obj, trace->prog);
		if (!prog) {
			pr_err("prog: %s not founded\n", trace->prog);
			continue;
		}
		bpf_program__set_autoload(prog, false);
		pr_debug("prog: %s is made no-autoload\n", trace->prog);

check_ret:
		if (!trace_is_func(trace) || (trace_is_ret(trace) &&
		    autoload))
			continue;

		sprintf(kret_name, "ret%s", trace->prog);
		prog = probe_program(skel->obj, kret_name);
		if (!prog) {
			pr_err("prog: %s not founded\n", kret_name);
			continue;
		}
		bpf_program__set_autoload(prog, false);
		pr_debug("prog: %s is made no-autoload\n", trace->prog);
	}

	return 0;
}

static int probe_trace_load()
{
	int i = 0;

	skel = kprobe__open();
	if (!skel) {
		pr_err("failed to open kprobe-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is opened successfully\n");

	/* set the max entries of perf event map to current cpu count */
	bpf_map__set_max_entries(skel->maps.m_event, get_nprocs_conf());

	if (probe_trace_pre_load() || kprobe__load(skel)) {
		pr_err("failed to load kprobe-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");

	bpf_set_config(skel, bss, trace_ctx.bpf_args);
	trace_ctx.obj = skel->obj;

	for (; i < ARRAY_SIZE(cpus); i++)
		INIT_LIST_HEAD(&cpus[i]);

	switch (trace_ctx.mode) {
	case TRACE_MODE_BASIC:
	case TRACE_MODE_DROP:
		probe_ops.trace_poll = basic_poll_handler;
		break;
	case TRACE_MODE_INETL:
	case TRACE_MODE_TIMELINE:
		probe_ops.trace_poll = tl_poll_handler;
		break;
	}

	return 0;
err:
	return -1;
}

void probe_trace_close()
{
	if (skel)
		kprobe__destroy(skel);
}

static analyzer_result_t probe_analy_exit(trace_t *trace, analy_exit_t *e)
{
	analy_entry_t *pos;
	int cpu = e->cpu;

	if (cpu > MAX_CPU_COUNT) {
		pr_err("cpu count is too big\n");
		goto out;
	}

	if (list_empty(&cpus[cpu])) {
		pr_debug("no entry found for exit: %s on cpu %d (list empty)\n",
			 trace->name, cpu);
		goto out;
	}

	list_for_each_entry(pos, &cpus[cpu], cpu_list) {
		if (pos->event->func == e->event.func)
			goto found;
	}
	pr_debug("no entry found for exit: %s on cpu %d; func: %d, "
		 "last_func: %d\n", trace->name, cpu, e->event.func,
		 pos->event->func);
	goto out;
found:
	pos->status |= ANALY_ENTRY_RETURNED;
	pos->priv = e->event.val;
	list_del(&pos->cpu_list);
	put_fake_analy_ctx(pos->fake_ctx);
	e->entry = pos;
	pos->status &= ~ANALY_ENTRY_ONCPU;
	pr_debug("found exit for entry: %s(%llx) on cpu %d with return "
		 "value %llx, ctx:%llx:%d\n", trace->name, pos->event->key, cpu,
		 e->event.val, PTR2X(pos->ctx), pos->ctx->refs);
out:
	return RESULT_CONT;
}

static analyzer_result_t probe_analy_entry(trace_t *trace, analy_entry_t *e)
{
	struct list_head *list;

	if (!trace_is_ret(trace)) {
		pr_debug("tp found for %s(%llx), ctx:%llx:%d\n", trace->name,
			 (u64)e->event->key, PTR2X(e->ctx),
			 e->ctx->refs);
		goto out;
	}
	list = &cpus[e->cpu];
	list_add(&e->cpu_list, list);
	get_fake_analy_ctx(e->fake_ctx);
	pr_debug("mounted entry %s(%llx) on cpu %d, ctx:%llx:%d\n", trace->name,
		 (u64)e->event->key, e->cpu, PTR2X(e->ctx),
		 e->ctx->refs);
	e->status |= ANALY_ENTRY_ONCPU;

out:
	return RESULT_CONT;
}

static void probe_trace_ready()
{
	bpf_set_config_field(skel, bss, ready, true);
}

static void probe_print_stack(int key)
{
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

analyzer_t probe_analyzer =  {
	.mode = TRACE_MODE_INETL_MASK | TRACE_MODE_TIMELINE_MASK,
	.analy_entry = probe_analy_entry,
	.analy_exit = probe_analy_exit,
};

trace_ops_t probe_ops = {
	.trace_attach = probe_trace_attach,
	.trace_load = probe_trace_load,
	.trace_close = probe_trace_close,
	.trace_ready = probe_trace_ready,
	.print_stack = probe_print_stack,
	.analyzer = &probe_analyzer,
};
