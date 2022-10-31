#include "trace.h"
#include "progs/kprobe.skel.h"
#ifndef COMPAT_MODE
#include "progs/kprobe_core.skel.h"
#endif
#include "analysis.h"
#include "nettrace.h"
#include "analysis.h"

#define MAX_CPU_COUNT 1024

struct list_head cpus[MAX_CPU_COUNT];
trace_ops_t probe_ops;

static int bpf_kprobe_attach(struct bpf_program *prog, char *name, bool ret)
{
	if (file_exist("/sys/bus/event_source/devices/kprobe/type"))
		return libbpf_get_error(bpf_program__attach_kprobe(prog,
				ret, name));
	return compat_bpf_attach_kprobe(bpf_program__fd(prog), name, ret);
}

static int probe_trace_load(trace_t *trace)
{
	char tmp[128], *regex, _regex[128],
	     *target = trace->name;
	struct bpf_program *prog;
	int err;

	prog = bpf_object__find_program_by_name(trace_ctx.obj, trace->prog);
	if (!prog) {
		pr_err("eBPF program %s not found\n", trace->prog);
		goto err;
	}

	switch (trace->type) {
	case TRACE_TP:
		pr_debug("attaching %s\n", trace->prog);
		err = libbpf_get_error(bpf_program__attach(prog));
		if (err) {
			pr_err("failed to attach %s\n", trace->prog);
			goto err;
		}
		return 0;
	case TRACE_FUNCTION:
		break;
	default:
		return -EINVAL;
	}

kprobe:
	regex = trace->regex;
retry:
	if (regex) {
		if (execf(tmp, "awk 'BEGIN{ORS=\"\"}$3~/%s/{print $3;exit 1}' "
			  "/proc/kallsyms", regex) != 1) {
			pr_warn("kernel function not found: %s\n", regex);
			goto on_fail;
		}
		target = tmp;
	}

	pr_debug("attaching %s to %s\n", trace->prog, target);
	err = bpf_kprobe_attach(prog, target, false);
	if (err && !regex) {
		sprintf(_regex, "^%s\\.", trace->name);
		regex = _regex;
		goto retry;
	}
	if (err) {
on_fail:
		pr_warn("failed to attach target: %s\n", target);
		return 0;
	}

	pr_verb("attach %s success\n", trace->name);
	if (trace_is_ret(trace)) {
		char kret_name[128];

		sprintf(kret_name, "ret%s", trace->prog);
		prog = bpf_object__find_program_by_name(trace_ctx.obj, kret_name);
		if (!prog) {
			pr_warn("failed to find kretprobe program: %s\n",
				kret_name);
			return 0;
		}
		err = bpf_kprobe_attach(prog, target, true);
		if (err)
			pr_warn("failed to attach kretprobe program: %s\n",
				tmp);
		else
			pr_verb("attach kretprobe %s to %s success\n",
				kret_name, target);
	}
	return 0;
err:
	return -1;
}

#define LOAD_SKEL(name)					\
	skel = (void *) name##__open();			\
	if (skel && !name##__load((void *)skel))	\
		goto load_success;			\
	pr_warn("failed to load skel: " #name "\n")

static struct kprobe *skel;
static int probe_trace_open()
{
	int i = 0;

#ifndef COMPAT_MODE
	LOAD_SKEL(kprobe_core);
#endif
	LOAD_SKEL(kprobe);

	pr_err("failed to load kprobe-based eBPF\n");
	goto err;

load_success:
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

analyzer_t probe_analyzer =  {
	.mode = TRACE_MODE_INETL_MASK | TRACE_MODE_TIMELINE_MASK,
	.analy_entry = probe_analy_entry,
	.analy_exit = probe_analy_exit,
};

trace_ops_t probe_ops = {
	.trace_load = probe_trace_load,
	.trace_open = probe_trace_open,
	.trace_close = probe_trace_close,
	.trace_ready = probe_trace_ready,
	.analyzer = &probe_analyzer,
};
