#include <sys/sysinfo.h>
#include <parse_sym.h>

#include "trace.h"
#include "analysis.h"
#include "nettrace.h"
#include "analysis.h"

static bool tracing_trace_supported()
{
	/* for now, monitor mode only */
	if (trace_ctx.mode != TRACE_MODE_MONITOR)
		return false;

#ifdef COMPAT_MODE
	pr_err("--monitor is not supported in compat mode!\n");
	return false;
#endif
	return true;
}

#ifndef COMPAT_MODE

#include "progs/tracing.skel.h"
#include "progs/feat_args_ext.skel.h"

#define MAX_CPU_COUNT 1024

trace_ops_t tracing_ops;

static struct tracing *skel;

static bool tracing_support_feat_args_ext()
{
	struct feat_args_ext *tmp;
	int err;

	tmp = feat_args_ext__open_and_load();
	if (tmp == NULL)
		return false;
	err = feat_args_ext__attach(tmp);
	feat_args_ext__destroy(tmp);
	return err == 0;
}

static void tracing_trace_attach_manual(char *prog_name, char *func)
{
	struct bpf_program *prog;

	prog = bpf_pbn(skel->obj, prog_name);
	if (!prog) {
		pr_verb("failed to find prog %s\n", prog_name);
		return;
	}
	bpf_program__set_attach_target(prog, 0, func);
}

static int tracing_trace_attach()
{
	char kret_name[128];
	trace_t *trace;
	int err;

	trace_for_each(trace) {
		if (!(trace->status & TRACE_ATTACH_MANUAL))
			continue;

		tracing_trace_attach_manual(trace->prog, trace->name);
		if (!trace_is_ret(trace))
			continue;

		sprintf(kret_name, "ret%s", trace->prog);
		tracing_trace_attach_manual(kret_name, trace->name);
	}
	return tracing__attach(skel);
}

static void tracing_load_rules()
{
	rule_t *local_rule;
	rules_ret_t *rule;
	trace_t *trace;
	int i;

	trace_for_each(trace) {
		if (trace_is_invalid(trace) || !trace_is_enable(trace) ||
		    !trace_is_ret(trace) || !trace_is_func(trace))
			continue;

		rule = &skel->bss->rules_all[trace->index];
		i = 0;
		list_for_each_entry(local_rule, &trace->rules, list) {
			if (local_rule->level == RULE_INFO)
				continue;
			rule->expected[i] = local_rule->expected;
			rule->op[i] = local_rule->type;
			i++;
		}
	}
}

static void tracing_check_args()
{
	bool support_feat_args_ext, support_btf_modules;
	trace_t *trace;

	support_feat_args_ext = tracing_support_feat_args_ext();
	if (!support_feat_args_ext)
		pr_warn("tracing kernel function with 6+ arguments is not"
			"supportd by your kernel, following functions "
			"are skipped:\n");

	trace_for_each(trace) {
		if (trace_is_invalid(trace) || !trace_is_enable(trace) ||
		    !trace_is_func(trace))
			continue;

		if (!support_feat_args_ext && trace->arg_count > 6) {
			pr_warn("\t%s\n", trace->name);
			trace_set_invalid(trace);
		}
	}

	support_btf_modules = kernel_has_config("DEBUG_INFO_BTF_MODULES");
	if (!support_btf_modules)
		pr_warn("CONFIG_DEBUG_INFO_BTF_MODULES is not supported "
			"by your kernel, following functions are "
			"skipped:\n");

	trace_for_each(trace) {
		if (trace_is_invalid(trace) || !trace_is_enable(trace) ||
		    !trace_is_func(trace))
			continue;

		if (!support_btf_modules && !btf_get_type(trace->name)) {
			pr_warn("\t%s\n", trace->name);
			trace_set_invalid(trace);
		}
	}
}

static int tracing_trace_load()
{
	int i = 0;

	skel = tracing__open();
	if (!skel) {
		pr_err("failed to open tracing-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is opened successfully\n");

	/* set the max entries of perf event map to current cpu count */
	bpf_map__set_max_entries(skel->maps.m_event, get_nprocs_conf());

	trace_ctx.obj = skel->obj;
	tracing_load_rules();
	tracing_check_args();

	if (trace_pre_load() || tracing__load(skel)) {
		pr_err("failed to load tracing-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");

	bpf_set_config(skel, bss, trace_ctx.bpf_args);
	switch (trace_ctx.mode) {
	case TRACE_MODE_MONITOR:
		tracing_ops.trace_poll = basic_poll_handler;
		break;
	default:
		goto err;
	}

	return 0;
err:
	return -1;
}

void tracing_trace_close()
{
	if (skel)
		tracing__destroy(skel);
	skel = NULL;
}

static analyzer_result_t
tracing_analy_exit(trace_t *trace, analy_exit_t *e)
{
	return RESULT_CONT;
}

static analyzer_result_t
tracing_analy_entry(trace_t *trace, analy_entry_t *e)
{
	return RESULT_CONT;
}

static void tracing_trace_ready()
{
	bpf_set_config_field(skel, bss, ready, true);
}

static void tracing_print_stack(int key)
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
		pr_info("    -> [%lx]%s\n", ip[i], sym->desc);
	}
	pr_info("\n");
}

analyzer_t tracing_analyzer = {
	.mode = TRACE_MODE_DIAG_MASK | TRACE_MODE_TIMELINE_MASK,
	.analy_entry = tracing_analy_entry,
	.analy_exit = tracing_analy_exit,
};

trace_ops_t tracing_ops = {
	.trace_attach = tracing_trace_attach,
	.trace_load = tracing_trace_load,
	.trace_close = tracing_trace_close,
	.trace_ready = tracing_trace_ready,
	.trace_supported = tracing_trace_supported,
	.print_stack = tracing_print_stack,
	.analyzer = &tracing_analyzer,
};

#else
trace_ops_t tracing_ops = {
	.trace_supported = tracing_trace_supported,
};
#endif
