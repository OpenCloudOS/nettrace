#include <sys/sysinfo.h>
#include <parse_sym.h>

#include "trace.h"
#include "analysis.h"
#include "progs/tracing.skel.h"
#include "progs/feat_args_ext.skel.h"

static struct tracing *skel;

/* check whether trampoline is supported by current arch */
static bool tracing_arch_supported()
{
	return simple_exec("cat /proc/kallsyms | "
			   "grep arch_prepare_bpf_trampoline | "
			   "grep T") == 0;
}

static bool tracing_trace_supported()
{
	/* TRACING is not supported, skip this handle */
	if (!libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, NULL))
		goto failed;

	if (!tracing_arch_supported()) {
		pr_warn("trampoline is not supported, skip TRACING\n");
		goto failed;
	}

	return true;
failed:
	pr_verb("TRACING is not supported, trying others\n");
	return false;
}

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

static void tracing_adjust_target()
{
	struct bpf_program *prog;
	trace_t *trace;

	trace_for_each(trace) {
		if (!(trace->status & TRACE_ATTACH_MANUAL))
			continue;

		/* function name contain "." is not supported by BTF */
		if (strchr(trace->name, '.')) {
			prog = bpf_pbn(trace_ctx.obj, trace->prog);
			bpf_program__set_autoload(prog, false);
			prog = bpf_pbn(trace_ctx.obj, trace->ret_prog);
			bpf_program__set_autoload(prog, false);
			trace_set_invalid_reason(trace, "BTF invalid");
		}
	}
}

static int tracing_trace_attach()
{
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
		    !trace_is_ret_any(trace) || !trace_is_func(trace))
			continue;

		rule = &skel->rodata->rules_all[trace->index];
		i = 0;
		list_for_each_entry(local_rule, &trace->rules, list) {
			if (local_rule->level == RULE_INFO)
				continue;
			rule->expected[i] = local_rule->expected;
			rule->op[i] = local_rule->type;
			trace_set_flag(trace->index, FUNC_FLAG_RULE);
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
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = trace_ctx.args.btf_path,
	);

	skel = tracing__open_opts(&opts);
	if (!skel) {
		pr_err("failed to open tracing-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is opened successfully\n");

	tracing_load_rules();
	trace_ctx.obj = skel->obj;
	tracing_check_args();

	skel->rodata->m_config = trace_ctx.bpf_args;
	skel->bss->m_data = trace_ctx.bpf_data;

	if (trace_pre_load()) {
		pr_err("failed to prepare load\n");
		goto err;
	}

	tracing_adjust_target();
	if (tracing__load(skel)) {
		pr_err("failed to load tracing-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");

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

analy_entry_t *
tracing_analy_exit(trace_t *trace, retevent_t *event, fake_analy_ctx_t *fctx)
{
	analy_entry_t *pos = NULL;
	u32 key = event->key;

	/* the entry is added to the head, so the lastest added entry will be
	 * matched first.
	 */
	list_for_each_entry(pos, &fctx->ctx->entries, list) {
		if (pos->event->func == event->func &&
		    pos->event->key == key &&
		    (pos->status & ANALY_ENTRY_TO_RETURN))
			goto found;
	}
	pr_debug_ctx("fctx=%llx func=%s, func-index=%d, no entry found for exit\n",
		     key, fctx->ctx, PTR2X(fctx), trace->name, event->func);
	return NULL;
found:
	/* the entry event here is writable, as we copied it out in this case. */
	pos->event->retval = event->val;
	put_fake_analy_ctx(pos->fake_ctx);
	pos->status &= ~ANALY_ENTRY_TO_RETURN;
	pr_debug_ctx("func=%s, func-index=%d, entry found for exit\n",
		     key, pos->ctx, trace->name, event->func);
	return pos;
}

int tracing_analy_entry(trace_t *trace, analy_entry_t *e)
{
	if (!trace_is_ret(trace)) {
		pr_debug_ctx("func=%s, entry without return\n",
			     e->event->key, e->ctx, trace->name);
		return RESULT_CONT;
	}

	get_fake_analy_ctx(e->fake_ctx);
	e->status |= ANALY_ENTRY_TO_RETURN;
	pr_debug_ctx("func=%s, mount entry\n", e->event->key, e->ctx, trace->name);

	return RESULT_CONT;
}

bpf_data_t *get_bpf_data()
{
	return &skel->bss->m_data;
}

static void tracing_trace_ready()
{
	skel->bss->m_data.ready = true;
}

static void tracing_print_stack(int key)
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
		pr_info("    -> [%llx]%s\n", ip[i], sym->desc);
	}
	pr_info("\n");
}

trace_ops_t tracing_ops = {
	.trace_attach = tracing_trace_attach,
	.trace_load = tracing_trace_load,
	.trace_close = tracing_trace_close,
	.trace_ready = tracing_trace_ready,
	.trace_supported = tracing_trace_supported,
	.print_stack = tracing_print_stack,
};
