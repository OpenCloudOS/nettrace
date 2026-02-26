#include <sys/sysinfo.h>
#include <string.h>
#include <linux/bpf.h>

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

static trace_t *find_trace_by_prog(const char *prog_name)
{
	trace_t *trace;

	if (!prog_name)
		return NULL;

	trace_for_each(trace) {
		if ((trace->prog && !strcmp(prog_name, trace->prog)) ||
		    (trace->ret_prog && !strcmp(prog_name, trace->ret_prog)))
			return trace;
	}

	return NULL;
}

static int fixup_insn(struct bpf_program *prog, trace_t *trace)
{
	const short magic_skb = (short)(BPF_MAGIC_SKB * sizeof(__u64));
	const short magic_sk = (short)(BPF_MAGIC_SK * sizeof(__u64));
	const short skb_off = (short)(trace->skb * sizeof(__u64));
	const short sk_off = (short)(trace->sk * sizeof(__u64));
	struct bpf_insn *insns;
	size_t insn_cnt, i;
	int fixed = 0;

	insns = (struct bpf_insn *)bpf_program__insns(prog);
	insn_cnt = bpf_program__insn_cnt(prog);

	for (i = 0; i < insn_cnt; i++) {
		struct bpf_insn *insn = &insns[i];

		if (BPF_CLASS(insn->code) != BPF_LDX ||
		    BPF_MODE(insn->code) != BPF_MEM ||
		    BPF_SIZE(insn->code) != BPF_DW)
			continue;

		if (insn->off == magic_skb) {
			if (trace->skb >= 0) {
				insn->off = skb_off;
			} else {
				insn->code = BPF_ALU64 | BPF_MOV | BPF_K;
				insn->src_reg = 0;
				insn->off = 0;
				insn->imm = 0;
			}
			fixed++;
			continue;
		}

		if (insn->off == magic_sk) {
			if (trace->sk >= 0) {
				insn->off = sk_off;
			} else {
				insn->code = BPF_ALU64 | BPF_MOV | BPF_K;
				insn->src_reg = 0;
				insn->off = 0;
				insn->imm = 0;
			}
			fixed++;
		}
	}

	return fixed;
}

static void fixup_programs()
{
	struct bpf_program *prog;
	int fixed_total = 0;

	bpf_object__for_each_program(prog, skel->obj) {
		const char *prog_name = bpf_program__name(prog);
		trace_t *trace = find_trace_by_prog(prog_name);
		int fixed;

		if (!trace || trace_is_invalid(trace))
			continue;

		fixed = fixup_insn(prog, trace);
		if (!fixed)
			continue;

		pr_debug("fixed %d instruction(s) in prog=%s, trace=%s (skb=%d sk=%d)\n",
			 fixed, prog_name, trace->name, trace->skb, trace->sk);
		fixed_total += fixed;
	}

	pr_debug("instruction fixup done, total=%d\n", fixed_total);
}

static int tracing_trace_open()
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

	skel->rodata->m_config = trace_ctx.bpf_args;
	skel->bss->m_data = trace_ctx.bpf_data;

	fixup_programs();

	return 0;
err:
	return -1;
}

static int tracing_trace_load()
{
	if (tracing__load(skel)) {
		pr_err("failed to load tracing-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");
	btf_release_cache();

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

static void tracing_prepare_traces()
{
	bool support_feat_args_ext;
	int checked = 0, resolved = 0, missing = 0;
	trace_t *trace;

	pr_debug("begin to resolve kernel symbol...\n");

	/* make the programs that target kernel function can't be found
	 * load manually.
	 */
	trace_for_each(trace) {
		char __name[136], *name;
		int skb_idx, sk_idx;

		if (trace_is_invalid(trace) || !trace_is_enable(trace))
			continue;
		checked++;

		/* function name contain "." is not supported by BTF */
		if (strchr(trace->name, '.')) {
			trace_set_invalid_reason(trace, "BTF invalid");
			continue;
		}

		if (!trace_is_func(trace)) {
			name = __name;
			sprintf(__name, "__bpf_trace_%s", trace->name);
		} else {
			name = trace->name;
		}

		if (btf_get_trace_args_local(name, &trace->arg_count,
					     &skb_idx, &sk_idx)) {
			if (sym_get_type(name) == SYM_MODULE &&
			    !btf_get_trace_args(name, &trace->arg_count,
						&skb_idx, &sk_idx)) {
				/* fallback to module BTF for module symbols */
			} else {
				pr_verb("kernel function %s not founded, skipped\n",
					name);
				trace_set_invalid_reason(trace, "not found");
				missing++;
				continue;
			}
		}
		trace->skb = skb_idx;
		trace->sk = sk_idx;
		if (!trace_is_func(trace)) {
			trace->arg_count -= 1;
			trace->skb -= 1;
			trace->sk -= 1;
		}
		resolved++;

		if (trace->skb >= 0 || trace->sk >= 0) {
			pr_debug("trace %s args resolved by BTF: skb=%d, sk=%d\n",
				 name, trace->skb, trace->sk);
		} else {
			pr_debug("trace %s has no skb or sk argument\n", name);
		}
	}

	support_feat_args_ext = tracing_support_feat_args_ext();
	if (!support_feat_args_ext) {
		pr_warn("tracing kernel function with 6+ arguments is not"
			"supportd by your kernel, following functions "
			"are skipped:\n");
		trace_for_each(trace) {
			if (trace->arg_count > 6) {
				pr_warn("\t%s\n", trace->name);
				trace_set_invalid(trace);
			}
		}
	}
	pr_debug("finished to resolve kernel symbol: checked=%d resolved=%d missing=%d\n",
		 checked, resolved, missing);
}

trace_ops_t tracing_ops = {
	.trace_attach = tracing_trace_attach,
	.trace_load = tracing_trace_load,
	.trace_open = tracing_trace_open,
	.trace_close = tracing_trace_close,
	.trace_ready = tracing_trace_ready,
	.trace_supported = tracing_trace_supported,
	.prepare_traces = tracing_prepare_traces,
	.print_stack = tracing_print_stack,
};
