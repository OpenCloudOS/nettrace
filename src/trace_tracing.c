#include <sys/sysinfo.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/bpf.h>

#include "trace.h"
#include "analysis.h"
#include "progs/tracing.skel.h"
#include "progs/feat_args_ext.skel.h"

static struct tracing *skel;

static int attach_trace_prog(trace_t *trace, int prog_fd,
			     enum bpf_attach_type attach_type,
			     int *link_fd);

static int tracing_lookup_sym_type(const char **names, const int *types,
				   int nr, const char *name)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (!names[i] || strcmp(names[i], name))
			continue;
		return types[i];
	}

	return SYM_NOT_EXIST;
}

static void tracing_prepare_symbols(const char **func_names, int func_nr,
				    int *func_types)
{
	int i;

	if (!func_names || !func_types || func_nr <= 0)
		return;

	for (i = 0; i < func_nr; i++)
		func_types[i] = SYM_NOT_EXIST;

	/* Extract symbol types for all targets in one pass from /proc/kallsyms. */
	sym_get_types_bulk(func_names, func_nr, func_types);
}


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
	static int cached = -1;
	struct feat_args_ext *tmp;
	bool supported = false;

	if (cached >= 0)
		return cached;

	/* Verifier acceptance is enough for this feature probe. */
	tmp = feat_args_ext__open_and_load();
	if (tmp)
		supported = true;

	feat_args_ext__destroy(tmp);
	cached = supported ? 1 : 0;

	return supported;
}

static int tracing_trace_attach()
{
	trace_t *trace;
	int err;

	err = tracing__attach(skel);
	if (err) {
		pr_err("failed to attach tracing programs: %d\n", err);
		return err;
	}

	trace_for_each(trace) {
		if (trace_is_invalid(trace) || !trace_is_enable(trace) ||
		    trace->custom)
			continue;

		if (!trace_is_func(trace)) {
			err = attach_trace_prog(trace, trace->prog_fd,
						BPF_TRACE_RAW_TP,
						&trace->link_fd);
			if (err)
				return err;
			continue;
		}

		err = attach_trace_prog(trace, trace->prog_fd,
					BPF_TRACE_FENTRY,
					&trace->link_fd);
		if (err)
			return err;

		err = attach_trace_prog(trace, trace->ret_prog_fd,
					BPF_TRACE_FEXIT,
					&trace->ret_link_fd);
		if (err)
			return err;
	}

	return 0;
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

static int fixup_insn(struct bpf_insn *insns, size_t insn_cnt, trace_t *trace)
{
	size_t i;
	int fixed = 0;

	for (i = 0; i < insn_cnt; i++) {
		struct bpf_insn *insn = &insns[i];

		if (insn->code == (BPF_JMP | BPF_CALL) &&
		    insn->src_reg == 0 &&
		    insn->imm == BPF_FUNC_nt_get_func_index) {
			insn->code = BPF_ALU64 | BPF_MOV | BPF_K;
			insn->dst_reg = 0;
			insn->src_reg = 0;
			insn->off = 0;
			insn->imm = trace->index;
			fixed++;
			continue;
		}

		if (insn->code == (BPF_JMP | BPF_CALL) &&
		    insn->src_reg == 0 &&
		    insn->imm == BPF_FUNC_nt_get_skb) {
			if (trace->skb >= 0) {
				insn->code = BPF_LDX | BPF_MEM | BPF_DW;
				insn->dst_reg = 0;
				insn->src_reg = 1;
				insn->off = (short)(trace->skb * sizeof(__u64));
				insn->imm = 0;
			} else {
				insn->code = BPF_ALU64 | BPF_MOV | BPF_K;
				insn->dst_reg = 0;
				insn->src_reg = 0;
				insn->off = 0;
				insn->imm = 0;
			}
			fixed++;
			continue;
		}

		if (insn->code == (BPF_JMP | BPF_CALL) &&
		    insn->src_reg == 0 &&
		    insn->imm == BPF_FUNC_nt_get_sk) {
			if (trace->sk >= 0) {
				insn->code = BPF_LDX | BPF_MEM | BPF_DW;
				insn->dst_reg = 0;
				insn->src_reg = 1;
				insn->off = (short)(trace->sk * sizeof(__u64));
				insn->imm = 0;
			} else {
				insn->code = BPF_ALU64 | BPF_MOV | BPF_K;
				insn->dst_reg = 0;
				insn->src_reg = 0;
				insn->off = 0;
				insn->imm = 0;
			}
			fixed++;
			continue;
		}
	}

	return fixed;
}

static int fixup_prog(struct bpf_program *prog, trace_t *trace)
{
	struct bpf_insn *insns;
	size_t insn_cnt;

	insns = (struct bpf_insn *)bpf_program__insns(prog);
	insn_cnt = bpf_program__insn_cnt(prog);

	return fixup_insn(insns, insn_cnt, trace);
}

static void fixup_programs()
{
	struct bpf_program *prog;
	int fixed_total = 0;

	bpf_object__for_each_program(prog, skel->obj) {
		const char *prog_name = bpf_program__name(prog);
		trace_t *trace = find_trace_by_prog(prog_name);
		int fixed;

		pr_debug("checking prog=%s for fixup\n", prog_name);
		if (!strcmp(prog_name, "nt__default") ||
		    !strcmp(prog_name, "nt_ret__default") ||
		    !strcmp(prog_name, "nt__default_tp"))
			continue;

		if (!trace || trace_is_invalid(trace))
			continue;

		fixed = fixup_prog(prog, trace);
		if (!fixed)
			continue;

		pr_debug("fixed %d instruction(s) in prog=%s, trace=%s (skb=%d sk=%d)\n",
			 fixed, prog_name, trace->name, trace->skb, trace->sk);
		fixed_total += fixed;
	}

	pr_debug("instruction fixup done, total=%d\n", fixed_total);
}

static int load_cloned_prog(trace_t *trace, struct bpf_program *tmpl,
			    const char *prog_name)
{
	struct bpf_insn *insns;
	const struct bpf_insn *tmpl_insns;
	size_t insn_cnt;
	int fd;
	int btf_fd;
	__u32 func_info_cnt, line_info_cnt;
	DECLARE_LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.expected_attach_type = bpf_program__expected_attach_type(tmpl),
		.prog_flags = bpf_program__flags(tmpl),
		.attach_btf_id = trace->attach_btf_id,
		.attach_btf_obj_fd = trace->attach_btf_fd,
	);

	if (trace->attach_btf_id < 0) {
		pr_verb("trace %s has invalid attach btf id\n", trace->name);
		return -ENOENT;
	}

	insn_cnt = bpf_program__insn_cnt(tmpl);
	tmpl_insns = bpf_program__insns(tmpl);
	insns = calloc(insn_cnt, sizeof(*insns));
	if (!insns)
		return -ENOMEM;

	memcpy(insns, tmpl_insns, insn_cnt * sizeof(*insns));
	fixup_insn(insns, insn_cnt, trace);

	btf_fd = bpf_object__btf_fd(skel->obj);
	if (btf_fd > 0)
		opts.prog_btf_fd = btf_fd;

	func_info_cnt = bpf_program__func_info_cnt(tmpl);
	if (func_info_cnt) {
		opts.func_info = bpf_program__func_info(tmpl);
		opts.func_info_cnt = func_info_cnt;
		opts.func_info_rec_size = sizeof(struct bpf_func_info);
	}

	line_info_cnt = bpf_program__line_info_cnt(tmpl);
	if (line_info_cnt) {
		opts.line_info = bpf_program__line_info(tmpl);
		opts.line_info_cnt = line_info_cnt;
		opts.line_info_rec_size = sizeof(struct bpf_line_info);
	}

	fd = bpf_prog_load(bpf_program__type(tmpl), prog_name, "GPL",
			   insns, insn_cnt, &opts);
	pr_debug("loaded cloned prog %s for trace %s, fd=%d\n", prog_name, trace->name, fd);
	free(insns);
	return fd;
}

static int attach_trace_prog(trace_t *trace, int prog_fd,
			     enum bpf_attach_type attach_type,
			     int *link_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);

	if (prog_fd < 0)
		return 0;

	*link_fd = bpf_link_create(prog_fd, trace->attach_btf_fd,
				   attach_type, &opts);
	if (*link_fd < 0) {
		pr_err("failed to attach prog for trace %s: btf_id=%d btf_fd=%d attach_type=%d fd=%d %s\n",
		       trace->name, trace->attach_btf_id, trace->attach_btf_fd,
		       attach_type, prog_fd, strerror(errno));
		return -errno;
	}

	return 0;
}

static int tracing_trace_open()
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = trace_ctx.args.btf_path,
	);
	trace_t *trace;

	skel = tracing__open_opts(&opts);
	if (!skel) {
		pr_err("failed to open tracing-based eBPF\n");
		goto err;
	}
	pr_debug("eBPF is opened successfully\n");

	tracing_load_rules();
	trace_ctx.obj = skel->obj;

	trace_for_each(trace) {
		trace->prog_fd = -1;
		trace->ret_prog_fd = -1;
		trace->link_fd = -1;
		trace->ret_link_fd = -1;
	}

	skel->rodata->m_config = trace_ctx.bpf_args;
	skel->bss->m_data = trace_ctx.bpf_data;

	/* make sure all the instructions are ready */
	bpf_object__prepare(skel->obj);
	fixup_programs();

	return 0;
err:
	return -1;
}

static int tracing_trace_load()
{
	struct bpf_program *tmpl_entry;
	struct bpf_program *tmpl_exit;
	struct bpf_program *tmpl_tp;
	trace_t *trace;
	int err = 0;

	if (tracing__load(skel)) {
		pr_err("failed to load tracing-based eBPF\n");
		err = -1;
		goto err;
	}
	pr_debug("eBPF is loaded successfully\n");

	tmpl_entry = bpf_pbn(skel->obj, "nt__default");
	tmpl_exit = bpf_pbn(skel->obj, "nt_ret__default");
	tmpl_tp = bpf_pbn(skel->obj, "nt__default_tp");

	trace_for_each(trace) {
		int fd;
		bool need_entry, need_exit;

		if (trace_is_invalid(trace) || !trace_is_enable(trace) ||
		    trace->custom)
			continue;

		if (trace->attach_btf_id < 0) {
			trace_set_invalid_reason(trace, "BTF invalid");
			continue;
		}

		if (!trace_is_func(trace)) {
			if (!tmpl_tp) {
				pr_err("default tp template not found\n");
				err = -ENOENT;
				goto err;
			}
			fd = load_cloned_prog(trace, tmpl_tp, trace->prog);
			if (fd < 0) {
				pr_err("failed to load tp prog %s: %d\n",
				       trace->prog, fd);
				err = fd;
				goto err;
			}
			trace->prog_fd = fd;
			continue;
		}

		need_entry = !trace_is_retonly(trace);
		need_exit = trace_is_ret(trace) || trace_is_retonly(trace);

		if (need_entry) {
			if (!tmpl_entry) {
				pr_err("default entry template not found\n");
				err = -ENOENT;
				goto err;
			}
			fd = load_cloned_prog(trace, tmpl_entry, trace->prog);
			if (fd < 0) {
				pr_err("failed to load prog %s: %d\n",
				       trace->prog, fd);
				err = fd;
				goto err;
			}
			trace->prog_fd = fd;
		}

		if (need_exit) {
			if (!tmpl_exit) {
				pr_err("default exit template not found\n");
				err = -ENOENT;
				goto err;
			}
			fd = load_cloned_prog(trace, tmpl_exit, trace->ret_prog);
			if (fd < 0) {
				pr_err("failed to load ret prog %s: %d\n",
				       trace->ret_prog, fd);
				err = fd;
				goto err;
			}
			trace->ret_prog_fd = fd;
		}
	}

	return 0;
err:
	return err;
}

void tracing_trace_close()
{
	trace_t *trace;

	trace_for_each(trace) {
		if (trace->link_fd >= 0) {
			close(trace->link_fd);
			trace->link_fd = -1;
		}
		if (trace->ret_link_fd >= 0) {
			close(trace->ret_link_fd);
			trace->ret_link_fd = -1;
		}
		if (trace->prog_fd >= 0) {
			close(trace->prog_fd);
			trace->prog_fd = -1;
		}
		if (trace->ret_prog_fd >= 0) {
			close(trace->ret_prog_fd);
			trace->ret_prog_fd = -1;
		}
	}

	btf_release_cache();

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
	const char *func_names[TRACE_MAX] = {};
	int func_types[TRACE_MAX] = {};
	int func_nr = 0;
	trace_t *trace;

	pr_debug("begin to resolve kernel symbol...\n");

	trace_for_each(trace) {
		if (trace_is_invalid(trace) || !trace_is_enable(trace) ||
		    !trace_is_func(trace))
			continue;
		if (strchr(trace->name, '.'))
			continue;
		if (func_nr >= TRACE_MAX)
			break;
		func_names[func_nr++] = trace->name;
	}
	tracing_prepare_symbols(func_names, func_nr, func_types);

	/* make the programs that target kernel function can't be found
	 * load manually.
	 */
	trace_for_each(trace) {
		char __name[136], *name;
		int skb_idx, sk_idx;
		int btf_id = -1;
		int btf_fd = 0;

		trace->attach_btf_id = -1;
		trace->attach_btf_fd = 0;

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
			sprintf(__name, "btf_trace_%s", trace->name);
		} else {
			name = trace->name;
		}

		if (btf_get_trace_args_local(name, &trace->arg_count,
					     &skb_idx, &sk_idx,
					     &btf_id, &btf_fd)) {
			if (tracing_lookup_sym_type(func_names,
						    func_types,
						    func_nr,
						    name) == SYM_MODULE &&
			    !btf_get_trace_args(name, &trace->arg_count,
						&skb_idx, &sk_idx,
						&btf_id, &btf_fd)) {
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
		trace->attach_btf_id = btf_id;
		trace->attach_btf_fd = btf_fd;
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
