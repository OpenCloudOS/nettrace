#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define BPF_FEAT_TRACING 1

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"
#include "core.h"

#define nt_regs(regs, index) (void *)((unsigned long long *)regs)[index - 1]
#define nt_regs_ctx(ctx, index) nt_regs(ctx->regs, index)


typedef int (*fake_func)(context_t *ctx);
#define __DECLARE_FAKE_FUNC(name, args...)			\
	static __always_inline int name(args)
#define DECLARE_FAKE_FUNC(name)					\
	__DECLARE_FAKE_FUNC(name, context_t *ctx)

/* one trace may have more than one implement */
#define __DEFINE_KPROBE_INIT(name, target, ctx_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("fexit/"#target)					\
	int TRACE_RET_NAME(name)(void **regs)			\
	{							\
		context_t ctx = {				\
			.func = INDEX_##name,			\
			.regs = regs,				\
			.args = CONFIG(),			\
			ctx_init				\
		};						\
		if (handle_exit(&ctx, regs, INDEX_##name))	\
			return 0;				\
		return fake__##name(&ctx);			\
	}							\
	SEC("fentry/"#target)					\
	int TRACE_NAME(name)(void **regs)			\
	{							\
		context_t ctx = {				\
			.func = INDEX_##name,			\
			.regs = regs,				\
			.args = CONFIG(),			\
			ctx_init				\
		};						\
		return fake__##name(&ctx);			\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_KPROBE_INIT(name, target, ctx_init...)		\
	__DEFINE_KPROBE_INIT(name, target, ctx_init)

#define __KPROBE_DEFAULT(name, skb_index, sk_index, acount)	\
	DEFINE_KPROBE_INIT(name, name,				\
		.skb = nt_ternary_take(skb_index,		\
				       nt_regs(regs, skb_index),\
				       NULL),			\
		.arg_count = acount)				\
	{							\
		return default_handle_entry(ctx);		\
	}
#define KPROBE_DUMMY(name, skb_index, sk_index, acount)

/* for now, only generate BPF program for monitor case */
#define KPROBE_DEFAULT(name, skb_index, sk_index, acount)	\
	nt_ternary_take(acount, __KPROBE_DEFAULT,		\
		KPROBE_DUMMY)(name, skb_index, sk_index, acount)

#define DEFINE_TP_INIT(name, cata, tp, ctx_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("tp_btf/"#tp)					\
	int TRACE_NAME(name)(void **regs) {			\
		context_t ctx = {				\
			.func = INDEX_##name,			\
			.regs = regs,				\
			.args = CONFIG(),			\
			ctx_init				\
		};						\
		return fake__##name(&ctx);			\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, index)			\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = nt_regs(regs, index))
#define TP_DEFAULT(name, cata, tp, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		return default_handle_entry(ctx);		\
	}
#define FNC(name)

#define ctx_event_null(ctx, event)				\
	ctx->e = (void *)&(event);				\
	ctx->size = 0;
#define ctx_event(ctx, event)					\
	ctx->e = (void *)&(event);				\
	ctx->size = sizeof(event)

#define ext_event_init() { }

const volatile int func_ret_index[TRACE_MAX];


static try_inline int
handle_exit(context_t *ctx, void **regs, int func_index);
#define get_ret(func)

#include "core.c"

rules_ret_t rules_all[TRACE_MAX];

static int
handle_exit(context_t *ctx, void **regs, int func_index)
{
	int i, expected, ret;
	bool hit = false;

	rules_ret_t *rules = &rules_all[func_index];
	if (!rules)
		goto no_match;

	if (bpf_core_helper_exist(get_func_ret))
		bpf_get_func_ret(ctx->regs, &ctx->retval);
	else
		bpf_probe_read_kernel(&ctx->retval, sizeof(u64),
			regs + ctx->arg_count);

	ret = (int)ctx->retval;
	for (i = 0; i < MAX_RULE_COUNT; i++) {
		expected = rules->expected[i];
		switch (rules->op[i]) {
		case RULE_RETURN_ANY:
			hit = true;
			break;
		case RULE_RETURN_EQ:
			hit = expected == ret;
			break;
		case RULE_RETURN_LT:
			hit = expected < ret;
			break;
		case RULE_RETURN_GT:
			hit = expected > ret;
			break;
		case RULE_RETURN_NE:
			hit = expected != ret;
			break;
		default:
			goto no_match;
		}
		if (hit)
			break;
	}

	if (!hit)
		goto no_match;
	return 0;
no_match:
	return -1;
}
