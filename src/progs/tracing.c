#define KBUILD_MODNAME ""
#define __PROG_TYPE_TRACING 1

#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"
#include "core.h"

#define ctx_get_arg(ctx, index) (void *)((unsigned long long *)ctx)[index]
#define info_get_arg(info, index) ctx_get_arg(info->ctx, index)

#define DECLARE_FAKE_FUNC(name)					\
	static __always_inline int name(context_info_t *info)

/* one trace may have more than one implement */
#define __DEFINE_KPROBE_INIT(name, target, acount, info_init...) \
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("fexit/"#target)					\
	int TRACE_RET_NAME(name)(void **ctx)			\
	{							\
		context_info_t info;				\
								\
		if (pre_handle_exit(ctx, INDEX_##name, &info.retval, acount)) \
			return 0;				\
		/* initialize info only after the check pass */	\
		info = (context_info_t) {			\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			.args = CONFIG(),			\
			.retval = info.retval,			\
			info_init				\
		};						\
		return fake__##name(&info);			\
	}							\
	SEC("fentry/"#target)					\
	int TRACE_NAME(name)(void **ctx)			\
	{							\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			.args = CONFIG(),			\
			info_init				\
		};						\
		return fake__##name(&info);			\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_KPROBE_INIT(name, target, acount, info_init...)	\
	__DEFINE_KPROBE_INIT(name, target, acount, info_init)

#define __KPROBE_DEFAULT(name, skb_index, sk_index, acount)	\
	DEFINE_KPROBE_INIT(name, name, acount,			\
		.skb = nt_ternary_take(skb_index,		\
				       ctx_get_arg(ctx, skb_index),\
				       NULL),			\
		.sk = nt_ternary_take(sk_index,			\
				      ctx_get_arg(ctx, sk_index),\
				      NULL))			\
	{							\
		return default_handle_entry(info);		\
	}
#define KPROBE_DUMMY(name, skb_index, sk_index, acount)

/* for now, only generate BPF program for monitor case */
#define KPROBE_DEFAULT(name, skb_index, sk_index, acount)	\
	nt_ternary_take(acount, __KPROBE_DEFAULT,		\
		KPROBE_DUMMY)(name, skb_index, sk_index, acount)

#define DEFINE_TP_INIT(name, cata, tp, info_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("tp_btf/"#tp)					\
	int TRACE_NAME(name)(void **ctx) {			\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			.args = CONFIG(),			\
			info_init				\
		};						\
		return fake__##name(&info);			\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, skb_index)			\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = ctx_get_arg(ctx, skb_index))
#define TP_DEFAULT(name, cata, tp, skb_index, offset)		\
	DEFINE_TP(name, cata, tp, skb_index)			\
	{							\
		return default_handle_entry(info);		\
	}
#define FNC(name)

static __always_inline int pre_handle_exit(void *ctx, int func_index,
					   u64 *retval,
					   int arg_count);
static try_inline int default_handle_entry(context_info_t *info);
/* we don't need to get/put kernel function to pair the entry and exit in
 * TRACING program.
 */
#define get_ret(func)

#include "core.c"

static try_inline int default_handle_entry(context_info_t *info)
{
	DECLARE_EVENT(event_t, e)
	handle_entry(info, e_size);

	switch (info->func) {
	case INDEX_consume_skb:
	case INDEX___kfree_skb:
		handle_destroy(info);
		break;
	default:
		break;
	}

	return 0;
}

rules_ret_t rules_all[TRACE_MAX];

static __always_inline int pre_handle_exit(void *ctx, int func_index,
					   u64 *retval,
					   int arg_count)
{
	int i, expected, ret;
	rules_ret_t *rules;
	bool hit = false;
	void *ret_ptr;

	/* this can't happen */
	if (func_index >= TRACE_MAX)
		goto no_match;

	rules = &rules_all[func_index];
	if (!rules)
		goto no_match;

	*retval = 0;
	if (bpf_core_helper_exist(get_func_ret)) {
		bpf_get_func_ret(ctx, retval);
	} else {
		if (!arg_count)
			goto no_match;
		ret_ptr = ctx + arg_count * 8;
		bpf_probe_read_kernel(retval, sizeof(u64), ret_ptr);
	}

	ret = (int)*retval;
	pr_bpf_debug("func=%d retval=%d\n", func_index, ret);
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
