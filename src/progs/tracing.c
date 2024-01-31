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

#define ctx_get_arg(ctx, index) (void *)((unsigned long long *)ctx)[index - 1]
#define info_get_arg(info, index) ctx_get_arg(info->ctx, index)

#define DECLARE_FAKE_FUNC(name)					\
	static __always_inline int name(context_info_t *info)

/* one trace may have more than one implement */
#define __DEFINE_KPROBE_INIT(name, target, info_init...)	\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("fexit/"#target)					\
	int TRACE_RET_NAME(name)(void **ctx)			\
	{							\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			.args = CONFIG(),			\
			info_init				\
		};						\
		if (handle_exit(&info))				\
			return 0;				\
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
#define DEFINE_KPROBE_INIT(name, target, info_init...)		\
	__DEFINE_KPROBE_INIT(name, target, info_init)

#define __KPROBE_DEFAULT(name, skb_index, sk_index, acount)	\
	DEFINE_KPROBE_INIT(name, name,				\
		.skb = nt_ternary_take(skb_index,		\
				       ctx_get_arg(ctx, skb_index),\
				       NULL),			\
		.arg_count = acount)				\
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
#define DEFINE_TP(name, cata, tp, index)			\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = ctx_get_arg(ctx, index))
#define TP_DEFAULT(name, cata, tp, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		return default_handle_entry(info);		\
	}
#define FNC(name)

static try_inline int handle_exit(context_info_t *info);
/* we don't need to get/put kernel function to pair the entry and exit in
 * TRACING program.
 */
#define get_ret(func)

#include "core.c"

rules_ret_t rules_all[TRACE_MAX];

static try_inline int handle_exit(context_info_t *info)
{
	int i, expected, ret;
	rules_ret_t *rules;
	bool hit = false;
	int func_index;
	void *ret_ptr;

	func_index = info->func;
	/* this can't happen */
	if (func_index >= TRACE_MAX)
		goto no_match;

	rules = &rules_all[func_index];
	if (!rules)
		goto no_match;

	if (bpf_core_helper_exist(get_func_ret)) {
		bpf_get_func_ret(info->ctx, &info->retval);
	} else {
		ret_ptr = info->ctx + info->arg_count * 8;
		bpf_probe_read_kernel(&info->retval, sizeof(u64), ret_ptr);
	}

	ret = (int)info->retval;
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
