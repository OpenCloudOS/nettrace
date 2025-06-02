#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include "core.h"

#include "kprobe_trace.h"

#define pt_regs_param_0 PT_REGS_PARM1
#define pt_regs_param_1 PT_REGS_PARM2
#define pt_regs_param_2 PT_REGS_PARM3
#define pt_regs_param_3 PT_REGS_PARM4
#define pt_regs_param_4 PT_REGS_PARM5

#define ctx_get_arg(ctx, index) (void *)pt_regs_param_##index((struct pt_regs*)ctx)
#define info_get_arg(info, index) ctx_get_arg(info->ctx, index)

#define DECLARE_FAKE_FUNC(name)					\
	static inline int name(context_info_t *info)

/* one trace may have more than one implement */
#define __DEFINE_KPROBE_INIT(name, target, info_init...)	\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("kretprobe/"#target)				\
	int TRACE_RET_NAME(name)(struct pt_regs *ctx)		\
	{							\
		return handle_exit(ctx, INDEX_##name);		\
	}							\
	SEC("kprobe/"#target)					\
	int TRACE_NAME(name)(struct pt_regs *ctx)		\
	{							\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			.args = (void *)CONFIG(),		\
			info_init				\
		};						\
		if (pre_handle_entry(&info, INDEX_##name))	\
			return 0;				\
		handle_entry_finish(&info,			\
				    fake__##name(&info));	\
		return 0;					\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_KPROBE_INIT(name, target, dummy, info_init...)	\
	__DEFINE_KPROBE_INIT(name, target, info_init)

#define KPROBE_DEFAULT(name, skb_index, sk_index, dummy)	\
	DEFINE_KPROBE_INIT(name, name, dummy,			\
		.skb = nt_ternary_take(skb_index,		\
				       ctx_get_arg(ctx, skb_index),\
				       NULL),			\
		.sk = nt_ternary_take(sk_index,			\
				      ctx_get_arg(ctx, sk_index),\
				      NULL)) {			\
	return default_handle_entry(info);			\
}

#define DEFINE_TP_INIT(name, cata, tp, info_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("tp/"#cata"/"#tp)					\
	int TRACE_NAME(name)(void *ctx) {			\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			.args = (void *)CONFIG(),		\
			info_init				\
		};						\
		if (pre_handle_entry(&info, INDEX_##name))	\
			return 0;				\
		handle_entry_finish(&info,			\
				    fake__##name(&info));	\
		return 0;					\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, skb_index, offset)		\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = *(void **)(ctx + offset))
#define TP_DEFAULT(name, cata, tp, skb, offset)			\
	DEFINE_TP(name, cata, tp, skb, offset)			\
	{							\
		return default_handle_entry(info);		\
	}
#define FNC(name)

static inline int handle_exit(struct pt_regs *ctx, int func);
static inline void get_ret(context_info_t *info);
static inline int default_handle_entry(context_info_t *info);

#include "core.c"

static __always_inline int get_ret_key(int func)
{
	return func;
}

static inline void get_ret(context_info_t *info)
{
	int *ref, key;

	if (!(info->func_status & FUNC_STATUS_RET))
		return;

	key = get_ret_key(info->func);
	ref = bpf_map_lookup_elem(&m_ret, &key);
	if (!ref)
		return;
	(*ref)++;
}

static inline int put_ret(bpf_args_t *args, int func)
{
	int *ref, key;

	if (!(get_func_status(args, func) & FUNC_STATUS_RET))
		return 1;

	key = get_ret_key(func);
	ref = bpf_map_lookup_elem(&m_ret, &key);
	if (!ref || *ref <= 0)
		return 1;
	(*ref)--;
	return 0;
}

static inline int handle_exit(struct pt_regs *ctx, int func)
{
	bpf_args_t *args = (void *)CONFIG();
	retevent_t event;

	if (!args->ready || put_ret(args, func))
		return 0;

	event = (retevent_t) {
		.ts = bpf_ktime_get_ns(),
		.func = func,
		.meta = FUNC_TYPE_RET,
		.val = PT_REGS_RC(ctx),
		.pid = (u32)bpf_get_current_pid_tgid(),
	};

	if (func == INDEX_skb_clone)
		init_ctx_match((void *)event.val, func, false);

	EVENT_OUTPUT(ctx, event);
	return 0;
}
