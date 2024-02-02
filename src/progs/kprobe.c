#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>
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
	static try_inline int name(context_info_t *info)

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
			.args = CONFIG(),			\
			info_init				\
		};						\
		return fake__##name(&info);			\
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
			.args = CONFIG(),			\
			info_init				\
		};						\
		return fake__##name(&info);			\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, offset)			\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = *(void **)(ctx + offset))
#define TP_DEFAULT(name, cata, tp, skb, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		return default_handle_entry(info);		\
	}
#define FNC(name)

static try_inline int handle_exit(struct pt_regs *ctx, int func);
static try_inline void get_ret(int func);
static try_inline int default_handle_entry(context_info_t *info);

#include "core.c"

static try_inline void get_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref)
		return;
	(*ref)++;
}

static try_inline int put_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref || *ref <= 0)
		return 1;
	(*ref)--;
	return 0;
}

static try_inline int default_handle_entry(context_info_t *info)
{
#ifdef COMPAT_MODE
	detail_event_t __e;

	/* the kernel of version 4.X can't spill const variable to stack,
	 * so we can't pass the e_size to handle_entry() in this case.
	 */
	info->e = (void *)&__e;
	if (info->args->detail) {
		__e = (detail_event_t) {0};
		handle_entry(info, sizeof(detail_event_t));
	} else {
		*(event_t *)&__e = (event_t) {0};
		handle_entry(info, sizeof(event_t));
	}
#else
	DECLARE_EVENT(event_t, e)
	handle_entry(info, e_size);
#endif

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

static try_inline int handle_exit(struct pt_regs *ctx, int func)
{
	retevent_t event;

	if (!ARGS_GET_CONFIG(ready) || put_ret(func))
		return 0;

	event = (retevent_t) {
		.ts = bpf_ktime_get_ns(),
		.func = func,
		.val = PT_REGS_RC(ctx),
	};

	if (func == INDEX_skb_clone) {
		bool matched = true;
		bpf_map_update_elem(&m_matched, &event.val, &matched, 0);
	}

	EVENT_OUTPUT(ctx, event);
	return 0;
}
