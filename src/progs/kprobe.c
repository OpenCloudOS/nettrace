#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"


#define nt_regs(regs, index) (void *)PT_REGS_PARM##index((struct pt_regs*)regs)
#define nt_regs_ctx(ctx, index) nt_regs(ctx->regs, index)


#define __DECLARE_FAKE_FUNC(name, args...)			\
	static try_inline int name(args)
#define DECLARE_FAKE_FUNC(name)					\
	__DECLARE_FAKE_FUNC(name, context_t *ctx, struct sk_buff *skb)

/* one trace may have more than one implement */
#define __DEFINE_KPROBE_INIT(name, target, ctx_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("kretprobe/"#target)				\
	int TRACE_RET_NAME(name)(struct pt_regs *regs)		\
	{							\
		return handle_exit(regs, INDEX_##name);		\
	}							\
	SEC("kprobe/"#target)					\
	int TRACE_NAME(name)(struct pt_regs *regs)		\
	{							\
		context_t ctx = {				\
			.func = INDEX_##name,			\
			.regs = regs,				\
			.args = CONFIG(),			\
			ctx_init				\
		};						\
		return fake__##name(&ctx, ctx.skb);		\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_KPROBE_INIT(name, target, ctx_init...)		\
	__DEFINE_KPROBE_INIT(name, target, ctx_init)

#define KPROBE_DEFAULT(name, skb_index, sk_index, dummy)	\
	DEFINE_KPROBE_SKB_SK(name, skb_index, sk_index)		\
	{							\
		return default_handle_entry(ctx);		\
	}

#define DEFINE_TP_INIT(name, cata, tp, ctx_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("tp/"#cata"/"#tp)					\
	int TRACE_NAME(name)(void *regs) {			\
		context_t ctx = {				\
			.func = INDEX_##name,			\
			.regs = regs,				\
			.args = CONFIG(),			\
			ctx_init				\
		};						\
		return fake__##name(&ctx, ctx.skb);		\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, offset)			\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = *(void **)(regs + offset))
#define TP_DEFAULT(name, cata, tp, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		return default_handle_entry(ctx);		\
	}
#define FNC(name)

static try_inline int handle_exit(struct pt_regs *regs, int func);
static try_inline void get_ret(int func);

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

static try_inline int handle_exit(struct pt_regs *regs, int func)
{
	retevent_t event = {
		.ts = bpf_ktime_get_ns(),
		.func = func,
		.val = PT_REGS_RC(regs),
	};

	if (!ARGS_GET_CONFIG(ready) || put_ret(func))
		return 0;

	if (func == INDEX_skb_clone) {
		bool matched = true;
		bpf_map_update_elem(&m_matched, &event.val, &matched, 0);
	}

	EVENT_OUTPUT(regs, event);
	return 0;
}
