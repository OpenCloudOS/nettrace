#ifndef _H_PROG_KPROBE
#define _H_PROG_KPROBE

typedef struct {
	void *regs;
	struct sk_buff *skb;
	struct sock *sk;
	event_t *e;
	bpf_args_t *args;
	size_t size;
	u16 func;
} context_t;

#define MODE_SKIP_LIFE_MASK (TRACE_MODE_BASIC_MASK | TRACE_MODE_DROP_MASK)

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

/* init the skb by the index of func args */
#define DEFINE_KPROBE_SKB(name, skb_index)			\
	DEFINE_KPROBE_INIT(name, name,				\
			   .skb = nt_regs(regs, skb_index))

/* the same as DEFINE_KPROBE_SKB(), but can set a different target */
#define DEFINE_KPROBE_SKB_TARGET(name, target, skb_index)	\
	DEFINE_KPROBE_INIT(name, target,			\
			   .skb = nt_regs(regs, skb_index))

#define DEFINE_KPROBE_SKB_SK(name, skb_index, sk_index)		\
	DEFINE_KPROBE_INIT(name, name,				\
			   .skb = nt_regs(regs, skb_index),	\
			   .sk = nt_regs(regs, sk_index))

/* the args here can be sk_index. Therefore, DEFINE_KPROBE_SKB_SK
 * will be used when the 3th arg offered.
 */
#define KPROBE_DEFAULT(name, skb_index, args...)		\
	nt_take_3th(dummy, ##args, DEFINE_KPROBE_SKB_SK,	\
		    DEFINE_KPROBE_SKB)(name, skb_index, ##args)	\
	{							\
		return default_handle_entry(ctx);		\
	}

#define DEFINE_TP(name, cata, tp, offset)			\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("tp/"#cata"/"#tp)					\
	int TRACE_NAME(name)(void *regs) {			\
		context_t ctx = {				\
			.skb = *(void **)(regs + offset),	\
			.func = INDEX_##name,			\
			.regs = regs,				\
			.args = CONFIG(),			\
		};						\
		return fake__##name(&ctx, ctx.skb);		\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define TP_DEFAULT(name, cata, tp, offset)			\
	DEFINE_TP(name, cata, tp, offset)			\
	{							\
		return default_handle_entry(ctx);		\
	}
#define FNC(name)

#define __DECLARE_EVENT(prefix, type, name, init...)	\
	pure_##type __attribute__((__unused__)) *name;	\
	if (ctx->args->detail)				\
		goto prefix##_detail;			\
	type _##name = { init };			\
	ctx_event(ctx, _##name);			\
	name = (void *)ctx->e +				\
	       offsetof(type, __event_filed);		\
	goto prefix##_handle;				\
prefix##_detail:;					\
	detail_##type __##name = { init };		\
	ctx_event(ctx, __##name);			\
	name = (void *)ctx->e +				\
	       offsetof(detail_##type, __event_filed);	\
prefix##_handle:;

#define DECLARE_EVENT(type, name, init...)		\
	__DECLARE_EVENT(basic, type, name, init)

#define ctx_event_null(ctx, event)				\
	ctx->e = (void *)&(event);				\
	ctx->size = 0;
#define ctx_event(ctx, event)					\
	ctx->e = (void *)&(event);				\
	ctx->size = sizeof(event)

#define ext_event_init() { }

#endif
