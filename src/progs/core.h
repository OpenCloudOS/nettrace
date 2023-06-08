#ifndef _H_PROG_CORE
#define _H_PROG_CORE

typedef struct {
	void *regs;
	struct sk_buff *skb;
	event_t *e;
	bpf_args_t *args;
	union {
		struct sock *sk;
		u64 arg_count;
		u64 retval;
	};

	/* regs spill only support u64 on kernel 5.4, so it donesn't work
	 * to use u16 here.
	 */
	size_t size;
	u16 func;
} context_t;

#define MODE_SKIP_LIFE_MASK (TRACE_MODE_BASIC_MASK |	\
			     TRACE_MODE_DROP_MASK |	\
			     TRACE_MODE_SOCK_MASK |	\
			     TRACE_MODE_MONITOR_MASK)

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
		.skb = nt_ternary_take(skb_index,		\
				       nt_regs(regs, skb_index),\
				       NULL),			\
		.sk = nt_ternary_take(sk_index,			\
				      nt_regs(regs, sk_index),	\
				      NULL))

#define DEFINE_KPROBE_SK(name, ignored, sk_index)		\
	DEFINE_KPROBE_INIT(name, name,				\
			   .sk = nt_regs(regs, sk_index))

#ifndef COMPAT_MODE
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
#else
#define __DECLARE_EVENT(prefix, type, name, init...)	\
	DECLARE_EVENT(type, name, init)
#define DECLARE_EVENT(type, name, init...)		\
	detail_##type __attribute__((__unused__)) *name; \
	detail_##type __##name = { init };		\
	ctx_event(ctx, __##name);			\
	name = &__##name;

#endif

#define ctx_event_null(ctx, event)				\
	ctx->e = (void *)&(event);				\
	ctx->size = 0;
#define ctx_event(ctx, event)					\
	ctx->e = (void *)&(event);				\
	ctx->size = sizeof(event)

#define ext_event_init() { }

#endif
