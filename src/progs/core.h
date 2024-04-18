#ifndef _H_PROG_CORE
#define _H_PROG_CORE

typedef struct {
	/* the bpf context args */
	void *ctx;
	struct sk_buff *skb;
	struct sock *sk;
	event_t *e;
	/* the filter condition stored in map */
	bpf_args_t *args;
	/* used by fexit to pass the retval to event */
	u64 retval;
	u16 func;
} context_info_t;

#define MODE_SKIP_LIFE_MASK (TRACE_MODE_BASIC_MASK |	\
			     TRACE_MODE_DROP_MASK |	\
			     TRACE_MODE_SOCK_MASK |	\
			     TRACE_MODE_MONITOR_MASK |	\
			     TRACE_MODE_RTT_MASK)

/* init the skb by the index of func args */
#define DEFINE_KPROBE_SKB(name, skb_index, arg_count)		\
	DEFINE_KPROBE_INIT(name, name, arg_count,		\
			   .skb = ctx_get_arg(ctx, skb_index))

#ifndef COMPAT_MODE
#define DECLARE_EVENT(type, name)			\
	pure_##type __attribute__((__unused__)) *name;	\
	int __attribute__((__unused__)) name##_size;	\
	detail_##type __##name;				\
	info->e = (void *)&__##name;			\
	if (info->args->detail) {			\
		name = (void *)info->e +		\
		       offsetof(detail_##type, __event_filed);	\
		__##name = (detail_##type) {0};		\
		name##_size = sizeof(detail_##type);	\
	} else {					\
		name = (void *)info->e +		\
		       offsetof(type, __event_filed);	\
		*(type *)info->e = (type) {0};		\
		name##_size = sizeof(type);		\
	}
#else
/* use the detailed event version directly for compat mode. */
#define DECLARE_EVENT(type, name)			\
	detail_##type __##name = { 0 };			\
	detail_##type __attribute__((__unused__)) *name;\
	int __attribute__((__unused__)) name##_size;	\
	name = &__##name;				\
	info->e = (void *)name;				\
	name##_size = sizeof(detail_##type);
#endif

#endif
