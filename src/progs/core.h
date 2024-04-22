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
			     TRACE_MODE_MONITOR_MASK)

/* init the skb by the index of func args */
#define DEFINE_KPROBE_SKB(name, skb_index, arg_count)		\
	DEFINE_KPROBE_INIT(name, name, arg_count,		\
			   .skb = ctx_get_arg(ctx, skb_index))

#define DECLARE_EVENT(type, name)			\
	pure_##type __attribute__((__unused__)) *name;	\
	type __attribute__((__unused__))__##name;	\
	detail_##type __detail_##name = {0};		\
	info->e = (void *)&__detail_##name;		\
	if (info->args->detail) {			\
		name = (void *)info->e +		\
		       offsetof(detail_##type, __event_filed);	\
	} else {					\
		name = (void *)info->e +		\
		       offsetof(type, __event_filed);	\
	}

#define handle_event_output(info, e)			\
	do_event_output(info, (info->args->detail ? sizeof(__detail_##e) : sizeof(__##e)))

#define handle_entry_output(info, e)			\
({							\
	int err = handle_entry(info);			\
	if (!err)					\
		handle_event_output(info, e);		\
	err;						\
})
#endif
