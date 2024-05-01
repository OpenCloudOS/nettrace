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

/* init the skb by the index of func args */
#define DEFINE_KPROBE_SKB(name, skb_index, arg_count)		\
	DEFINE_KPROBE_INIT(name, name, arg_count,		\
			   .skb = ctx_get_arg(ctx, skb_index))

/* BPF_NO_GLOBAL_DATA means this kernel version is old, we need to initialize
 * all the event data.
 */
#ifdef BPF_NO_GLOBAL_DATA
#define DECLARE_EVENT(type, name)				\
	pure_##type __attribute__((__unused__)) *name;		\
	type __attribute__((__unused__))__##name;		\
	detail_##type __detail_##name = {0};			\
	info->e = (void *)&__detail_##name;			\
	if (info->args->detail) {				\
		WRITE_ONCE(name, (void *)info->e +		\
		       offsetof(detail_##type, __event_filed));	\
	} else {						\
		WRITE_ONCE(name, (void *)info->e +		\
		       offsetof(type, __event_filed));		\
	}

#define handle_event_output(info, e)		\
	do_event_output(info, (info->args->detail ? sizeof(__detail_##e) : sizeof(__##e)))
#else
/* initialize only part event data if not detail */
#define DECLARE_EVENT(type, name)				\
	pure_##type __attribute__((__unused__)) *name;		\
	type __attribute__((__unused__))__##name;		\
	detail_##type __detail_##name;				\
	info->e = (void *)&__detail_##name;			\
	int name##_size;					\
	if (info->args->detail) {				\
		name##_size = sizeof(detail_##type);		\
		__builtin_memset(info->e, 0, name##_size);	\
		name = offsetof(detail_##type, __event_filed) +	\
		       (void *)info->e;				\
	} else {						\
		name##_size = sizeof(type);			\
		__builtin_memset(info->e, 0, name##_size);	\
		name = offsetof(type, __event_filed) +		\
		       (void *)info->e;				\
	}

#define handle_event_output(info, e) do_event_output(info, e##_size)
#endif

#define handle_entry_output(info, e)		\
({						\
	int err = handle_entry(info);		\
	if (!err)				\
		handle_event_output(info, e);	\
	err;					\
})

#endif
