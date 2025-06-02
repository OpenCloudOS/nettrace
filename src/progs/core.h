#ifndef _H_PROG_CORE
#define _H_PROG_CORE

#include "skb_parse.h"

typedef struct {
	u16 func1;
	u16 func2;
	u32 ts1;
	u32 ts2;
} match_val_t;

typedef struct {
	/* the bpf context args */
	void *ctx;
	struct sk_buff *skb;
	struct sock *sk;
	event_t *e;
	/* the filter condition stored in map */
	bpf_args_t *args;
	union {
		/* used by fexit to pass the retval to event */
		u64 retval;
		/* match only used in context mode, no conflict with retval */
		match_val_t match_val;
		u32 matched;
	};
	u16 func;
	u8  func_status;
	/* don't output the event for this skb */
	u8  no_event:1;
} context_info_t;

/* init the skb by the index of func args */
#define DEFINE_KPROBE_SKB(name, skb_index, arg_count)		\
	DEFINE_KPROBE_INIT(name, name, arg_count,		\
			   .skb = ctx_get_arg(ctx, skb_index))

/* BPF_NO_GLOBAL_DATA means this kernel version is old, we need to initialize
 * all the event data.
 */
#if defined(BPF_NO_GLOBAL_DATA) || defined(__F_INIT_EVENT)
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

#ifdef __F_OUTPUT_WHOLE
#define handle_event_output(info, e)		\
	do_event_output(info, sizeof(__detail_##e))
#else
#define handle_event_output(info, e)		\
	do_event_output(info, (info->args->detail ? sizeof(__detail_##e) : sizeof(__##e)))
#endif

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
