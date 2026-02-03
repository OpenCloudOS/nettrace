#ifndef _H_PROG_CORE
#define _H_PROG_CORE

#include "vmlinux.h"

typedef struct {
	u16 func1;
	u16 func2;
	u32 ts1;
	u32 ts2;
} match_val_t;

typedef struct {
	/* the bpf context args */
	u64 *ctx;
	struct sk_buff *skb;
	struct sock *sk;
	union {
		/* used in the return only case, to pass the retval to event */
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

#endif
