#ifndef _H_PROG_CORE
#define _H_PROG_CORE

#include "vmlinux.h"

typedef struct {
	u16 func1;
	u16 func2;
	u16 ref;
	u16 dead:1;
	u32 ts1;
	u32 ts2;
} skb_ctx_t;

typedef struct {
	/* the bpf context args */
	u64 *ctx;
	struct sk_buff *skb;
	struct sock *sk;
	union {
		/* match only used in context mode, no conflict with retval */
		skb_ctx_t *sctx;
		/* used in the return only case, to pass the retval to event */
		u64 retval;
	};
	u16 func;
	u8  func_status;
	/* don't output the event for this skb */
	u8  no_output:1;
	u8  is_return:1;
} context_info_t;

#endif
