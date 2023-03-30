#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"

#undef FUNC_NAME
#define FUNC_NAME(name)		\
	nt_ternary_take(QDISC_LEGACY, name##_legacy, name)

#undef FAKE_FUNC_NAME
#define FAKE_FUNC_NAME FUNC_NAME(handle_qdisc)


static try_inline int
FAKE_FUNC_NAME(context_t *ctx, struct Qdisc *q)
{
	struct netdev_queue *txq;
	DECLARE_EVENT(qdisc_event_t, e)

	txq = _C(q, dev_queue);

#ifndef QDISC_LEGACY
	u64 start;

	start = _C(txq, trans_start);
	if (start)
		e->last_update = bpf_jiffies64() - start;
#endif

	e->qlen = _C(&(q->q), qlen);
	e->state = _C(txq, state);
	e->flags = _C(q, flags);

	return handle_entry(ctx);
}

#define DEFINE_QDISC(name)				\
DEFINE_KPROBE_SKB_TARGET(FUNC_NAME(name), name, 1) {	\
	struct Qdisc *q = nt_regs_ctx(ctx, 2);		\
	return FAKE_FUNC_NAME(ctx, q);			\
}

DEFINE_QDISC(sch_direct_xmit)
DEFINE_QDISC(pfifo_enqueue)
