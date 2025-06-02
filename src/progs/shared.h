#ifndef _H_PROGS_SHARED
#define _H_PROGS_SHARED

#define MAX_FUNC_STACK 16

#include "skb_shared.h"

#include "kprobe_trace.h"

typedef struct {
	pkt_args_t pkt;
	u32  trace_mode;
	u32  pid;
	u32  netns;
	u32  max_event;
	bool drop_reason;
	bool detail;
	bool hooks;
	bool ready;
	bool stack;
	bool tiny_output;
	bool has_filter;
	bool latency_summary;
	bool func_stats;
	bool match_mode;
	bool latency_free;
	u32  first_rtt;
	u32  last_rtt;
	u32  rate_limit;
	u32  latency_min;
	int  __rate_limit;
	u64  __last_update;
	u8   trace_status[TRACE_MAX];
	u64  event_count;
} bpf_args_t;

typedef struct {
	u16		meta;
	u16		func;
	u32		key;
	union {
		packet_t	pkt;
		sock_t		ske;
	};
	union {
		/* For FEXIT program only for now */
		u64	retval;
		struct {
			u16 latency_func1;
			u16 latency_func2;
			u32 latency;
		};
	};
#ifdef __F_STACK_TRACE
	u32		stack_id;
#endif
	u32		pid;
	int		__event_filed[0];
} event_t;

typedef struct {
	u16 meta;
	u16 func;
	u32 key;
	u64 ts;
} tiny_event_t;

typedef struct {
	u16		meta;
	u16		func;
	u32		key;
	union {
		packet_t	pkt;
		sock_t		ske;
	};
	u64		retval;
#ifdef __F_STACK_TRACE
	u32		stack_id;
#endif
	u32		pid;
	/* fields above are exactly the same as event_t's, and the below
	 * fields are what we need to add for detail event.
	 */
	char		task[16];
	char		ifname[16];
	u32		ifindex;
	u32		netns;
	int		__event_filed[0];
} detail_event_t;

typedef struct {
} pure_event_t;

enum {
	FUNC_TYPE_FUNC,
	FUNC_TYPE_RET,
	FUNC_TYPE_TINY,
	FUNC_TYPE_TRACING_RET,
	FUNC_TYPE_MAX,
};


#define FUNC_STATUS_FREE	(1 << 0)
#define FUNC_STATUS_SK		(1 << 1)
#define FUNC_STATUS_MATCHER	(1 << 3)
#define FUNC_STATUS_STACK	(1 << 4)
#define FUNC_STATUS_RET		(1 << 5)
#define FUNC_STATUS_CFREE	(1 << 6) /* custom skb free function */

#undef DEFINE_EVENT
#define DEFINE_EVENT(name, fields...)		\
typedef struct {				\
	event_t event;				\
	int __event_filed[0];			\
	fields					\
} name;						\
typedef struct {				\
	detail_event_t event;			\
	int __event_filed[0];			\
	fields					\
} detail_##name;				\
typedef struct {				\
	fields					\
} pure_##name;
#define event_field(type, name) type name;

DEFINE_EVENT(drop_event_t,
	event_field(u64, location)
	event_field(u32, reason)
)

DEFINE_EVENT(reset_event_t,
	event_field(unsigned char, state)
	event_field(u32, reason)
)

DEFINE_EVENT(nf_event_t,
	event_field(char, table[8])
	event_field(char, chain[8])
	event_field(u8, hook)
	event_field(u8, pf)
)

DEFINE_EVENT(nf_hooks_event_t,
	event_field(char, table[8])
	event_field(char, chain[8])
	event_field(u8, hook)
	event_field(u8, pf)
	event_field(u64, hooks[6])
)

DEFINE_EVENT(qdisc_event_t,
	event_field(u64, last_update)
	event_field(u32, state)
	event_field(u32, qlen)
	event_field(u32, flags)
)

DEFINE_EVENT(rtt_event_t,
	event_field(u32, first_rtt)
	event_field(u32, last_rtt)
)

#define MAX_EVENT_SIZE sizeof(detail_nf_hooks_event_t)

typedef struct __attribute__((__packed__)) {
	u16 meta;
	u16 func;
	u32 pid;
	u64 ts;
	u64 val;
} retevent_t;

typedef enum trace_mode {
	TRACE_MODE_BASIC,
	TRACE_MODE_DROP,
	TRACE_MODE_TIMELINE,
	TRACE_MODE_DIAG,
	TRACE_MODE_SOCK,
	TRACE_MODE_MONITOR,
	TRACE_MODE_RTT,
	TRACE_MODE_LATENCY,
	/* following is some fake mode */
	TRACE_MODE_TINY = 16,
} trace_mode_t;

enum rule_type {
	/* equal */
	RULE_RETURN_EQ = 1,
	/* not equal */
	RULE_RETURN_NE,
	/* less than */
	RULE_RETURN_LT,
	/* greater then */
	RULE_RETURN_GT,
	/* in range */
	RULE_RETURN_RANGE,
	/* always active this rule */
	RULE_RETURN_ANY,
};

#define MAX_RULE_COUNT	8
typedef struct {
	int expected[MAX_RULE_COUNT];
	int op[MAX_RULE_COUNT];
} rules_ret_t;

#define TRACE_MODE_BASIC_MASK		(1 << TRACE_MODE_BASIC)
#define TRACE_MODE_TIMELINE_MASK	(1 << TRACE_MODE_TIMELINE)
#define TRACE_MODE_DIAG_MASK		(1 << TRACE_MODE_DIAG)
#define TRACE_MODE_DROP_MASK		(1 << TRACE_MODE_DROP)
#define TRACE_MODE_SOCK_MASK		(1 << TRACE_MODE_SOCK)
#define TRACE_MODE_MONITOR_MASK		(1 << TRACE_MODE_MONITOR)
#define TRACE_MODE_RTT_MASK		(1 << TRACE_MODE_RTT)
#define TRACE_MODE_LATENCY_MASK		(1 << TRACE_MODE_LATENCY)
#define TRACE_MODE_TINY_MASK		(1 << TRACE_MODE_TINY)

#define TRACE_MODE_SKB_REQUIRE_MASK				\
	(TRACE_MODE_BASIC_MASK | TRACE_MODE_TIMELINE_MASK |	\
	 TRACE_MODE_DIAG_MASK | TRACE_MODE_DROP_MASK |		\
	 TRACE_MODE_RTT_MASK | TRACE_MODE_LATENCY_MASK)
#define TRACE_MODE_SOCK_REQUIRE_MASK	TRACE_MODE_SOCK_MASK
#define TRACE_MODE_ALL_MASK					\
	(TRACE_MODE_SKB_REQUIRE_MASK | TRACE_MODE_MONITOR_MASK |\
	 TRACE_MODE_SOCK_REQUIRE_MASK)
#define TRACE_MODE_BPF_CTX_MASK		\
	(TRACE_MODE_DIAG_MASK | TRACE_MODE_TIMELINE_MASK |	\
	 TRACE_MODE_LATENCY_MASK)
#define TRACE_MODE_CTX_MASK		\
	(TRACE_MODE_DIAG_MASK | TRACE_MODE_TIMELINE_MASK)

#define __MACRO_SIZE(macro)	sizeof(#macro)
#define MACRO_SIZE(macro)	__MACRO_SIZE(macro)
#define __MACRO_CONCAT(a, b)	a##b
#define MACRO_CONCAT(a, b)	__MACRO_CONCAT(a, b)

#define TRACE_PREFIX		__trace_
#define TRACE_RET_PREFIX	ret__trace_
#define TRACE_PREFIX_LEN	MACRO_SIZE(TRACE_PREFIX)
#define TRACE_NAME(name)	MACRO_CONCAT(TRACE_PREFIX, name)
#define TRACE_RET_NAME(name)	MACRO_CONCAT(TRACE_RET_PREFIX, name)

#if defined(__F_NO_SK_FLAGS_OFFSET) && defined(__F_SK_PRPTOCOL_LEGACY)
#define __F_DISABLE_SOCK
#endif

#ifdef INLINE_MODE
#define __F_INIT_EVENT
#endif

#endif
