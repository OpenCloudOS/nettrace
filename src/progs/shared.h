#ifndef _H_PROGS_SHARED
#define _H_PROGS_SHARED

#define MAX_FUNC_STACK 16

#define DEFINE_BPF_ARGS()		\
	DEFINE_FIELD(u32, trace_mode)	\
	DEFINE_FIELD(u32, pid)		\
	u32  netns;			\
	bool drop_reason;		\
	bool detail;			\
	bool hooks;			\
	bool ready;			\
	bool stack;			\
	bool pkt_fixed;			\
	u16  stack_funs[MAX_FUNC_STACK];

#include <skb_shared.h>

typedef struct {
	union {
		packet_t	pkt;
		sock_t		ske;
	};
	u64		key;
	u64		retval;
	u32		func;
#ifdef BPF_FEAT_STACK_TRACE
	u32		stack_id;
#endif
	int		__event_filed[0];
} event_t;

typedef struct {
	union {
		packet_t	pkt;
		sock_t		ske;
	};
	u64		key;
	u64		retval;
	u32		func;
#ifdef BPF_FEAT_STACK_TRACE
	u32		stack_id;
#endif
	u32		pid;
	char		task[16];
	char		ifname[16];
	u32		ifindex;
	u32		netns;
	int		__event_filed[0];
} detail_event_t;

typedef struct {
} pure_event_t;

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

#define MAX_EVENT_SIZE sizeof(detail_nf_hooks_event_t)

typedef struct __attribute__((__packed__)) {
	u64 ts;
	u64 val;
	u16 func;
} retevent_t;

typedef enum trace_mode {
	TRACE_MODE_BASIC,
	TRACE_MODE_DROP,
	TRACE_MODE_TIMELINE,
	TRACE_MODE_DIAG,
	TRACE_MODE_SOCK,
	TRACE_MODE_MONITOR,
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
#define TRACE_MODE_SKB_MASK		\
	(TRACE_MODE_BASIC_MASK | TRACE_MODE_TIMELINE_MASK |	\
	 TRACE_MODE_DIAG_MASK | TRACE_MODE_DROP_MASK |		\
	 TRACE_MODE_MONITOR_MASK)
#define TRACE_MODE_ALL_MASK		\
	(TRACE_MODE_SKB_MASK | TRACE_MODE_SOCK_MASK)
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

#endif
