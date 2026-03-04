#ifndef _H_PROGS_SHARED
#define _H_PROGS_SHARED

#define MAX_FUNC_STACK 16

#include "skb_shared.h"
#include "trace_funcs.h"

#define BPF_FUNC_nt_get_func_index 0x0FFF
#define BPF_FUNC_nt_get_skb 0x0FFE
#define BPF_FUNC_nt_get_sk 0x0FFD

/* The read only fields for BPF prog */
typedef struct {
	pkt_args_t pkt;
	u32  trace_mode;
	u32  pid;
	u32  netns;
	u32  max_event;
	bool drop_reason;
	bool detail;
	bool hooks;
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
	u8   trace_flags[TRACE_MAX];
} bpf_args_t;

typedef struct {
	int  __rate_limit;
	u64  __last_update;
	u64  event_count;
	bool ready;
} bpf_data_t;

enum log_code {
	LOG_ALLOC_FAIL = 1,
};

#define LOG_MSG_LEN 128
typedef struct {
	u64 ts;
	u32 pid;
	u32 code;
	char msg[LOG_MSG_LEN];
} log_event_t;

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
	u32		stack_id;
	u32		pid;
	/* detail fields */
	char		task[16];
	char		ifname[16];
	u16		ifindex;
	u16		cpu;
	u32		netns;
} event_t;

typedef struct {
	u16 meta;
	u16 func;
	u32 key;
	u64 ts;
} tiny_event_t;

enum {
	FUNC_TYPE_FUNC,
	FUNC_TYPE_RET,
	FUNC_TYPE_TINY,
	FUNC_TYPE_MAX,
};


#define FUNC_FLAG_FREE		(1 << 0)
#define FUNC_FLAG_SK		(1 << 1) /* parse sk instead of skb */
#define FUNC_FLAG_RET		(1 << 2) /* fentry + fexit */
#define FUNC_FLAG_MATCHER	(1 << 3)
#define FUNC_FLAG_STACK		(1 << 4)
#define FUNC_FLAG_RET_ONLY	(1 << 5) /* fexit only, no fentry */
#define FUNC_FLAG_CFREE		(1 << 6) /* custom skb free function */
#define FUNC_FLAG_RULE		(1 << 7)

typedef struct {
	event_t event;
	u64 location;
	u32 reason;
} drop_event_t;

typedef struct {
	event_t event;
	unsigned char state;
	u32 reason;
} reset_event_t;

typedef struct {
	event_t event;
	char table[8];
	char chain[8];
	u8 hook;
	u8 pf;
} nf_event_t;

typedef struct {
	event_t event;
	char table[8];
	char chain[8];
	u8 hook;
	u8 pf;
	u64 hooks[6];
} nf_hooks_event_t;

typedef struct {
	event_t event;
	u64 last_update;
	u32 state;
	u32 qlen;
	u32 flags;
} qdisc_event_t;

typedef struct {
	event_t event;
	u32 first_rtt;
	u32 last_rtt;
} rtt_event_t;

#define MAX_EVENT_SIZE sizeof(nf_hooks_event_t)

typedef struct {
	u16 meta;
	u16 func;
	/* for now, the low 4-bytes of skb is the key */
	u32 key;
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
#define MAX_STATS_BUCKETS 17
#define LAST_STATS_BUCKET (MAX_STATS_BUCKETS - 1)
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

#define TRACE_PREFIX		nt__
#define TRACE_RET_PREFIX	nt_ret__
#define TRACE_PREFIX_LEN	MACRO_SIZE(TRACE_PREFIX)
#define TRACE_NAME(name)	MACRO_CONCAT(TRACE_PREFIX, name)
#define TRACE_RET_NAME(name)	MACRO_CONCAT(TRACE_RET_PREFIX, name)

#if defined(__F_NO_SK_FLAGS_OFFSET) && defined(__F_SK_PRPTOCOL_LEGACY)
#define __F_DISABLE_SOCK
#endif

#endif
