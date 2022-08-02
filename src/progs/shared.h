#ifndef _H_PROGS_SHARED
#define _H_PROGS_SHARED

#include <packet.h>

typedef struct __attribute__((__packed__)) {
	packet_t	pkt;
	u64		key;
	u32		func;
} event_t;

typedef struct __attribute__((__packed__)) {
	packet_t	pkt;
	u64		key;
	u32		func;
	u32		pid;
	char		task[16];
	char		ifname[16];
	u32		ifindex;
} detail_event_t;

typedef struct __attribute__((__packed__)) {
	union {
		detail_event_t detail_event;
		event_t	event;
	};
	u64	location;
	u32	reason;
} drop_event_t;

typedef struct __attribute__((__packed__)) {
	union {
		detail_event_t detail_event;
		event_t	event;
	};
	char table[8];
	char chain[8];
	u8 hook;
	u8 pf;
} nf_event_t;

typedef struct __attribute__((__packed__)) {
	union {
		detail_event_t detail_event;
		event_t	event;
	};
	char table[8];
	char chain[8];
	u8 hook;
	u8 pf;
	u64 hooks[8];
} nf_hooks_event_t;

#define MAX_EVENT_SIZE sizeof(nf_hooks_event_t)

typedef struct __attribute__((__packed__)) {
	u64 ts;
	u64 val;
	u16 func;
} retevent_t;

typedef enum trace_mode {
	TRACE_MODE_BASIC,
	TRACE_MODE_TIMELINE,
	TRACE_MODE_INETL,
} trace_mode_t;

typedef struct bpf_args {
	pkt_args_t pkt;
	u32  trace_mode;
	u32  pid;
	bool enable_trace_mode;
	bool enable_pid;
	bool drop_reason;
	bool detail;
	bool hooks;
	bool ready;
} bpf_args_t;

#endif
