/* 
 * This file define the struct that we use both in BPF and use space, such
 * as the perf event data.
 */
#ifndef _H_BPF_SKB_SHARED
#define _H_BPF_SKB_SHARED

#define nt_take_2th(ignored, a, ...)	a
#define nt_take_3th(ignored, a, b, ...)	b

#define __nt_placehold_arg_1		1,
#define ____nt_ternary_take(a, b, c)	nt_take_2th(a b, c)
#define __nt_ternary_take(a, b, c)	\
	____nt_ternary_take(__nt_placehold_arg_##a, b, c)

/* take b if a is 1; else, take c */
#define nt_ternary_take(a, b, c) __nt_ternary_take(a, b, c)

typedef struct {
	u16	sport;
	u16	dport;
} l4_min_t;

typedef struct __attribute__((__packed__)) {
	u64	ts;
	union {
		struct {
			u32	saddr;
			u32	daddr;
		} ipv4;
		struct {
			u8	saddr[16];
			u8	daddr[16];
		} ipv6;
	} l3;
	union {
		struct {
			u16	sport;
			u16	dport;
			u32	seq;
			u32	ack;
			u8	flags;
		} tcp;
		struct {
			u16	sport;
			u16	dport;
		} udp;
		l4_min_t min;
		struct {
			u8	type;
			u8	code;
			u16	seq;
			u16	id;
		} icmp;
		struct {
			u16	op;
		} arp_ext;
		struct
        	{
                	u32 spi;
                	u32 seq;
        	} espheader;
#define field_udp l4.udp
	} l4;
	u16 proto_l3;
	u8 proto_l4;
	u8 pad;
} packet_t;

#define TCP_FLAGS_ACK	(1 << 4)
#define TCP_FLAGS_PSH	(1 << 3)
#define TCP_FLAGS_RST	(1 << 2)
#define TCP_FLAGS_SYN	(1 << 1)

#define DEFINE_FIELD_STD(type, name)		\
	type name;				\
	bool enable_##name;
#define DEFINE_FIELD_ARRAY(type, name, size)	\
	type name[size];			\
	bool enable_##name;
#define DEFINE_FIELD(type, name, args...)		\
	nt_take_3th(dummy, ##args, DEFINE_FIELD_ARRAY,	\
		    DEFINE_FIELD_STD)(type, name, ##args)

/* used for packet filter condition */
typedef struct {
	DEFINE_FIELD(u32, saddr)
	DEFINE_FIELD(u32, daddr)
	DEFINE_FIELD(u32, addr)
	DEFINE_FIELD(u8, saddr_v6, 16)
	DEFINE_FIELD(u8, daddr_v6, 16)
	DEFINE_FIELD(u8, addr_v6, 16)
	DEFINE_FIELD(u16, sport)
	DEFINE_FIELD(u16, dport)
	DEFINE_FIELD(u16, port)
	DEFINE_FIELD(u16, l3_proto)
	DEFINE_FIELD(u8, l4_proto)
} pkt_args_t;

#define CONFIG_MAP_SIZE	1024

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif
typedef __u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

#endif
