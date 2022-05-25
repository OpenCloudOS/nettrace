#ifndef _H_BPF_PACKET
#define _H_BPF_PACKET

typedef struct {
	u16	sport;
	u16	dport;
} l4_min_t;

typedef struct {
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
#define field_sport	field_tcp.sport
#define field_dport	field_tcp.dport
#define field_flags	field_tcp.flags
#define field_tcp	l4.tcp
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

#endif
