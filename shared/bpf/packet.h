#ifndef _H_BPF_PACKET
#define _H_BPF_PACKET

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

typedef struct {
	u32	saddr;
	bool	enable_saddr;
	u32	daddr;
	bool	enable_daddr;
	u32	addr;
	bool	enable_addr;
	u16	sport;
	bool	enable_sport;
	u16	dport;
	bool	enable_dport;
	u16	port;
	bool	enable_port;
	u16	l3_proto;
	bool	enable_l3_proto;
	u8	l4_proto;
	bool	enable_l4_proto;
} pkt_args_t;

#define CONFIG_MAP_SIZE	1024

#endif
