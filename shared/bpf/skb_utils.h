#ifndef _H_BPF_SKB_UTILS
#define _H_BPF_SKB_UTILS

#include "macro.h"
#include "packet.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 64);
} m_event SEC(".maps");

#define EVENT_OUTPUT(ctx, data)					\
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,	\
			      &(data), sizeof(data))

#define _(P)						\
({							\
	typeof(P) tmp;					\
	bpf_probe_read_kernel(&tmp, sizeof(P), &(P));	\
	tmp;						\
})

#ifndef CONFIG_NO_FILTER
#define PARAM_DEFINE(type, name, default)	\
	const volatile type arg_##name = default
#define PARAM_DEFINE_ENABLE(type, name)		\
	PARAM_DEFINE(type, name, 0);		\
	const volatile bool enable_##name = false
#define PARAM_DEFINE_UINT(type, name)		\
	PARAM_DEFINE_ENABLE(type, name)
#define PARAM_DEFINE_BOOL(name, default)	\
	PARAM_DEFINE(bool, name, default)
#define PARAM_ENABLED(name)			\
	(enable_##name)
#define PARAM_CHECK_ENABLE(name, val)		\
	(PARAM_ENABLED(name) && arg_##name != (val))
#define PARAM_CHECK_BOOL(name)			\
	(arg_##name)

PARAM_DEFINE_UINT(u32, saddr);
PARAM_DEFINE_UINT(u32, daddr);
PARAM_DEFINE_UINT(u32, addr);
PARAM_DEFINE_UINT(u16, sport);
PARAM_DEFINE_UINT(u16, dport);
PARAM_DEFINE_UINT(u16, port);
PARAM_DEFINE_UINT(u16, l3_proto);
PARAM_DEFINE_UINT(u8,  l4_proto);
#else
#define PARAM_CHECK_ENABLE(name, val)		\
	(1)
#define PARAM_CHECK_BOOL(name)			\
	(1)
#endif

typedef struct {
	u64 pad;
	u64 skb;
	u64 location;
	u16 prot;
	u32 reason;
} kfree_skb_t;

#define TCP_H_LEN	(sizeof(struct tcphdr))
#define UDP_H_LEN	(sizeof(struct udphdr))
#define IP_H_LEN	(sizeof(struct iphdr))
#define ICMP_H_LEN	(sizeof(struct icmphdr))

#define ETH_TOTAL_H_LEN		(sizeof(struct ethhdr))
#define IP_TOTAL_H_LEN		(ETH_TOTAL_H_LEN + IP_H_LEN)
#define TCP_TOTAL_H_LEN		(IP_TOTAL_H_LEN + TCP_H_LEN)
#define UDP_TOTAL_H_LEN		(IP_TOTAL_H_LEN + UDP_H_LEN)
#define ICMP_TOTAL_H_LEN	(IP_TOTAL_H_LEN + ICMP_H_LEN)

#define IP_CSUM_OFFSET	(ETH_TOTAL_H_LEN + offsetof(struct iphdr, check))

#define SKB_END(skb)	((void *)(long)skb->data_end)
#define SKB_DATA(skb)	((void *)(long)skb->data)
#define SKB_CHECK_IP(skb)	\
	(SKB_DATA(skb) + IP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_CHECK_TCP(skb)	\
	(SKB_DATA(skb) + TCP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_CHECK_UDP(skb)	\
	(SKB_DATA(skb) + UDP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_CHECK_ICMP(skb)	\
	(SKB_DATA(skb) + ICMP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_HDR_IP(skb)		\
	(SKB_DATA(skb) + ETH_TOTAL_H_LEN)

#define IS_PSEUDO 0x10


static __always_inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0xF0) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}

static inline void *load_l4_hdr(struct __sk_buff *skb, struct iphdr *ip,
			        void *dst, __u32 len)
{
	__u32 offset, iplen;
	void *l4;

	iplen = get_ip_header_len(((u8 *)ip)[0]);
	offset = ETH_TOTAL_H_LEN + (iplen > IP_H_LEN ? iplen: IP_H_LEN);
	l4 = SKB_DATA(skb) + offset;

	if (l4 + len > SKB_END(skb)) {
		if (bpf_skb_load_bytes(skb, offset, dst, len))
			return NULL;
		return dst;
	}
	return l4;
}

static inline void *get_l2(struct sk_buff *skb)
{
	u16 mh = _(skb->mac_header);
	if (mh != (u16)~0U && mh)
		return _(skb->head) + mh;
	else
		return NULL;
}

static inline void *get_l3(struct sk_buff *skb)
{
	if (_(skb->network_header) > _(skb->mac_header))
		return _(skb->head) + _(skb->network_header);
	else if (get_l2(skb))
		return get_l2(skb) + ETH_HLEN;
	else
		return NULL;
}

static inline void *get_l3_send(struct sk_buff *skb)
{
	if (_(skb->network_header))
		return _(skb->head) + _(skb->network_header);
	else
		return NULL;
}

static inline bool skb_l4_was_set(const struct sk_buff *skb)
{
	return _(skb->transport_header) != 0xFFFF &&
	       _(skb->transport_header) > _(skb->network_header);
}

static inline void *get_l4(struct sk_buff *skb)
{
	if (skb_l4_was_set(skb))
		return _(skb->head) + _(skb->transport_header);
	void *ip = get_l3(skb);
	if (!ip)
		return NULL;
	return ip + get_ip_header_len(_(((u8 *)ip)[0]));
}

#ifdef FEATURE_DIRECT_ACCESS
static inline int probe_parse_ip(struct sk_buff *skb, event_t *event, bool ipv4)
{
	void *l3 = get_l3(skb);

#define CHECK_ATTR(attr)				\
	(PARAM_CHECK_ENABLE(s##attr, s##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, s##attr) ||		\
	 PARAM_CHECK_ENABLE(d##attr, d##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, d##attr))

	if (!ipv4) {
		struct ipv6hdr *ipv6 = l3;
		event->proto_l4 = _(ipv6->nexthdr);
		bpf_probe_read_kernel(event->l3.ipv6.saddr,
				      sizeof(ipv6->saddr),
				      &ipv6->saddr);
		bpf_probe_read_kernel(event->l3.ipv6.daddr,
				      sizeof(ipv6->daddr),
				      &ipv6->daddr);
	} else {
		struct iphdr *ip = l3;
		u32 saddr = _(ip->saddr);
		u32 daddr = _(ip->daddr);

		if (CHECK_ATTR(addr))
			return -1;

		event->proto_l4	= _(ip->protocol);
		event->l3.ipv4.saddr = saddr;
		event->l3.ipv4.daddr = daddr;
	}

	if (PARAM_CHECK_ENABLE(l4_proto, event->proto_l4))
		return -1;

	void *l4 = get_l4(skb);
	switch (event->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);

		if (CHECK_ATTR(port))
			return -1;

		event->l4.tcp.sport = sport;
		event->l4.tcp.dport = dport;
		event->l4.tcp.flags = _(((u8 *)tcp)[13]);
		event->l4.tcp.seq = _(tcp->seq);
		event->l4.tcp.ack = _(tcp->ack_seq);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);
	
		if (CHECK_ATTR(port))
			return -1;

		event->l4.udp.sport = sport;
		event->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;
		event->l4.icmp.code = _(icmp->code);
		event->l4.icmp.type = _(icmp->type);
		event->l4.icmp.seq = _(icmp->un.echo.sequence);
		event->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	}
	return 0;
}
#else
static inline int probe_parse_ip(struct sk_buff *skb, packet_t *pkt, bool ipv4)
{
	void *l3 = get_l3(skb);

#define CHECK_ATTR(attr)				\
	(PARAM_CHECK_ENABLE(s##attr, s##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, s##attr) ||		\
	 PARAM_CHECK_ENABLE(d##attr, d##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, d##attr))

	if (!ipv4) {
		struct ipv6hdr *ipv6 = l3;
		pkt->proto_l4 = _(ipv6->nexthdr);
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr,
				      sizeof(ipv6->saddr),
				      &ipv6->saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr,
				      sizeof(ipv6->daddr),
				      &ipv6->daddr);
	} else {
		struct iphdr *ip = l3;
		u32 saddr = _(ip->saddr);
		u32 daddr = _(ip->daddr);

		if (CHECK_ATTR(addr))
			return -1;

		pkt->proto_l4	= _(ip->protocol);
		pkt->l3.ipv4.saddr = saddr;
		pkt->l3.ipv4.daddr = daddr;
	}

	if (PARAM_CHECK_ENABLE(l4_proto, pkt->proto_l4))
		return -1;

	bool port_filter = PARAM_ENABLED(sport) || PARAM_ENABLED(dport) ||
			   PARAM_ENABLED(port);
	void *l4 = get_l4(skb);

	switch (pkt->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);

		if (CHECK_ATTR(port))
			return -1;

		pkt->l4.tcp.sport = sport;
		pkt->l4.tcp.dport = dport;
		pkt->l4.tcp.flags = _(((u8 *)tcp)[13]);
		pkt->l4.tcp.seq = _(tcp->seq);
		pkt->l4.tcp.ack = _(tcp->ack_seq);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);
	
		if (CHECK_ATTR(port))
			return -1;

		pkt->l4.udp.sport = sport;
		pkt->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;

		if (port_filter)
			return -1;
		pkt->l4.icmp.code = _(icmp->code);
		pkt->l4.icmp.type = _(icmp->type);
		pkt->l4.icmp.seq = _(icmp->un.echo.sequence);
		pkt->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	default:
		if (port_filter)
			return -1;
	}
	return 0;
}
#endif

static inline int probe_parse_skb(struct sk_buff *skb, packet_t *pkt)
{
	struct ethhdr *eth = get_l2(skb);

	if (!eth)
		return -1;

	u16 l3 = bpf_ntohs(_(eth->h_proto));
	if (PARAM_CHECK_ENABLE(l3_proto, l3))
		return -1;

	pkt->proto_l3 = l3;
	switch (l3) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		return probe_parse_ip(skb, pkt, l3 == ETH_P_IP);
	default:
		if (PARAM_ENABLED(l4_proto))
			return -1;
		return 0;
	}
}

static inline int direct_parse_skb(struct __sk_buff *skb, packet_t *pkt,
				bool filter)
{
	struct ethhdr *eth = SKB_DATA(skb);
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)ip > SKB_END(skb))
		goto err;

	if (filter && (PARAM_CHECK_ENABLE(l3_proto, eth->h_proto)))
		goto err;

	pkt->proto_l3 = bpf_ntohs(eth->h_proto);
	if (SKB_CHECK_IP(skb))
		goto err;

	if (filter && (PARAM_CHECK_ENABLE(l4_proto, ip->protocol) ||
		       PARAM_CHECK_ENABLE(saddr, ip->saddr) ||
		       PARAM_CHECK_ENABLE(daddr, ip->daddr)))
		goto err;

	l4_min_t *l4_p = (void *)(ip + 1);
	struct tcphdr *tcp = (void *)l4_p;

	switch (ip->protocol) {
	case IPPROTO_UDP:
		if (SKB_CHECK_UDP(skb))
			goto err;
		goto fill_port;
	case IPPROTO_TCP:
		if (SKB_CHECK_TCP(skb))
			goto err;

		pkt->l4.tcp.flags = ((u8 *)tcp)[13];
		pkt->l4.tcp.ack = tcp->ack_seq;
		pkt->l4.tcp.seq = tcp->seq;
fill_port:
		pkt->l4.min = *l4_p;
		break;
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = (void *)l4_p;
		if (SKB_CHECK_ICMP(skb))
			goto err;

		pkt->l4.icmp.code = icmp->code;
		pkt->l4.icmp.type = icmp->type;
		pkt->l4.icmp.seq = icmp->un.echo.sequence;
		pkt->l4.icmp.id = icmp->un.echo.id;
	}
	default:
		goto out;
	}

	if (filter && (PARAM_CHECK_ENABLE(sport, l4_p->sport) ||
		       PARAM_CHECK_ENABLE(dport, l4_p->dport)))
		return 1;

	pkt->l3.ipv4.saddr = ip->saddr;
	pkt->l3.ipv4.daddr = ip->daddr;
	pkt->proto_l4 = ip->protocol;
	pkt->proto_l3 = ETH_P_IP;
	pkt->ts = bpf_ktime_get_ns();

out:
	return 0;
err:
	return 1;
}

#endif