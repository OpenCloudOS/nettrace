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

struct bpf_args;
#ifdef MAP_CONFIG
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, CONFIG_MAP_SIZE);
	__uint(max_entries, 1);
} m_config SEC(".maps");

#define CONFIG() ({						\
	int _key = 0;						\
	void * _v = bpf_map_lookup_elem(&m_config, &_key);	\
	if (!_v)						\
		return 0; /* this can't happen */		\
	(struct bpf_args*)_v;					\
})

#define try_inline __attribute__((always_inline))
#else
extern struct bpf_args _bpf_args;
#define CONFIG() &_bpf_args
#define try_inline inline
#endif

#define ARGS_INIT()		bpf_args_t *bpf_args = CONFIG();
#define ARGS_PKT()		(&bpf_args->pkt)

#define ARGS_ENABLED(name)	bpf_args->enable_##name
#define ARGS_GET(name)		bpf_args->name
#define ARGS_GET_CONFIG(name)	((struct bpf_args *)CONFIG())->name
#define ARGS_CHECK(name, val)	\
	(ARGS_ENABLED(name) && bpf_args->name != (val))

typedef struct {
	u64 pad;
	u64 skb;
	u64 location;
	u16 prot;
	u32 reason;
} kfree_skb_t;

typedef struct {
	void *data;
	struct sk_buff *skb;
	pkt_args_t *args;
	packet_t *pkt;
	bool filter;
	u16 mac_header;
	u16 network_header;
	u16 trans_header;
} parse_ctx_t;

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


static try_inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0xF0) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}

static try_inline void *load_l4_hdr(struct __sk_buff *skb, struct iphdr *ip,
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

static try_inline bool skb_l2_check(u16 header)
{
	return !header || header == (u16)~0U;
}

static try_inline bool skb_l4_check(u16 l4, u16 l3)
{
	return l4 == 0xFFFF || l4 <= l3;
}

#define CHECK_ATTR(attr)			\
	((ARGS_CHECK(attr, d##attr) &&		\
	  ARGS_CHECK(attr, s##attr)) ||		\
	 ARGS_CHECK(s##attr, s##attr) ||	\
	 ARGS_CHECK(d##attr, d##attr))

static try_inline int probe_parse_ip(void *ip, parse_ctx_t *ctx)
{
	pkt_args_t *bpf_args = ctx->args;
	bool filter = ctx->filter;
	packet_t *pkt = ctx->pkt;
	void *l4 = NULL;

	if (!skb_l4_check(ctx->trans_header, ctx->network_header))
		l4 = ctx->data + ctx->trans_header;

	if (pkt->proto_l3 == ETH_P_IPV6) {
		struct ipv6hdr *ipv6 = ip;

		pkt->proto_l4 = _(ipv6->nexthdr);
		l4 = l4 ?: ip + sizeof(*ipv6);

		bpf_probe_read_kernel(pkt->l3.ipv6.saddr,
				      sizeof(ipv6->saddr),
				      &ipv6->saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr,
				      sizeof(ipv6->daddr),
				      &ipv6->daddr);
	} else {
		struct iphdr *ipv4 = ip;
		u32 saddr = _(ipv4->saddr);
		u32 daddr = _(ipv4->daddr);

		if (filter && CHECK_ATTR(addr))
			return -1;

		l4 = l4 ?: ip + get_ip_header_len(_(((u8 *)ip)[0]));

		pkt->proto_l4 = _(ipv4->protocol);
		pkt->l3.ipv4.saddr = saddr;
		pkt->l3.ipv4.daddr = daddr;
	}

	if (filter && ARGS_CHECK(l4_proto, pkt->proto_l4))
		return -1;

	bool port_filter = ARGS_ENABLED(sport) || ARGS_ENABLED(dport) ||
			   ARGS_ENABLED(port);

	switch (pkt->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);

		if (filter && CHECK_ATTR(port))
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
	
		if (filter && CHECK_ATTR(port))
			return -1;

		pkt->l4.udp.sport = sport;
		pkt->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;

		if (filter && port_filter)
			return -1;
		pkt->l4.icmp.code = _(icmp->code);
		pkt->l4.icmp.type = _(icmp->type);
		pkt->l4.icmp.seq = _(icmp->un.echo.sequence);
		pkt->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	default:
		if (filter && port_filter)
			return -1;
	}
	return 0;
}

static try_inline int probe_parse_skb_cond(parse_ctx_t *ctx)
{
	pkt_args_t *bpf_args = ctx->args;
	struct sk_buff *skb = ctx->skb;
	bool filter = ctx->filter;
	packet_t *pkt = ctx->pkt;
	u16 l3_proto;
	void *l3;

	ctx->network_header = _(skb->network_header);
	ctx->mac_header = _(skb->mac_header);
	ctx->data = _(skb->head);

	if (skb_l2_check(ctx->mac_header)) {
		/*
		 * try to parse skb for send path, which means that
		 * ether header doesn't exist in skb.
		 */
		l3_proto = bpf_ntohs(_(skb->protocol));
		if (!l3_proto)
			return -1;
		if (!ctx->network_header)
			return -1;
		l3 = ctx->data + ctx->network_header;
	} else if (ctx->mac_header == ctx->network_header) {
		/* to tun device, mac header is the same to network header.
		 * For this case, we assume that this is a IP packet.
		 */
		l3 = ctx->data + ctx->network_header;
		l3_proto = ETH_P_IP;
	} else {
		/* mac header is set properly, we can use it directly. */
		struct ethhdr *eth = ctx->data + ctx->mac_header;

		l3 = (void *)eth + ETH_HLEN;
		l3_proto = bpf_ntohs(_(eth->h_proto));
	}

	if (filter && ARGS_CHECK(l3_proto, l3_proto))
		return -1;

	ctx->trans_header = _(skb->transport_header);
	pkt->proto_l3 = l3_proto;

	switch (l3_proto) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		return probe_parse_ip(l3, ctx);
	default:
		if (filter && ARGS_ENABLED(l4_proto))
			return -1;
		return 0;
	}
}

static try_inline int probe_parse_skb(struct sk_buff *skb, packet_t *pkt)
{
	parse_ctx_t ctx = {
		.args = (void *)CONFIG(),
		.filter = true,
		.skb = skb,
		.pkt = pkt,
	};
	return probe_parse_skb_cond(&ctx);
}

static try_inline int probe_parse_skb_no_filter(struct sk_buff *skb,
					    packet_t *pkt)
{
	parse_ctx_t ctx = {
		.args = (void *)CONFIG(),
		.filter = false,
		.skb = skb,
		.pkt = pkt,
	};
	return probe_parse_skb_cond(&ctx);
}

static try_inline int direct_parse_skb(struct __sk_buff *skb, packet_t *pkt,
				       pkt_args_t *bpf_args)
{
	struct ethhdr *eth = SKB_DATA(skb);
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)ip > SKB_END(skb))
		goto err;

	if (bpf_args && (ARGS_CHECK(l3_proto, eth->h_proto)))
		goto err;

	pkt->proto_l3 = bpf_ntohs(eth->h_proto);
	if (SKB_CHECK_IP(skb))
		goto err;

	if (bpf_args && (ARGS_CHECK(l4_proto, ip->protocol) ||
		       ARGS_CHECK(saddr, ip->saddr) ||
		       ARGS_CHECK(daddr, ip->daddr)))
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

	if (bpf_args && (ARGS_CHECK(sport, l4_p->sport) ||
		       ARGS_CHECK(dport, l4_p->dport)))
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