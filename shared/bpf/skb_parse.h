/* 
 * The common part of parse skb and filter skb by specified condition.
 *
 * NOTE: This file can only be used in BPF program, can't be used in user
 * space code.
 */
#ifndef _H_BPF_SKB_UTILS
#define _H_BPF_SKB_UTILS

#ifndef NO_BTF
#include <bpf/bpf_core_read.h>
#endif

#include "skb_macro.h"
#include "skb_shared.h"


#define MAX_ENTRIES 256

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_ENTRIES);
} m_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, CONFIG_MAP_SIZE);
	__uint(max_entries, 1);
} m_config SEC(".maps");

#ifndef BPF_NO_GLOBAL_DATA
const volatile bool bpf_func_exist[BPF_LOCAL_FUNC_MAX] = {0};

/* TRACING is not supported by libbpf_probe_bpf_helper, so fallback with the
 * CO-RE checking.
 */
#ifdef __PROG_TYPE_TRACING
#define bpf_core_helper_exist(name) \
	bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_##name)
#else
#define bpf_core_helper_exist(name) bpf_func_exist[BPF_LOCAL_FUNC_##name]
#endif
#else
#define bpf_core_helper_exist(name) false
#endif

#define CONFIG() ({						\
	int _key = 0;						\
	void * _v = bpf_map_lookup_elem(&m_config, &_key);	\
	if (!_v)						\
		return 0; /* this can't happen */		\
	(pkt_args_t *)_v;					\
})

#define EVENT_OUTPUT_PTR(ctx, data, size)			\
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,	\
			      data, size)
#define EVENT_OUTPUT(ctx, data)					\
	EVENT_OUTPUT_PTR(ctx, &data, sizeof(data))

#define _(src)							\
({								\
	typeof(src) tmp;					\
	bpf_probe_read_kernel(&tmp, sizeof(src), &(src));	\
	tmp;							\
})

#undef _C
#ifdef NO_BTF
#define _C(src, a)	_((src)->a)
#else
#define _C(src, a, ...)		BPF_CORE_READ(src, a, ##__VA_ARGS__)
#endif

#ifdef INLINE_MODE
#undef inline
#define inline inline __attribute__((always_inline))
#define auto_inline inline
#else
#define auto_inline
#endif

#ifdef BPF_DEBUG
#define pr_bpf_debug(fmt, args...) {				\
	if (CONFIG()->bpf_debug)				\
		bpf_printk("nettrace: "fmt"\n", ##args);	\
}
#else
#define pr_bpf_debug(fmt, ...)
#endif
#define pr_debug_skb(fmt, ...)	\
	pr_bpf_debug("skb=%llx, "fmt, (u64)(void *)skb, ##__VA_ARGS__)

typedef struct {
	u64 pad;
	u64 skb;
	u64 location;
	u16 prot;
	u32 reason;
} kfree_skb_t;

typedef struct {
	void *data;
	pkt_args_t *args;
	union {
		struct sk_buff *skb;
		struct sock *sk;
	};
	union {
		packet_t *pkt;
		sock_t *ske;
	};
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


static inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0x0F) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}

static inline
void *load_l4_hdr(struct __sk_buff *skb, struct iphdr *ip, void *dst,
		  __u32 len)
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

/* check if the skb contains L2 head (mac head) */
static inline bool skb_l2_check(u16 header)
{
	return !header || header == (u16)~0U;
}

static inline bool skb_l4_check(u16 l4, u16 l3)
{
	return l4 == 0xFFFF || l4 <= l3;
}

/* used to do basic filter */
#define filter_enabled(args, attr)					\
	(args && args->attr)
#define filter_check(args, attr, value)					\
	(filter_enabled(args, attr) && args->attr != value)
#define filter_any_enabled(args, attr)					\
	(args && (args->attr || args->s##attr ||	\
		       args->d##attr))

static inline bool is_ipv6_equal(void *addr1, void *addr2)
{
	return *(u64 *)addr1 == *(u64 *)addr2 &&
	       *(u64 *)(addr1 + 8) == *(u64 *)(addr2 + 8);
}

static inline int filter_ipv6_check(pkt_args_t *args, void *saddr, void *daddr)
{
	if (!args)
		return 0;

	return (args->saddr_v6_enable && !is_ipv6_equal(args->saddr_v6, saddr)) ||
	       (args->daddr_v6_enable && !is_ipv6_equal(args->daddr_v6, daddr)) ||
	       (args->addr_v6_enable && !is_ipv6_equal(args->addr_v6, daddr) &&
				 !is_ipv6_equal(args->addr_v6, saddr));
}

static inline int filter_ipv4_check(pkt_args_t *args, u32 saddr,
					u32 daddr)
{
	if (!args)
		return 0;

	return (args->saddr && args->saddr != saddr) ||
	       (args->daddr && args->daddr != daddr) ||
	       (args->addr && args->addr != daddr && args->addr != saddr);
}

static inline int filter_port(pkt_args_t *args, u32 sport, u32 dport)
{
	if (!args)
		return 0;

	return (args->sport && args->sport != sport) ||
	       (args->dport && args->dport != dport) ||
	       (args->port && args->port != dport && args->port != sport);
}

static inline int probe_parse_ip(void *ip, parse_ctx_t *ctx)
{
	pkt_args_t *args = ctx->args;
	packet_t *pkt = ctx->pkt;
	void *l4 = NULL;

	if (!skb_l4_check(ctx->trans_header, ctx->network_header))
		l4 = ctx->data + ctx->trans_header;

	if (pkt->proto_l3 == ETH_P_IPV6) {
		struct ipv6hdr *ipv6 = ip;

		/* ipv4 address is set, skip ipv6 */
		if (filter_any_enabled(args, addr))
			goto err;

#ifndef NT_DISABLE_IPV6
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr, 16, &ipv6->saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr, 16, &ipv6->daddr);
		if (filter_ipv6_check(args, pkt->l3.ipv6.saddr,
				      pkt->l3.ipv6.daddr))
			goto err;
#endif
		pkt->proto_l4 = _(ipv6->nexthdr);
		l4 = l4 ?: ip + sizeof(*ipv6);
	} else {
		struct iphdr *ipv4 = ip;
		u32 saddr, daddr, len;

		len = bpf_ntohs(_C(ipv4, tot_len));
		if (args && (args->pkt_len_1 || args->pkt_len_2)) {
			if (len < args->pkt_len_1 || len > args->pkt_len_2)
				goto err;
		}

		/* skip ipv4 if ipv6 is set */
		if (filter_any_enabled(args, addr_v6[0]))
			goto err;

		l4 = l4 ?: ip + get_ip_header_len(_(((u8 *)ip)[0]));
		saddr = _(ipv4->saddr);
		daddr = _(ipv4->daddr);

		if (filter_ipv4_check(args, saddr, daddr))
			goto err;

		pkt->proto_l4 = _(ipv4->protocol);
		pkt->l3.ipv4.saddr = saddr;
		pkt->l3.ipv4.daddr = daddr;
	}

	if (filter_check(args, l4_proto, pkt->proto_l4))
		goto err;

	switch (pkt->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);
		u8 flags;

		if (filter_port(args, sport, dport))
			goto err;

		flags = _(((u8 *)tcp)[13]);
		if (filter_enabled(args, tcp_flags) &&
		    !(flags & args->tcp_flags))
			goto err;

		pkt->l4.tcp.sport = sport;
		pkt->l4.tcp.dport = dport;
		pkt->l4.tcp.flags = flags;
		pkt->l4.tcp.seq = bpf_ntohl(_(tcp->seq));
		pkt->l4.tcp.ack = bpf_ntohl(_(tcp->ack_seq));
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);
	
		if (filter_port(args, sport, dport))
			goto err;

		pkt->l4.udp.sport = sport;
		pkt->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;

		if (filter_any_enabled(args, port))
			goto err;
		pkt->l4.icmp.code = _(icmp->code);
		pkt->l4.icmp.type = _(icmp->type);
		pkt->l4.icmp.seq = _(icmp->un.echo.sequence);
		pkt->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	case IPPROTO_ESP: {
		struct ip_esp_hdr *esp_hdr = l4;
		if (filter_any_enabled(args, port))
			goto err;
		pkt->l4.espheader.seq = _(esp_hdr->seq_no);
		pkt->l4.espheader.spi = _(esp_hdr->spi);
		break;
	}
	default:
		if (filter_any_enabled(args, port))
			goto err;
	}
	return 0;
err:
	return -1;
}

#ifndef __F_DISABLE_SOCK

#if (!defined(NO_BTF) || defined(__F_SK_PRPTOCOL_LEGACY))
static __always_inline u8 sk_get_protocol(struct sock *sk)
{
	u32 flags = _(((u32 *)(&sk->__sk_flags_offset))[0]);
	u8 l4_proto;

#ifdef CONFIG_CPU_BIG_ENDIAN
	l4_proto = (flags << 8) >> 24;
#else
	l4_proto = (flags << 16) >> 24;
#endif
	return l4_proto;
}
#endif

static inline int probe_parse_sk(struct sock *sk, sock_t *ske,
				 pkt_args_t *args)
{
	struct inet_connection_sock *icsk;
	struct sock_common *skc;
	u8 saddr[16], daddr[16];
	u16 l3_proto;
	u8 l4_proto;

	skc = (struct sock_common *)sk;
	switch (_C(skc, skc_family)) {
	case AF_INET:
		l3_proto = ETH_P_IP;
		ske->l3.ipv4.saddr = _C(skc, skc_rcv_saddr);
		ske->l3.ipv4.daddr = _C(skc, skc_daddr);
		if (filter_ipv4_check(args, ske->l3.ipv4.saddr,
				      ske->l3.ipv4.daddr))
			goto err;
		break;
	case AF_INET6:
		bpf_probe_read_kernel(saddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(daddr, 16, &skc->skc_v6_daddr);
		if (filter_ipv6_check(args, saddr, daddr))
			goto err;
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and 
		 * IPv6
		 */
		goto err;
	}
	if (filter_check(args, l3_proto, l3_proto))
		goto err;

#ifdef NO_BTF
#ifdef __F_SK_PRPTOCOL_LEGACY
	l4_proto = sk_get_protocol(sk);
#else
	l4_proto = _C(sk, sk_protocol);
#endif
#else
	if (bpf_core_field_size(sk->sk_protocol) == 2)
		l4_proto = _C(sk, sk_protocol);
	else
		l4_proto = sk_get_protocol(sk);
#endif

	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (filter_check(args, l4_proto, l4_proto))
		goto err;

	switch (l4_proto) {
	case IPPROTO_TCP: {
		struct tcp_sock *tp = (void *)sk;

		if (bpf_core_type_exists(struct tcp_sock)) {
			ske->l4.tcp.packets_out = _C(tp, packets_out);
			ske->l4.tcp.retrans_out = _C(tp, retrans_out);
			ske->l4.tcp.snd_una = _C(tp, snd_una);
		} else {
			ske->l4.tcp.packets_out = _(tp->packets_out);
			ske->l4.tcp.retrans_out = _(tp->retrans_out);
			ske->l4.tcp.snd_una = _(tp->snd_una);
		}
	}
	case IPPROTO_UDP:
		ske->l4.min.sport = bpf_htons(_C(skc, skc_num));
		ske->l4.min.dport = _C(skc, skc_dport);
		break;
	default:
		break;
	}

	if (filter_port(args, ske->l4.tcp.sport, ske->l4.tcp.dport))
		goto err;

	ske->rqlen = _C(sk, sk_receive_queue.qlen);
	ske->wqlen = _C(sk, sk_write_queue.qlen);

	ske->proto_l3 = l3_proto;
	ske->proto_l4 = l4_proto;
	ske->state = _C(skc, skc_state);

	if (!bpf_core_type_exists(struct inet_connection_sock))
		return 0;

	icsk = (void *)sk;
	bpf_probe_read_kernel(&ske->ca_state, sizeof(u8),
		(u8 *)icsk +
		bpf_core_field_offset(struct inet_connection_sock,
			icsk_retransmits) -
		1);

	if (bpf_core_helper_exist(jiffies64))
		ske->timer_out = _C(icsk, icsk_timeout) - (unsigned long)bpf_jiffies64();

	ske->timer_pending = _C(icsk, icsk_pending);

	return 0;
err:
	return -1;
}

static inline int probe_parse_pkt_sk(struct sock *sk, packet_t *pkt,
				     pkt_args_t *args)
{
	struct sock_common *skc;
	u16 l3_proto;
	u8 l4_proto;

	skc = (struct sock_common *)sk;
	switch (_C(skc, skc_family)) {
	case AF_INET:
		l3_proto = ETH_P_IP;
		pkt->l3.ipv4.saddr = _C(skc, skc_rcv_saddr);
		pkt->l3.ipv4.daddr = _C(skc, skc_daddr);
		if (filter_ipv4_check(args, pkt->l3.ipv4.saddr,
				      pkt->l3.ipv4.daddr))
			goto err;
		break;
	case AF_INET6:
#ifndef NT_DISABLE_IPV6
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr, 16, &skc->skc_v6_daddr);
		if (filter_ipv6_check(args, pkt->l3.ipv6.saddr,
				      pkt->l3.ipv6.daddr))
			goto err;
#endif
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and 
		 * IPv6
		 */
		goto err;
	}
	if (filter_check(args, l3_proto, l3_proto))
		goto err;

#ifdef NO_BTF
#ifdef __F_SK_PRPTOCOL_LEGACY
	l4_proto = sk_get_protocol(sk);
#else
	l4_proto = _C(sk, sk_protocol);
#endif
#else
	if (bpf_core_field_size(sk->sk_protocol) == 2)
		l4_proto = _C(sk, sk_protocol);
	else
		l4_proto = sk_get_protocol(sk);
#endif

	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (filter_check(args, l4_proto, l4_proto))
		goto err;

	switch (l4_proto) {
	case IPPROTO_TCP: {
		struct tcp_sock *tp = (void *)sk;

		if (bpf_core_type_exists(struct tcp_sock)) {
			pkt->l4.tcp.seq = bpf_htonl(_C(tp, snd_una));
			pkt->l4.tcp.ack = bpf_htonl(_C(tp, rcv_nxt));
		} else {
			pkt->l4.tcp.seq = bpf_htonl(_(tp->snd_una));
			pkt->l4.tcp.ack = bpf_htonl(_(tp->rcv_nxt));
		}
	}
	case IPPROTO_UDP:
		pkt->l4.min.sport = bpf_htons(_C(skc, skc_num));
		pkt->l4.min.dport = _C(skc, skc_dport);
		break;
	default:
		break;
	}

	if (filter_port(args, pkt->l4.tcp.sport, pkt->l4.tcp.dport))
		goto err;

	pkt->proto_l3 = l3_proto;
	pkt->proto_l4 = l4_proto;

	return 0;
err:
	return -1;
}

#else

static inline int probe_parse_sk(struct sock *sk, sock_t *ske, void *args)
{
	return -1;
}

static inline int probe_parse_pkt_sk(struct sock *sk, packet_t *pkt,
				     pkt_args_t *args)
{
	return -1;
}
#endif

static inline int __probe_parse_skb(parse_ctx_t *ctx)
{
	struct sk_buff *skb = ctx->skb;
	pkt_args_t *args = ctx->args;
	packet_t *pkt = ctx->pkt;
	u16 l3_proto;
	void *l3;

	ctx->network_header = _C(skb, network_header);
	ctx->mac_header = _C(skb, mac_header);
	ctx->data = _C(skb, head);

	pr_debug_skb("begin to parse, nh=%d mh=%d", ctx->network_header,
		     ctx->mac_header);
	pr_debug_skb("th=%d", _C(skb, transport_header));

	if (skb_l2_check(ctx->mac_header)) {
		/*
		 * try to parse skb for send path, which means that
		 * ether header doesn't exist in skb.
		 */
		l3_proto = bpf_ntohs(_C(skb, protocol));
		if (!l3_proto)
			goto err;
		if (!ctx->network_header)
			goto err;
		l3 = ctx->data + ctx->network_header;
	} else if (ctx->network_header && ctx->mac_header >= ctx->network_header) {
		/* to tun device, mac header is the same to network header.
		 * For this case, we assume that this is a IP packet.
		 *
		 * For vxlan device, mac header may be inner mac, and the
		 * network header is outer, which make mac > network.
		 */
		l3 = ctx->data + ctx->network_header;
		l3_proto = ETH_P_IP;
	} else {
		/* mac header is set properly, we can use it directly. */
		struct ethhdr *eth = ctx->data + ctx->mac_header;

		l3 = (void *)eth + ETH_HLEN;
		l3_proto = bpf_ntohs(_(eth->h_proto));
	}

	if (filter_check(args, l3_proto, l3_proto))
		goto err;

	ctx->trans_header = _C(skb, transport_header);
	pkt->proto_l3 = l3_proto;
	pr_debug_skb("l3=%d", l3_proto);

	switch (l3_proto) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		return probe_parse_ip(l3, ctx);
	default:
		if (filter_enabled(args, l4_proto))
			goto err;
		return 0;
	}
err:
	return -1;
}

static __always_inline int probe_parse_skb(struct sk_buff *skb, packet_t *pkt,
					   void *filter_args)
{
	parse_ctx_t ctx = {
		.args = filter_args,
		.skb = skb,
		.pkt = pkt,
	};
	return __probe_parse_skb(&ctx);
}

static inline int direct_parse_skb(struct __sk_buff *skb, packet_t *pkt,
				       pkt_args_t *bpf_args)
{
	struct ethhdr *eth = SKB_DATA(skb);
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)ip > SKB_END(skb))
		goto err;

	if (bpf_args && args_check(bpf_args, l3_proto, eth->h_proto))
		goto err;

	pkt->proto_l3 = bpf_ntohs(eth->h_proto);
	if (SKB_CHECK_IP(skb))
		goto err;

	if (bpf_args && (args_check(bpf_args, l4_proto, ip->protocol) ||
			 args_check(bpf_args, saddr, ip->saddr) ||
			 args_check(bpf_args, daddr, ip->daddr)))
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

	if (bpf_args && (args_check(bpf_args, sport, l4_p->sport) ||
			 args_check(bpf_args, dport, l4_p->dport)))
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
