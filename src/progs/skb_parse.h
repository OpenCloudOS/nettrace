/* 
 * The common part of parse skb and filter skb by specified condition.
 *
 * NOTE: This file can only be used in BPF program, can't be used in user
 * space code.
 */
#ifndef _H_BPF_SKB_UTILS
#define _H_BPF_SKB_UTILS

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "shared.h"
#include "skb_macro.h"

const volatile bpf_args_t m_config = {};
volatile bpf_data_t m_data;

#define bpf_core_helper_exist(name) \
	bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_##name)

#define skb_cb(__skb) ((void *)(__skb) + bpf_core_field_offset(typeof(*__skb), cb))
#define __ptr(a) ((void *)(a))
#define __cast(a, b) (a) = bpf_core_cast(b, typeof(*(a)))

#define _LP(dst, src) bpf_probe_read_kernel(dst, sizeof(*dst), src)
#define _P(src)							\
({								\
	typeof(src) ____tmp;					\
	_LP(&____tmp, &src);					\
	____tmp;						\
})

typedef struct {
	u64 pad;
	u64 skb;
	u64 location;
	u16 prot;
	u32 reason;
} kfree_skb_t;

typedef struct {
	void *data;
	u16 mac_header;
	u16 network_header;
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

static inline bool skb_l4_was_set(u16 transport_header)
{
	return transport_header != (typeof(transport_header))~0U;
}

/* check if the skb contains L2 head (mac head) */
static inline bool skb_l2_check(u16 header)
{
	return !header || header == (u16)~0U;
}

static inline bool skb_l4_check(u16 l4, u16 l3)
{
	return !skb_l4_was_set(l4) || l4 <= l3;
}

/* used to do basic filter */
#define filter_enabled(filter, attr)					\
	(filter && m_config.pkt.attr)
#define filter_check(filter, attr, value)				\
	(filter_enabled(filter, attr) && m_config.pkt.attr != value)
#define filter_any_enabled(filter, attr)				\
	(filter && (m_config.pkt.attr || m_config.pkt.s##attr ||	\
		       m_config.pkt.d##attr))

static inline bool is_ipv6_equal(void *addr1, void *addr2)
{
	return *(u64 *)addr1 == *(u64 *)addr2 &&
	       *(u64 *)(addr1 + 8) == *(u64 *)(addr2 + 8);
}

static inline int filter_ipv6_check(void *saddr, void *daddr, bool filter)
{
	if (!filter)
		return 0;

	return (m_config.pkt.saddr_v6_enable && !is_ipv6_equal(m_config.pkt.saddr_v6, saddr)) ||
	       (m_config.pkt.daddr_v6_enable && !is_ipv6_equal(m_config.pkt.daddr_v6, daddr)) ||
	       (m_config.pkt.addr_v6_enable && !is_ipv6_equal(m_config.pkt.addr_v6, daddr) &&
				 !is_ipv6_equal(m_config.pkt.addr_v6, saddr));
}

static inline int filter_ipv4_check(u32 saddr, u32 daddr, bool filter)
{
	if (!filter)
		return 0;

	return (m_config.pkt.saddr && m_config.pkt.saddr != saddr) ||
	       (m_config.pkt.daddr && m_config.pkt.daddr != daddr) ||
	       (m_config.pkt.addr && m_config.pkt.addr != daddr && m_config.pkt.addr != saddr);
}

static inline int filter_port(u32 sport, u32 dport, bool filter)
{
	if (!filter)
		return 0;

	return (m_config.pkt.sport && m_config.pkt.sport != sport) ||
	       (m_config.pkt.dport && m_config.pkt.dport != dport) ||
	       (m_config.pkt.port && m_config.pkt.port != dport && m_config.pkt.port != sport);
}

struct arphdr_all {
	__be16		ar_hrd;
	__be16		ar_pro;
	unsigned char	ar_hln;
	unsigned char	ar_pln;
	__be16		ar_op;

	unsigned char	ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char	ar_sip[4];		/* sender IP address		*/
	unsigned char	ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char	ar_tip[4];		/* target IP address		*/
};

static inline int probe_parse_arp(void *l3, packet_t *pkt, bool filter)
{
	struct arphdr_all *arp = l3;

	pkt->l4.arp_ext.op = bpf_ntohs(_P(arp->ar_op));
	if (pkt->l4.arp_ext.op != ARPOP_REQUEST && pkt->l4.arp_ext.op != ARPOP_REPLY)
		return 0;

	bpf_probe_read_kernel(&pkt->l3.ipv4.saddr, 4, arp->ar_sip);
	bpf_probe_read_kernel(&pkt->l3.ipv4.daddr, 4, arp->ar_tip);

	if (filter_ipv4_check(pkt->l3.ipv4.saddr, pkt->l3.ipv4.daddr, filter))
		return -1;

	bpf_probe_read_kernel(pkt->l4.arp_ext.source, ETH_ALEN, arp->ar_sha);
	bpf_probe_read_kernel(pkt->l4.arp_ext.dest, ETH_ALEN, arp->ar_tha);

	return 0;
}

static inline int probe_parse_l4(void *l4, packet_t *pkt, bool filter)
{
	switch (pkt->proto_l4) {
	case IPPROTO_IP:
	case IPPROTO_TCP: {
		struct tcphdr *tcp = bpf_core_cast(l4, struct tcphdr);
		u16 sport = tcp->source;
		u16 dport = tcp->dest;
		u8 flags;

		if (filter_port(sport, dport, filter))
			return -1;

		flags = _P(((u8 *)tcp)[13]);
		if (filter_enabled(filter, tcp_flags) && !(flags & m_config.pkt.tcp_flags))
			return -1;

		pkt->l4.tcp.sport = sport;
		pkt->l4.tcp.dport = dport;
		pkt->l4.tcp.flags = flags;
		pkt->l4.tcp.seq = bpf_ntohl(tcp->seq);
		pkt->l4.tcp.ack = bpf_ntohl(tcp->ack_seq);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = bpf_core_cast(l4, struct udphdr);
		u16 sport = udp->source;
		u16 dport = udp->dest;
	
		if (filter_port(sport, dport, filter))
			return -1;

		pkt->l4.udp.sport = sport;
		pkt->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = bpf_core_cast(l4, struct icmphdr);

		if (filter_any_enabled(filter, port))
			return -1;
		pkt->l4.icmp.code = icmp->code;
		pkt->l4.icmp.type = icmp->type;
		pkt->l4.icmp.seq = icmp->un.echo.sequence;
		pkt->l4.icmp.id = icmp->un.echo.id;
		break;
	}
	case IPPROTO_ESP: {
		struct ip_esp_hdr *esp_hdr = bpf_core_cast(l4, struct ip_esp_hdr);
		if (filter_any_enabled(filter, port))
			return -1;
		pkt->l4.espheader.seq = esp_hdr->seq_no;
		pkt->l4.espheader.spi = esp_hdr->spi;
		break;
	}
	default:
		if (filter_any_enabled(filter, port))
			return -1;
	}
	return 0;
}

static inline int probe_parse_l3(struct sk_buff *skb, bool filter,
				 packet_t *pkt, void *l3,
				 parse_ctx_t *ctx)
{
	u16 trans_header;
	void *l4 = NULL;

	trans_header = skb->transport_header;
	if (!skb_l4_check(trans_header, ctx->network_header))
		l4 = ctx->data + trans_header;

	if (pkt->proto_l3 == ETH_P_IPV6) {
		struct ipv6hdr *ipv6 = bpf_core_cast(l3, struct ipv6hdr);

		/* ipv4 address is set, skip ipv6 */
		if (filter_any_enabled(filter, addr))
			return -1;

		bpf_probe_read_kernel(pkt->l3.ipv6.saddr, 16, &ipv6->saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr, 16, &ipv6->daddr);
		if (filter_ipv6_check(pkt->l3.ipv6.saddr, pkt->l3.ipv6.daddr,
				      filter))
			return -1;

		pkt->proto_l4 = ipv6->nexthdr;
		l4 = l4 ?: l3 + sizeof(*ipv6);
	} else {
		struct iphdr *ipv4 = bpf_core_cast(l3, struct iphdr);
		u32 saddr, daddr, len;

		len = bpf_ntohs(ipv4->tot_len);
		if (filter && (m_config.pkt.pkt_len_1 || m_config.pkt.pkt_len_2)) {
			if (len < m_config.pkt.pkt_len_1 || len > m_config.pkt.pkt_len_2)
				return -1;
		}

		/* skip ipv4 if ipv6 is set */
		if (filter_any_enabled(filter, addr_v6[0]))
			return -1;

		l4 = l4 ?: l3 + get_ip_header_len(_P(((u8 *)l3)[0]));
		saddr = ipv4->saddr;
		daddr = ipv4->daddr;

		if (filter_ipv4_check(saddr, daddr, filter))
			return -1;

		pkt->proto_l4 = ipv4->protocol;
		pkt->l3.ipv4.saddr = saddr;
		pkt->l3.ipv4.daddr = daddr;
	}

	if (filter_check(filter, l4_proto, pkt->proto_l4))
		return -1;

	return probe_parse_l4(l4, pkt, filter);
}

static inline int probe_parse_sk(struct sock *sk, sock_t *ske, bool filter)
{
	struct inet_connection_sock *icsk;
	struct sock_common *skc;
	u8 saddr[16], daddr[16];
	unsigned long tmo;
	u16 l3_proto;
	u8 l4_proto;

	__cast(skc, sk);
	switch (skc->skc_family) {
	case AF_INET:
		l3_proto = ETH_P_IP;
		ske->l3.ipv4.saddr = skc->skc_rcv_saddr;
		ske->l3.ipv4.daddr = skc->skc_daddr;
		if (filter_ipv4_check(ske->l3.ipv4.saddr, ske->l3.ipv4.daddr,
				      filter))
			goto err;
		break;
	case AF_INET6:
		bpf_probe_read_kernel(saddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(daddr, 16, &skc->skc_v6_daddr);
		if (filter_ipv6_check(saddr, daddr, filter))
			goto err;
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and 
		 * IPv6
		 */
		goto err;
	}
	if (filter_check(filter, l3_proto, l3_proto))
		goto err;

	l4_proto = sk->sk_protocol;
	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (filter_check(filter, l4_proto, l4_proto))
		goto err;

	switch (l4_proto) {
	case IPPROTO_TCP: {
		struct tcp_sock *tp = bpf_core_cast(sk, struct tcp_sock);

		if (bpf_core_type_exists(struct tcp_sock)) {
			ske->l4.tcp.packets_out = tp->packets_out;
			ske->l4.tcp.retrans_out = tp->retrans_out;
			ske->l4.tcp.snd_una = tp->snd_una;
		} else {
			ske->l4.tcp.packets_out = tp->packets_out;
			ske->l4.tcp.retrans_out = tp->retrans_out;
			ske->l4.tcp.snd_una = tp->snd_una;
		}
	}
	case IPPROTO_UDP:
		ske->l4.min.sport = bpf_htons(skc->skc_num);
		ske->l4.min.dport = skc->skc_dport;
		break;
	default:
		break;
	}

	if (filter_port(ske->l4.tcp.sport, ske->l4.tcp.dport, filter))
		goto err;

	ske->rqlen = sk->sk_receive_queue.qlen;
	ske->wqlen = sk->sk_write_queue.qlen;

	ske->proto_l3 = l3_proto;
	ske->proto_l4 = l4_proto;
	ske->state = skc->skc_state;

	if (!bpf_core_type_exists(struct inet_connection_sock))
		return 0;

	icsk = bpf_core_cast(sk, struct inet_connection_sock);
	bpf_probe_read_kernel(&ske->ca_state, sizeof(u8),
		(u8 *)icsk +
		bpf_core_field_offset(struct inet_connection_sock,
			icsk_retransmits) -
		1);

	if (bpf_core_helper_exist(jiffies64)) {
		if (bpf_core_field_exists(icsk->icsk_timeout))
			tmo = icsk->icsk_timeout;
		else
			tmo = icsk->icsk_retransmit_timer.expires;
		ske->timer_out = tmo - (unsigned long)bpf_jiffies64();
	}

	ske->timer_pending = icsk->icsk_pending;

	return 0;
err:
	return -1;
}

/* Parse the IP from socket, and parse TCP/UDP from the header data if
 * transport header was set. Or, parse TCP/UDP from the skb_cb.
 */
static inline int probe_parse_skb_sk(struct sock *sk, struct sk_buff *skb,
				     packet_t *pkt, bool filter,
				     parse_ctx_t *ctx)
{
	u16 l3_proto, trans_header;
	struct sock_common *skc;
	u8 l4_proto = 0;

	skc = bpf_core_cast(sk, struct sock_common);
	switch (skc->skc_family) {
	case AF_INET:
		l3_proto = ETH_P_IP;
		pkt->l3.ipv4.saddr = skc->skc_rcv_saddr;
		pkt->l3.ipv4.daddr = skc->skc_daddr;
		if (filter_ipv4_check(pkt->l3.ipv4.saddr, pkt->l3.ipv4.daddr,
				      filter))
			return -1;
		break;
	case AF_INET6:
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr, 16, &skc->skc_v6_daddr);
		if (filter_ipv6_check(pkt->l3.ipv6.saddr, pkt->l3.ipv6.daddr,
				      filter))
			return -1;
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and 
		 * IPv6
		 */
		return -1;
	}
	if (filter_check(filter, l3_proto, l3_proto))
		return -1;

	if (bpf_core_field_size(sk->sk_protocol) == 2)
		l4_proto = sk->sk_protocol;

	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (filter_check(filter, l4_proto, l4_proto))
		return -1;

	pkt->proto_l3 = l3_proto;
	pkt->proto_l4 = l4_proto;

	/* The TCP header is set, and we can parse it from the skb */
	trans_header = skb->transport_header;
	if (skb_l4_was_set(trans_header))
		return probe_parse_l4(skb->head + trans_header, pkt, filter);

	/* parse L4 information from the socket */
	switch (l4_proto) {
	case IPPROTO_TCP: {
		struct tcp_skb_cb *cb;
		struct tcp_sock *tp;

		__cast(cb, skb->cb);
		__cast(tp, sk);

		pkt->l4.tcp.flags = cb->tcp_flags;
		pkt->l4.tcp.ack   = tp->rcv_nxt;
		pkt->l4.tcp.seq   = cb->seq;
	}
	case IPPROTO_UDP:
		pkt->l4.min.sport = bpf_htons(skc->skc_num);
		pkt->l4.min.dport = skc->skc_dport;
		break;
	default:
		break;
	}

	return filter_port(pkt->l4.tcp.sport, pkt->l4.tcp.dport, filter);
}

static inline int probe_parse_skb(struct sk_buff *skb, struct sock *sk,
				  packet_t *pkt, bool filter)
{
	parse_ctx_t __ctx, *ctx = &__ctx;
	u16 l3_proto;
	void *l3;

	ctx->network_header = skb->network_header;
	ctx->mac_header = skb->mac_header;
	ctx->data = skb->head;

	if (skb_l2_check(ctx->mac_header)) {
		int family;

		sk = sk ?: bpf_core_cast(skb->sk, struct sock);
		/**
		 * try to parse skb for send path, which means that
		 * ether header doesn't exist in skb.
		 *
		 * 1. check the existing of network header. If any, parse
		 *    the header normally. Or, goto 2.
		 * 2. check the existing of transport If any, parse TCP
		 *    with data, and parse IP with the socket. Or, goto 3.
		 * 3. parse it with tcp_cb() and the socket.
		 */

		if (!ctx->network_header) {
			if (!sk)
				return -1;
			return probe_parse_skb_sk(sk, skb, pkt, filter, ctx);
		}

		l3_proto = bpf_ntohs(skb->protocol);
		if (!l3_proto) {
			/* try to parse l3 protocol from the socket */
			if (!sk)
				return -1;
			family = bpf_core_cast(sk, struct sock_common)->skc_family;
			if (family == AF_INET)
				l3_proto = ETH_P_IP;
			else if (family == AF_INET6)
				l3_proto = ETH_P_IPV6;
			else
				return -1;
		}
		l3 = ctx->data + ctx->network_header;
	} else if (ctx->network_header && ctx->mac_header >= ctx->network_header) {
		/* For tun device, mac header is the same to network header.
		 * For this case, we assume that this is a IP packet.
		 *
		 * For vxlan device, mac header may be inner mac, and the
		 * network header is outer, which make mac > network.
		 */
		l3 = ctx->data + ctx->network_header;
		l3_proto = ETH_P_IP;
	} else {
		/* mac header is set properly, we can use it directly. */
		struct ethhdr *eth = bpf_core_cast(ctx->data + ctx->mac_header,
						   struct ethhdr);

		l3 = __ptr(eth) + ETH_HLEN;
		l3_proto = bpf_ntohs(eth->h_proto);
	}

	if (filter) {
		if (m_config.pkt.l3_proto) {
			if (m_config.pkt.l3_proto != l3_proto)
				return -1;
		} else if (m_config.pkt.l4_proto) {
			/* Only IPv4 and IPv6 support L4 protocol filter */
			if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
				return -1;
		}
	}

	pkt->proto_l3 = l3_proto;
	switch (l3_proto) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		return probe_parse_l3(skb, filter, pkt, l3, ctx);
	case ETH_P_ARP:
		return probe_parse_arp(l3, pkt, filter);
	default:
		return 0;
	}
}

#endif
