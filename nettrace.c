#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bcc/proto.h>

#define DO_TRACE(regs, args...) {		\
	return do_trace(regs, skb, args);	\
}

#if defined(NT_ENABLE_DETAIL) || defined(NT_ENABLE_RET) || \
    defined(NT_ENABLE_SKB_MODE)
#define NT_ENABLE_ID
#endif

typedef struct sk_buff sk_buff_t;
typedef struct {
	u64 ts;		/* timestamp */
	union {
		struct {
			u32 saddr;
			u32 daddr;
		} ip;
	} field_l3;
	u64 ret_val;
#ifdef NT_ENABLE_ID
	u64 id;
#endif
#ifdef NT_ENABLE_DETAIL
	char ifname[IFNAMSIZ];
	u32 ifindex;
	char comm[16];
	u32 pid;
#endif
#ifdef NT_ENABLE_STACK
	u32 stack_id;
#endif
#define field_ip field_l3.ip
#define field_saddr field_ip.saddr
#define field_daddr field_ip.daddr
	union {
		struct {
			u16 sport;
			u16 dport;
			u32 seq;
			u16 flags;
		} tcp;
#define field_tcp field_l4.tcp
#define field_sport field_tcp.sport
#define field_dport field_tcp.dport
#define field_flags field_tcp.flags
		struct {
			u16 sport;
			u16 dport;
		} udp;
		struct {
			u8 type;
			u8 code;
			u16 seq;
			u16 id;
		} icmp;
#define field_udp field_l4.udp
	} field_l4;
	u16 proto_l3;
	u8  proto_l4;
	u8  func;
#ifdef NT_ENABLE_RET
	bool is_ret;
#endif
	u8 align0;
} context_t;

typedef struct {
	context_t ctx;
	bool match;
} ret_context_t;

BPF_PERF_OUTPUT(m_output);

#ifdef NT_ENABLE_RET
BPF_PERCPU_ARRAY(m_rets, ret_context_t, BPF_PH_count);
#endif

#ifdef NT_ENABLE_SKB_MODE
BPF_HASH(m_match, u64, bool);
#endif

#ifdef NT_ENABLE_STACK
BPF_STACK_TRACE(stacks, 2048);
#endif

static inline bool skb_l4_was_set(const struct sk_buff *skb)
{
	return skb->transport_header != 0xFFFF &&
	       skb->transport_header > skb->network_header;
}

static inline bool skb_l2_was_set(const struct sk_buff *skb)
{
	return skb->mac_header != 0xFFFF && skb->mac_header;
}

static inline void *get_l2(sk_buff_t *skb)
{
	if (skb_l2_was_set(skb))
		return skb->head + skb->mac_header;
	else
		return NULL;
}

static inline void *get_l3(sk_buff_t *skb)
{
	if (skb->network_header > skb->mac_header)
		return skb->head + skb->network_header;
	else if (get_l2(skb))
		return get_l2(skb) + ETH_HLEN;
	else
		return NULL;
}

static inline void *get_l3_send(sk_buff_t *skb)
{
	if (skb->network_header)
		return skb->head + skb->network_header;
	else
		return NULL;
}

static inline void *get_l4(sk_buff_t *skb)
{
	if (skb_l4_was_set(skb))
		return skb->head + skb->transport_header;
	else if (get_l3(skb))
		return get_l3(skb) + sizeof(struct iphdr);
	else
		return NULL;
}

static inline bool do_filter(context_t *ctx)
{
#ifdef NT_ENABLE_SKB_MODE
	bool *matched = (bool *)(m_match.lookup(&ctx->id));
	if (matched)
		return true;
#endif
	bool res = (BPF_PH_filter);
#ifdef NT_ENABLE_SKB_MODE
	if (res)
		m_match.update(&ctx->id, &res);
#endif
	return res;
}

static inline int parse_ip(context_t *ctx, sk_buff_t *skb,
			   struct iphdr *ip)
{
	void *l4;

	ctx->proto_l4 = ip->protocol;
	ctx->field_saddr = ip->saddr;
	ctx->field_daddr = ip->daddr;

	l4 = get_l4(skb);
	switch (ctx->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		ctx->field_flags = *((u16 *)((void *)&tcp->ack_seq +
					     sizeof(u32)));
		ctx->field_sport = tcp->source;
		ctx->field_dport = tcp->dest;
		ctx->field_l4.tcp.seq = tcp->seq;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		ctx->field_sport = udp->source;
		ctx->field_dport = udp->dest;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;
		ctx->field_l4.icmp.code = icmp->code;
		ctx->field_l4.icmp.type = icmp->type;
		ctx->field_l4.icmp.seq = icmp->un.echo.sequence;
		ctx->field_l4.icmp.id = icmp->un.echo.id;
		break;
	}
	}
	return 0;
}

static inline int parse_sk(context_t *ctx, struct sock *sk,
			   sk_buff_t *skb)
{
#ifdef CONFIG_CPU_BIG_ENDIAN
	u8 proto = *(u8 *)((void *)sk +
			   offsetof(struct sock, sk_gso_max_segs) - 3);
#else
	u8 proto = *(u8 *)((void *)sk +
			   offsetof(struct sock, sk_gso_max_segs) - 2);
#endif
	ctx->field_saddr = sk->sk_rcv_saddr;
	ctx->field_daddr = sk->sk_daddr;
	ctx->proto_l4 = proto;

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ctx->field_sport = sk->sk_num;
		ctx->field_dport = sk->sk_dport;
		break;
	}
	return 0;
}

static inline int init_ctx(context_t *ctx, sk_buff_t *skb)
{
	struct ethhdr *eth = get_l2(skb);
	struct sock *sk;
	void *ip;

	if (!eth)
		goto on_send;

	ip = get_l3(skb);
	ctx->proto_l3 = eth->h_proto;
	if (ctx->proto_l3 != htons(ETH_P_IP))
		return 0;
	return parse_ip(ctx, skb, ip);

on_send:
	sk = skb->sk;
	if (!sk || sk->sk_family != PF_INET)
		return 0;

	ctx->proto_l3 = htons(ETH_P_IP);
	ip = get_l3_send(skb);
	if (ip)
		return parse_ip(ctx, skb, ip);
	return 0;
}

static inline void do_output(void *regs, context_t *ctx)
{
	ctx->ts = bpf_ktime_get_ns();
	m_output.perf_submit(regs, ctx, sizeof(context_t));
}

static inline int do_trace(void *regs, sk_buff_t *skb, u32 func
#ifdef NT_ENABLE_RET
			   ,bool ret, bool ret_only
#endif
#ifdef NT_ENABLE_SKB_MODE
			   ,bool is_end
#endif
#ifdef NT_ENABLE_STACK
			   ,bool stack
#endif
			   )
{
	context_t lctx = {.func = (u8)func}, *ctx = &lctx;
	ret_context_t *rctx;

	if (!skb)
		return 0;

#ifdef NT_ENABLE_RET
	if (ret) {
		rctx = (ret_context_t *)m_rets.lookup(&func);
		if (!rctx)
			return 0;
		memset(rctx, 0, sizeof(ret_context_t));
		ctx = (context_t *)rctx;
		ctx->func = (u8) func;
	}
#endif

	if (init_ctx(ctx, skb))
		return 0;

#ifdef NT_ENABLE_ID
	ctx->id = (u64)(void *)skb;
#endif

	if (!do_filter(ctx))
		return 0;

#ifdef NT_ENABLE_STACK
	if (stack)
		ctx->stack_id = stacks.get_stackid(regs, 0);
#endif

#ifdef NT_ENABLE_DETAIL
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	ctx->pid = t->pid;
	bpf_get_current_comm(&ctx->comm, sizeof(ctx->comm));
	if (skb->dev) {
		bpf_probe_read_kernel(&ctx->ifname, IFNAMSIZ,
				      &skb->dev->name);
		ctx->ifindex = skb->dev->ifindex;
	} else {
		ctx->ifindex = skb->skb_iif;
	}
#endif

#ifdef NT_ENABLE_SKB_MODE
	if (is_end)
		m_match.delete(&ctx->id);
#endif

#ifdef NT_ENABLE_RET
	if (ret) {
		rctx->match = true;
		if(!ret_only)
			do_output(regs, ctx);
		return 0;
	}
#endif
	do_output(regs, ctx);
	return 0;
}

#ifdef NT_ENABLE_RET
static inline int ret_trace(struct pt_regs *regs, u32 func, bool is_clone)
{
	ret_context_t *rctx =  m_rets.lookup(&func);
	if (!rctx || !rctx->match)
		return 0;

	context_t *ctx = (context_t *)rctx;
	ctx->ret_val = PT_REGS_RC(regs);
	ctx->is_ret = true;
	do_output(regs, (context_t *)rctx);

#ifdef NT_ENABLE_SKB_MODE
	if (is_clone)
		m_match.update(&ctx->ret_val, &is_clone);
#endif

	rctx->match = false;
	return 0;
}
#endif

BPF_PH_function
