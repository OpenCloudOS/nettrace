#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <skb_macro.h>
#include "shared.h"
#include <skb_parse.h>

#define MARK_TOS_VALUE	0xe0

bpf_args_t _bpf_args = {
	.quiet = true
};

static inline void do_mark(struct __sk_buff *skb, struct iphdr *ip)
{
	__u8 old_tos = ip->tos;
	ip->tos = MARK_TOS_VALUE;
	bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, bpf_htons(old_tos),
			    bpf_htons(MARK_TOS_VALUE),
			    2);
}

static inline bool is_marked(struct iphdr *ip)
{
	return (ip->tos & MARK_TOS_VALUE) == MARK_TOS_VALUE;
}


/* mark the packet which to be traced. For now, the method of
 * marking is to set TOS in ip header to a special value.
 *
 * This eBPF with the type of TC is about to attach to the egress
 * of TC filter.
 */
SEC("tc")
int ntrace_mark(struct __sk_buff *skb)
{
	event_t event = {.location = LOCALTION_MARK};
	struct ethhdr *eth = SKB_DATA(skb);
	struct iphdr *ip;

	eth = SKB_DATA(skb);
	if (SKB_CHECK_IP(skb))
		goto out;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto out;

	ip = SKB_HDR_IP(skb);
	if (ip->tos & MARK_TOS_VALUE) {
		bpf_printk("ctrace: conflict mark(tos) value found: %x\n",
			   ip->tos);
		goto out;
	}

	if (direct_parse_skb(skb, &event.pkt, &_bpf_args.pkt))
		goto out;

	do_mark(skb, ip);
	if (!_bpf_args.quiet)
		EVENT_OUTPUT(skb, event);

	return TC_ACT_OK;
out:
	return TC_ACT_UNSPEC;
}


/*******************************************************************
 * 
 * Following functions aim to trace the receive and send of marked
 * packet.
 * 
 * ctrace_entry() is used to trace the packet entry to the node, and
 * ctrace_exit() is used to trace the packet leave.
 * 
 *******************************************************************/

static inline void try_output_skb(struct __sk_buff *skb, __u8 location)
{
	event_t event = { .location = location };
	struct ethhdr *eth = SKB_DATA(skb);
	struct iphdr *ip;

	if (SKB_CHECK_IP(skb))
		return;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return;

	ip = SKB_HDR_IP(skb);
	if (!is_marked(ip) || direct_parse_skb(skb, &event.pkt, NULL))
		return;

	EVENT_OUTPUT(skb, event);
}

SEC("tc")
int ntrace_entry(struct __sk_buff *skb)
{
	try_output_skb(skb, LOCALTION_INGRESS);
	return TC_ACT_UNSPEC;
}

SEC("tc")
int ntrace_exit(struct __sk_buff *skb)
{
	try_output_skb(skb, LOCALTION_EGRESS);
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
