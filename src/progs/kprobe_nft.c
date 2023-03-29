#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"
#include "kprobe.h"

#ifndef ST_NFT_DO_CHAIN
#define ST_NFT_DO_CHAIN

struct _xt_action_param {
	void *arg1;
	void *arg2;
	void *state;
};

struct _nft_pktinfo {
	void			*skb;
	bool			tprot_set;
	u8			tprot;
	struct _xt_action_param	xt;
};

struct _nft_pktinfo_new {
	void	*skb;
	void	*state;
};

#endif

#ifndef NFT_LEGACY
#undef _CT
#define _CT _C
#else
#undef _CT
#define _CT(src, a) _(src->a)
#endif

#undef FUNC_NAME
#define FUNC_NAME(name)		\
	nt_ternary_take(NFT_LEGACY, name##_legacy, name)

#undef FAKE_FUNC_NAME
#define FAKE_FUNC_NAME FUNC_NAME(handle_nft_do_chain)

static try_inline int FAKE_FUNC_NAME(context_t *ctx)
{
	struct nft_pktinfo *pkt = nt_regs_ctx(ctx, 1);
	struct nf_hook_state *state;
	struct nft_chain *chain;
	struct nft_table *table;
	nf_event_t e = { };

	ctx->skb = (struct sk_buff *)_(pkt->skb);
	ctx_event_null(ctx, e);
	if (handle_entry(ctx))
		return 0;

	if (ctx->args->nft_high)
		state = _(((struct _nft_pktinfo_new *)pkt)->state);
	else
		state = _(((struct _nft_pktinfo *)pkt)->xt.state);

	chain	= nt_regs_ctx(ctx, 2);
	table	= _CT(chain, table);
	e.hook	= _C(state, hook);
	e.pf	= _C(state, pf);

	bpf_probe_read_kernel_str(e.chain, sizeof(e.chain),
				  _CT(chain, name));
	bpf_probe_read_kernel_str(e.table, sizeof(e.table),
				  _CT(table, name));

	EVENT_OUTPUT(ctx->regs, e);
	return 0;
}

/**
 * This function is used to the kernel version that don't support
 * kernel module BTF.
 */
DEFINE_KPROBE_INIT(FUNC_NAME(nft_do_chain), nft_do_chain)
{
	return FAKE_FUNC_NAME(ctx);
}
