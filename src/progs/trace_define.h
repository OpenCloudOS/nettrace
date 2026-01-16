#define KBUILD_MODNAME ""
#define __PROG_TYPE_TRACING 1

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "trace_funcs.h"
#include "shared.h"

#define ctx_get_arg(ctx, index) ((void *)((unsigned long long *)(ctx))[index])
#define info_get_arg(info, index) ctx_get_arg(info->ctx, index)

#define DECLARE_FAKE_FUNC(name)					\
	static __always_inline int name(context_info_t *info)

/* one trace may have more than one implement */
#define __DEFINE_TRACE_INIT(name, target, info_init...) 	\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("fexit/"#target)					\
	int TRACE_RET_NAME(name)(void **ctx)			\
	{							\
		context_info_t info = (context_info_t) {	\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			info_init				\
		};						\
		if (handle_exit(&info, INDEX_##name))		\
			return 0;				\
		if (pre_handle_entry(&info, INDEX_##name))	\
			return 0;				\
		handle_entry_finish(&info, fake__##name(&info));\
		return 0;					\
	}							\
	SEC("fentry/"#target)					\
	int TRACE_NAME(name)(void **ctx)			\
	{							\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			info_init				\
		};						\
		if (pre_handle_entry(&info, INDEX_##name))	\
			return 0;				\
		handle_entry_finish(&info, fake__##name(&info));\
		return 0;					\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_TRACE_INIT(name, target, info_init...)	\
	__DEFINE_TRACE_INIT(name, target, info_init)

/* init the skb by the index of func args */
#define DEFINE_TRACE_SKB(name, skb_index)			\
	DEFINE_TRACE_INIT(name, name,				\
			  .skb = ctx_get_arg(ctx, skb_index))

#define TRACE_DEFAULT(name, skb_index, sk_index)		\
	DEFINE_TRACE_INIT(name, name,				\
		.skb = nt_ternary_take(skb_index,		\
				       ctx_get_arg(ctx, skb_index),\
				       NULL),			\
		.sk = nt_ternary_take(sk_index,			\
				      ctx_get_arg(ctx, sk_index),\
				      NULL))			\
	{							\
		return default_handle_entry(info);		\
	}

#define DEFINE_TP_INIT(name, cata, tp, info_init...)		\
	DECLARE_FAKE_FUNC(fake__##name);			\
	SEC("tp_btf/"#tp)					\
	int TRACE_NAME(name)(void **ctx) {			\
		context_info_t info = {				\
			.func = INDEX_##name,			\
			.ctx = ctx,				\
			info_init				\
		};						\
		if (pre_handle_entry(&info, INDEX_##name))	\
			return 0;				\
		handle_entry_finish(&info, fake__##name(&info));\
		return 0;					\
	}							\
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, skb_index)			\
	DEFINE_TP_INIT(name, cata, tp,				\
		       .skb = ctx_get_arg(ctx, skb_index))
#define TP_DEFAULT(name, cata, tp, skb_index)			\
	DEFINE_TP(name, cata, tp, skb_index)			\
	{							\
		return default_handle_entry(info);		\
	}
