#define KBUILD_MODNAME ""

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "trace_funcs.h"
#include "shared.h"

#define ctx_get_arg(ctx, index) ((void *)((unsigned long long *)(ctx))[index])
#define info_get_arg(info, index) ctx_get_arg(info->ctx, index)

#define DECLARE_FAKE_FUNC(name)						\
	static __always_inline int name(context_info_t *info)

#define TRACE_INIT_WRAPPER(name, __is_return, info_init...) {		\
	context_info_t info = (context_info_t) {			\
		.func = INDEX_##name,					\
		.ctx = (u64 *)ctx,					\
		info_init						\
	};								\
	if (__is_return && pre_handle_exit(&info, INDEX_##name))	\
		return 0;						\
	if (pre_handle_entry(&info, INDEX_##name, __is_return))		\
		return 0;						\
	handle_entry_finish(&info, fake__##name(&info));		\
	return 0;							\
}

/* one trace may have more than one implement */
#define __DEFINE_TRACE_INIT(name, target, info_init...) 		\
	DECLARE_FAKE_FUNC(fake__##name);				\
	SEC("fexit/"#target)						\
	int TRACE_RET_NAME(name)(void **ctx)				\
	{								\
		TRACE_INIT_WRAPPER(name, true, info_init)		\
	}								\
	SEC("fentry/"#target)						\
	int TRACE_NAME(name)(void **ctx)				\
	{								\
		TRACE_INIT_WRAPPER(name, false, info_init)		\
	}								\
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_TRACE_INIT(name, target, info_init...)			\
	__DEFINE_TRACE_INIT(name, target, info_init)

#define DEFINE_TP_INIT(name, info_init...)				\
	DECLARE_FAKE_FUNC(fake__##name);				\
	SEC("tp_btf/"#name)						\
	int TRACE_NAME(name)(void **ctx)				\
	{								\
		TRACE_INIT_WRAPPER(name, false, info_init)		\
	}								\
	DECLARE_FAKE_FUNC(fake__##name)
