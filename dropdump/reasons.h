#ifndef _H_TRACE_REASONS
#define _H_TRACE_REASONS

#include <drop_reason.h>

/* drop_reasons is used to translate 'enum skb_drop_reason' to string,
 * which is reported to user space.
 */
static const char * const drop_reasons[] = {
#define FN(name) [SKB_DROP_REASON_##name] = #name,
	__DEFINE_SKB_REASON(FN)
#undef FN
};

#endif