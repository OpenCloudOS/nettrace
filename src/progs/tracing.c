#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include <skb_shared.h>
#include <skb_utils.h>

#include "shared.h"

int nettrace_entry(void *ctx)
{
	return 0;
}
