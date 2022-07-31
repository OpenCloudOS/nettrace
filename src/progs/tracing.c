#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_tracing.h>

#include <packet.h>
#include <skb_utils.h>

#include "shared.h"

int nettrace_entry(void *ctx)
{
	return 0;
}
