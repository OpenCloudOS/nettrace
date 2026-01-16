#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "skb_parse.h"

int ret;

SEC("fexit/__inet_lookup_listener")
int BPF_PROG(feat_probe_args_ext)
{
	ret = READ_ONCE(ctx[8]);
	return 0;
}
