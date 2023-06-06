#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

int ret;

SEC("fexit/__inet_lookup_listener")
__attribute__((optimize("O0")))
int BPF_PROG(feat_probe_args_ext)
{
	ret = (int)ctx[10];
	return 0;
}
