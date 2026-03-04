#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#include <bpf/bpf.h>
#include "net_utils.h"

#define BPF_PROG_FD(name)	(bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)	(bpf_map__fd(obj->maps.name))


extern long int syscall (long int __sysno, ...);

const struct btf_type *btf_get_type(char *name);
int btf_get_arg_count(char *name);
int btf_get_trace_param_index(char *name, const char *struct_name);
int btf_get_trace_args(char *name, int *arg_count, int *skb, int *sk,
		       int *btf_id, int *btf_fd);
int btf_get_trace_args_local(char *name, int *arg_count, int *skb, int *sk,
			     int *btf_id, int *btf_fd);
void btf_release_cache(void);
const struct btf_type *btf_get_type_ext(char *name, struct btf **type_btf);

#endif
