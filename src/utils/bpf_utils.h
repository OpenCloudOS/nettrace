#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#include <bpf/bpf.h>
#include "net_utils.h"

#define BPF_PROG_FD(name)	(bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)	(bpf_map__fd(obj->maps.name))


extern long int syscall (long int __sysno, ...);

const struct btf_type *btf_get_type(char *name);
int btf_get_arg_count(char *name);

#endif
