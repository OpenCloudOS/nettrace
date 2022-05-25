#ifndef _H_BPF_UTILS
#define _H_BPF_UTILS

#define BPF_PROG_FD(name)       (bpf_program__fd(obj->progs.name))
#define BPF_MAP_FD(name)        (bpf_map__fd(obj->maps.name))
#define BPF_LINK_FD(name)       (bpf_link__fd(obj->links.name))

#endif
