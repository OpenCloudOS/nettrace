ROOT		?= $(abspath ../)
bpf_progs	:= progs/tracing progs/feat_args_ext
progs		:= nettrace
utils		:= $(ROOT)/utils
prog-nettrace-origin = \
		$(utils)/parse_sym.c $(utils)/net_utils.c \
		$(utils)/arg_parse.c $(utils)/sys_utils.c \
		$(utils)/bpf_utils.c \
		trace.c output.c trace_tracing.c \
		analysis.c trace_group.c \
		dropreason.c rstreason.c
prog-nettrace	= $(prog-nettrace-origin) nettrace.c

include ../common.mk

progs/trace_funcs.h:
	python3 gen_trace.py probe > progs/trace_funcs.h

trace_group.c: trace.yaml
	python3 gen_trace.py > trace_group.c

progs/*.c: progs/trace_funcs.h
	@:

nettrace.c: $(prog-nettrace-origin)

all: $(progs)

install: all
	@mkdir -p ${PREFIX}/usr/bin/
	@cp nettrace ${PREFIX}/usr/bin/

pack: all
	@cp nettrace ${PREFIX}/

clean:
	rm -rf $(progs) trace_group.c progs/trace_funcs.h \
		$(bpf_progs) progs/*.o progs/*.skel.h
