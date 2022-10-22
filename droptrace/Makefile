ROOT ?= $(abspath ../)
bpf_progs = progs/probe progs/trace
progs = droptrace
prog-droptrace = droptrace.c $(COMMON_SHARED) drop_reason.h \
		 $(COMPONENT)/parse_sym.c

include ../common.mk

progs/common.h:
	$(call cmd_download,$@,droptrace/$@)

$(foreach i,$(bpf_progs),$(i).c): progs/common.h drop_reason.h
	$(call cmd_download,$@,droptrace/$@)

droptrace.c: drop_reason.h
	@if [ -z `grep SKB_DROP_REASON_MAX drop_reason.h` ];then	\
		echo 'drop reason is not supported by current kernel';	\
		exit -1;						\
	fi

all: $(progs)

install: all
	@mkdir -p $(PREFIX)/usr/bin/ && cp droptrace $(PREFIX)/usr/bin/

pack: all
	@mkdir -p $(PREFIX) && cp droptrace $(PREFIX)

clean:
	rm -rf drop_reason.h droptrace vmlinux.h progs/*.skel.h		\
		progs/*.o kheaders.h
