ROOT ?= $(abspath ../)
bpf_progs = progs/probe progs/trace
progs = droptrace
prog-droptrace = droptrace.c parse_sym.c $(COMMON_SHARED) drop_reason.h

include ../common.mk

progs/common.h:
	cd progs && wget $(REMOTE_ROOT)/droptrace/$@

$(foreach i,$(bpf_progs),$(i).c): progs/common.h
	cd progs && wget $(REMOTE_ROOT)/droptrace/$@

drop_reason.h: vmlinux.h
	rm -rf $@
	awk 'BEGIN{ print "#ifndef _H_SKB_DROP_REASON"; \
		print "#define _H_SKB_DROP_REASON\n";\
		system("sed -e \"/enum skb_drop_reason {/,/}/!d\" $< >> $@");\
		print "\n#define __DEFINE_SKB_REASON(FN) \\";\
	}\
	/^enum skb_drop/ { dr=1; }\
	/^\};/ { dr=0; }\
	/^\tSKB_DROP_REASON_/ {\
		if (dr) {\
			sub(/SKB_DROP_REASON_/, "", $$1);\
			printf "\tFN(%s)\t\\\n", $$1;\
		}\
	}\
	END{ print "\n#endif" }' $< >> $@

droptrace.c: drop_reason.h

all: $(progs)

install: all
	@mkdir -p $(PREFIX)/usr/bin/ && cp droptrace $(PREFIX)/usr/bin/

pack: all
	@mkdir -p $(PREFIX) && cp droptrace $(PREFIX)

clean:
	rm -rf drop_reason.h droptrace vmlinux.h progs/*.skel.h progs/*.o
