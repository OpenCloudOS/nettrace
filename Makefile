
export VERSION=0.1.3
export RELEASE=1.tl3

targets = dropdump nodetrace
targets-call = for i in $^; do make -C $$i $@; done

PREFIX ?= ./output
PREFIX := $(abspath $(PREFIX))
export PREFIX

all: $(targets)
	$(call targets-call, all)

clean: $(targets)
	$(call targets-call, clean)
	rm -rf output

install:
	make -C src install

rpm:
	make -C src rpm

.PHONY: $(targets)
