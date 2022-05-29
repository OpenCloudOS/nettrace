
export VERSION=0.1.3
export RELEASE=1.tl3

targets = droptrace nodetrace src
targets-call = for i in $^; do make -C $$i $@; done

PREFIX ?= ./output
PREFIX := $(abspath $(PREFIX))
export PREFIX

all clean:: $(targets)
	$(call targets-call)

clean::
	rm -rf output

install:
	make -C src install

pack:
	make -C src pack

rpm:
	make -C src rpm

.PHONY: $(targets)
