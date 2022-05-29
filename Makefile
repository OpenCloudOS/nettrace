
export VERSION=0.1.3
export RELEASE=1.tl3

targets = droptrace nodetrace src
targets-call = for i in $^; do make -C $$i $@; done

ROOT := $(abspath .)
PREFIX ?= ./output
PREFIX := $(abspath $(PREFIX))
export PREFIX
SCRIPT = $(ROOT)/script
export SCRIPT
SOURCE_DIR := ~/rpmbuild/SOURCES/nettrace-${VERSION}

all clean:: $(targets)
	$(call targets-call)

clean::
	rm -rf output

install: $(targets)
	@mkdir -p $(PREFIX)
	$(call targets-call)
	@mkdir -p ${PREFIX}/usr/share/man/man8/
	@gzip -k $(SCRIPT)/*.8
	@mv $(SCRIPT)/*.8.gz ${PREFIX}/usr/share/man/man8/

pack:
	make -C src pack

rpm:
	@make clean
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r * ${SOURCE_DIR}/
	@cd ~/rpmbuild/SOURCES/ && tar -czf nettrace-${VERSION}.tar.gz \
		nettrace-${VERSION}
	@rpmbuild -ba $(SCRIPT)/nettrace.spec

.PHONY: $(targets)
