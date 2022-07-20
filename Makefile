
export VERSION=1.2.0
export RELEASE=1.tl3

targets = droptrace nodetrace src legacy
targets-call = for i in $^; do make -C $$i $@; done

ROOT := $(abspath .)
export ROOT
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

	@mkdir -p ${PREFIX}/usr/share/bash-completion/completions/
	@cd ${PREFIX}/usr/share/bash-completion/completions/;\
		cp $(SCRIPT)/bash-completion.sh ./nettrace;\
		ln -s nettrace droptrace

pack: $(targets)
	@mkdir -p $(PREFIX)/nettrace-$(VERSION)
	$(call targets-call)
	@cd $(PREFIX) && ls -p | grep -v / | xargs -I % mv % \
		nettrace-$(VERSION) && \
		tar -cjf nettrace-$(VERSION).tar.bz2 nettrace-$(VERSION)

rpm:
	@make clean
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r * ${SOURCE_DIR}/
	@cd ~/rpmbuild/SOURCES/ && tar -czf nettrace-${VERSION}.tar.gz \
		nettrace-${VERSION}
	@rpmbuild -ba $(SCRIPT)/nettrace.spec

.PHONY: $(targets)
