
export VERSION	= 1.2.1
RELEASE		?= tl3
export RELEASE

targets		:= droptrace nodetrace src legacy
targets-call	= for i in $^; do make $1 -C $$i $@; done
man-target 	:= script/zh_CN/nettrace.8

ROOT		:= $(abspath .)
export ROOT
PREFIX		?= ./output
PREFIX		:= $(abspath $(PREFIX))
MAN_DIR		:= $(PREFIX)/usr/share/man
BCOMP		:= ${PREFIX}/usr/share/bash-completion/completions/
export PREFIX
SCRIPT		= $(ROOT)/script
export SCRIPT
SOURCE_DIR	:= ~/rpmbuild/SOURCES/nettrace-${VERSION}
PACK_TARGET 	:= nettrace-$(VERSION)-$(RELEASE)
PACK_PATH	:= $(abspath $(PREFIX)/$(PACK_TARGET))

all clean:: $(targets)
	$(call targets-call)

clean::
	rm -rf output $(man-target)

%.8: %.md
	md2man-roff $< > $@

man: $(man-target)

install: man $(targets)
	@mkdir -p $(PREFIX)
	$(call targets-call)

	@mkdir -p ${MAN_DIR}/man8/; gzip -k $(SCRIPT)/*.8; mv		\
		$(SCRIPT)/*.8.gz ${MAN_DIR}/man8/
	
	@mkdir -p ${MAN_DIR}/zh_CN/man8/; gzip -k $(SCRIPT)/zh_CN/*.8;	\
		mv $(SCRIPT)/zh_CN/*.8.gz ${MAN_DIR}/zh_CN/man8/

	@mkdir -p $(BCOMP); cd $(BCOMP); cp $(SCRIPT)/bash-completion.sh \
		./nettrace; ln -s nettrace droptrace

pack: $(targets)
	@make clean
	@rm -rf $(PACK_PATH) && mkdir -p $(PACK_PATH)
	$(call targets-call,PREFIX=$(PACK_PATH))
	@cd $(PREFIX) && tar -cjf $(PACK_TARGET).tar.bz2 $(PACK_TARGET)

rpm:
	@make clean
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r * ${SOURCE_DIR}/
	@cd ~/rpmbuild/SOURCES/ && tar -czf nettrace-${VERSION}.tar.gz	\
		nettrace-${VERSION}
	@rpmbuild -ba $(SCRIPT)/nettrace.spec

.PHONY: $(targets)
