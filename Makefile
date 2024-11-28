
export VERSION	= 1.2.11
RELEASE		?= .tl3
export RELEASE

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
ARCH		?= $(shell uname -m)
SOURCE_DIR	:= ~/rpmbuild/SOURCES/nettrace-${VERSION}
PACK_TARGET 	:= nettrace-$(VERSION)-1$(RELEASE).$(ARCH)
PACK_PATH	:= $(abspath $(PREFIX)/$(PACK_TARGET))
PACK_NAME	:= $(PACK_TARGET).tar.bz2

all clean:
	make -C src $@

%.8: %.md
	md2man-roff $< > $@

man: $(man-target)

install:
	@mkdir -p $(PREFIX)
	make -C src install

	@mkdir -p ${MAN_DIR}/zh_CN/man8/; gzip -k $(SCRIPT)/zh_CN/*.8;	\
		mv $(SCRIPT)/zh_CN/*.8.gz ${MAN_DIR}/zh_CN/man8

	@mkdir -p ${MAN_DIR}/man8/; gzip -k $(SCRIPT)/*.8; mv		\
		$(SCRIPT)/*.8.gz ${MAN_DIR}/man8/;			\
		cd ${MAN_DIR}/man8/; for i in `ls ../zh_CN/man8/`;	\
		do							\
			if [ ! -f $$i ];then				\
				ln -s ../zh_CN/man8/$$i ./;		\
			fi;						\
		done

	@mkdir -p $(BCOMP); cd $(BCOMP); cp $(SCRIPT)/bash-completion.sh \
		./nettrace

pack:
	@make clean
	@rm -rf $(PACK_PATH) && mkdir -p $(PACK_PATH)
	make PREFIX=$(PACK_PATH) -C src pack
	@cd $(PREFIX) && tar -cjf $(PACK_NAME) $(PACK_TARGET) &&	\
		echo "$(PREFIX)/$(PACK_NAME) is generated"

rpm:
	@make clean
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r * ${SOURCE_DIR}/
	@sed -i 's/%{VERSION}/$(VERSION)/' ${SOURCE_DIR}/script/nettrace.spec
	@cd ~/rpmbuild/SOURCES/ && tar -czf nettrace-${VERSION}.tar.gz	\
		nettrace-${VERSION}
	@rpmbuild -D 'dist $(RELEASE)' --target ${ARCH}			\
		-ba ${SOURCE_DIR}/script/nettrace.spec
