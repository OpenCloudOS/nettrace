
ROOT = ../
SCRIPT = $(ROOT)/script
TARGET_DIR = ${PREFIX}/opt/nettrace/
SOURCE_DIR = ~/rpmbuild/SOURCES/nettrace-${VERSION}

prog-files = nettrace.c nettrace.py utils.py skb.yaml

install:
	echo $(TARGET_DIR)
	@mkdir -p ${TARGET_DIR}

	@cp $(prog-files) ${TARGET_DIR}

	@mkdir -p ${PREFIX}/usr/share/man/man8/
	@gzip -k $(SCRIPT)/nettrace.8
	@mv $(SCRIPT)/nettrace.8.gz ${PREFIX}/usr/share/man/man8/

	@mkdir -p ${PREFIX}/usr/share/bash-completion/completions/
	@cp $(SCRIPT)/bash-completion.sh \
		${PREFIX}/usr/share/bash-completion/completions/nettrace

	@mkdir -p ${PREFIX}/usr/sbin/
	@ln -s /opt/nettrace/nettrace.py ${PREFIX}/usr/sbin/nettrace

rpm:
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r ../* ${SOURCE_DIR}/
	@cd ~/rpmbuild/SOURCES/ && tar -czf nettrace-${VERSION}.tar.gz \
		nettrace-${VERSION}
	@rpmbuild -ba $(SCRIPT)/nettrace.spec

pack:
	@rm -rf ../nettrace.zip && zip -r ../nettrace.zip *.c *.py *.yaml
	@echo '#!/usr/bin/env python3' | cat - ../nettrace.zip > nettrace
	@chmod +x nettrace
	@rm -rf ../nettrace.zip
	@echo "`pwd`/nettrace is generated"

all:

clean:
	rm -rf build dist *.spec nettrace
