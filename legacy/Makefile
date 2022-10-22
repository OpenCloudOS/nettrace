
ROOT = ../
TARGET_DIR := ${PREFIX}/opt/nettrace/

prog-files = nettrace.c nettrace.py utils.py skb.yaml

include ../common.mk

nettrace.c:
	wget $(REMOTE_ROOT)/legacy/$@

install: nettrace.c
	@mkdir -p ${TARGET_DIR} && cp $(prog-files) ${TARGET_DIR}
	@mkdir -p ${PREFIX}/usr/bin/
	@ln -s /opt/nettrace/nettrace.py ${PREFIX}/usr/bin/nettrace-legacy

pack: nettrace.c
	@rm -rf $(PREFIX)/nettrace.zip && zip -r $(PREFIX)/nettrace.zip \
		*.c *.py *.yaml
	@cd $(PREFIX) && \
		echo '#!/usr/bin/env python3' | cat - nettrace.zip > \
		nettrace-legacy && chmod +x nettrace-legacy && \
		rm -rf nettrace.zip
	@echo "$(PREFIX)/nettrace.zip is generated"

all: nettrace.c

clean:
	rm -rf build dist *.spec nettrace
