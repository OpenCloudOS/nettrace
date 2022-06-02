
ROOT = ../
TARGET_DIR := ${PREFIX}/opt/nettrace/

prog-files = nettrace.c nettrace.py utils.py skb.yaml

install:
	@mkdir -p ${TARGET_DIR} && cp $(prog-files) ${TARGET_DIR}
	@mkdir -p ${PREFIX}/usr/bin/
	@ln -s /opt/nettrace/nettrace.py ${PREFIX}/usr/bin/nettrace

pack:
	@rm -rf $(PREFIX)/nettrace.zip && zip -r $(PREFIX)/nettrace.zip \
		*.c *.py *.yaml
	@cd $(PREFIX) && \
		echo '#!/usr/bin/env python3' | cat - nettrace.zip > \
		nettrace && chmod +x nettrace && rm -rf nettrace.zip
	@echo "$(PREFIX)/nettrace.zip is generated"

all:

clean:
	rm -rf build dist *.spec nettrace
