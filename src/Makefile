
ROOT = ../
TARGET_DIR := ${PREFIX}/opt/nettrace/

prog-files = nettrace.c nettrace.py utils.py skb.yaml

install:
	@mkdir -p ${TARGET_DIR} && cp $(prog-files) ${TARGET_DIR}

	@mkdir -p ${PREFIX}/usr/share/bash-completion/completions/
	@cp $(SCRIPT)/bash-completion.sh \
		${PREFIX}/usr/share/bash-completion/completions/nettrace

	@mkdir -p ${PREFIX}/usr/bin/
	@ln -s /opt/nettrace/nettrace.py ${PREFIX}/usr/bin/nettrace

pack:
	@rm -rf ../nettrace.zip && zip -r ../nettrace.zip *.c *.py *.yaml
	@echo '#!/usr/bin/env python3' | cat - ../nettrace.zip > nettrace
	@chmod +x nettrace
	@rm -rf ../nettrace.zip
	@echo "`pwd`/nettrace is generated"

all:

clean:
	rm -rf build dist *.spec nettrace
