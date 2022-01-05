export VERSION=0.1.3
export RELEASE=1.tl3

TARGET_DIR=${DESTDIR}/opt/nettrace/
SOURCE_DIR=~/rpmbuild/SOURCES/nettrace-${VERSION}

install:
	mkdir -p ${TARGET_DIR}

	cp nettrace.c ${TARGET_DIR}
	cp nettrace.py ${TARGET_DIR}
	cp utils.py ${TARGET_DIR}
	cp skb.yaml ${TARGET_DIR}

	mkdir -p ${DESTDIR}/usr/share/man/man8/
	gzip -k nettrace.8
	mv nettrace.8.gz ${DESTDIR}/usr/share/man/man8/

	mkdir -p ${DESTDIR}/usr/share/bash-completion/completions/
	cp bash-completion.sh ${DESTDIR}/usr/share/bash-completion/completions/nettrace

	mkdir -p ${DESTDIR}/usr/sbin/
	ln -s /opt/nettrace/nettrace.py ${DESTDIR}/usr/sbin/nettrace

rpm:
	rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	cp -r ./* ${SOURCE_DIR}/
	cd ~/rpmbuild/SOURCES/ && tar -czf nettrace-${VERSION}.tar.gz nettrace-${VERSION}
	rpmbuild -ba ./nettrace.spec

