NAME	= packetfence-pki
VERSION	= 1.0.4
PREFIX	= /usr/local/packetfence-pki
UID	= -o nobody
GID	= -g nogroup
DIRS	= inverse pki conf
INSTALL	= /usr/bin/install -c -D -m0644
TAR	= $(NAME)-$(VERSION).tar
GZ	= $(TAR).gz
BZ2	= $(TAR).bz2

dist: clean $(GZ)

$(TAR):
	for j in `find . ! -type l ! -name '*~'  ! -name '#*' ! -name 'db' ! -path '*/.git/*' !  -path '*/.gitignore'`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $$j $(NAME)-$(VERSION)/$$j; \
		fi; \
	done
	tar cf $(TAR) $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

$(GZ): $(TAR)
	gzip -f $(TAR)

bz2: clean $(BZ2)

$(BZ2): $(TAR)
	bzip2 $(TAR)

clean:
	rm -rf $(GZ) $(TAR) $(BZ2) $(NAME)-$(VERSION)

install:
	for i in '$(DIRS)'; do \
		for j in `find $$i`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $$j $(DESTDIR)$(PREFIX)/$$j; \
		fi; \
		done \
	done
	install -m0744 manage.py $(DESTDIR)$(PREFIX)/manage.py; \
	install -m666 initial_data.json $(DESTDIR)$(PREFIX)/initial_data.json; \
	install -d -m2770 $(DESTDIR)$(PREFIX)/logs; \
	install -d -m2770 ${DESTDIR}$(PREFIX)/ca; \
	if [ -e /etc/debian_version ]; then \
		install -m0600 debian/httpd.conf.debian $(DESTDIR)$(PREFIX)/conf/httpd.conf; \
	else \
		install -m0600 rpm/httpd.conf.rhel $(DESTDIR)$(PREFIX)/conf/httpd.conf; \
	fi; \

clean:
	rm -rf $(GZ) $(TAR) $(BZ2) $(NAME)-$(VERSION)

rpm: clean $(TAR)
	make $(BZ2)
	rpmbuild --define 'ver $(VERSION)' -ta --target noarch $(BZ2)
	make clean
