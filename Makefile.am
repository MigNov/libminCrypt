ACLOCAL_AMFLAGS=-I m4
SOURCEDIR=`rpm --eval '%{_sourcedir}'`

SUBDIRS = src examples

EXTRA_DIST = LICENSE

test:
	cd tests && ./runtests.sh

rpm:   dist-xz
	$(CP) $(PACKAGE_NAME)-$(VERSION).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME)-$(VERSION).tar.xz
	$(RPMBUILD) -bb $(PACKAGE_NAME).spec

srpm:  dist-xz
	$(CP) $(PACKAGE_NAME)-$(VERSION).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME)-$(VERSION).tar.xz
	$(RPMBUILD) -bs $(PACKAGE_NAME).spec
