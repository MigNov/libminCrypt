ACLOCAL_AMFLAGS=-I m4
SOURCEDIR=`rpm --eval '%{_sourcedir}'`
CFLAGS=-Wall

SUBDIRS = src tests include

EXTRA_DIST = LICENSE

rpm:   dist-xz
	$(CP) $(PACKAGE_NAME)-$(VERSION).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME)-$(VERSION).tar.xz
	rpmbuild -bb $(PACKAGE_NAME).spec

srpm:  dist-xz
	$(CP) $(PACKAGE_NAME)-$(VERSION).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME)-$(VERSION).tar.xz
	rpmbuild -bs $(PACKAGE_NAME).spec
