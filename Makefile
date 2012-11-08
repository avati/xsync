PACKAGE_NAME=glusterfs-xsync
PACKAGE_VERSION=0.2
PACKAGE_DIR=$(PACKAGE_NAME)-$(PACKAGE_VERSION)
dist:
	rm -rvf $(PACKAGE_DIR)
	mkdir -vp $(PACKAGE_DIR)
	install -m 0755 xsync.sh $(PACKAGE_DIR)/xsync.sh
	install -m 0755 gsyncd $(PACKAGE_DIR)/gsyncd
	install -m 0644 $(PACKAGE_NAME).spec $(PACKAGE_DIR)/$(PACKAGE_NAME).spec
	install -m 0644 README.md $(PACKAGE_DIR)/README.md
	tar -cvf $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz $(PACKAGE_DIR)

rpm:
	make dist && rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz
