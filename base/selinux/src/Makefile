POLICY_MAKEFILE = /usr/share/selinux/devel/Makefile
POLICY_DIR = $(DESTDIR)/usr/share/selinux/targeted

all:
	if [ ! -e $(POLICY_MAKEFILE) ]; then echo "You need to install the SELinux development tools (selinux-policy-devel)" && exit 1; fi
	$(MAKE) -f $(POLICY_MAKEFILE) || exit 1; 

clean:
	rm -rf tmp 
	rm pki.pp

install: all
	install -d $(POLICY_DIR)
	install -m 644 pki.pp $(POLICY_DIR)

load:
	/usr/sbin/semodule -i pki.pp

