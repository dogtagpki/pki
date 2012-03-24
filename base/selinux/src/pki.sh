#!/bin/sh

USAGE="$0 [ --update ]"

if [ ! -f /usr/share/selinux/devel/Makefile ]; then
echo 'selinux-policy-devel not installed, package required for building policy'
echo '# yum install selinux-policy-devel'
exit 1
fi

if [ $# -eq 1 ]; then
	if [ "$1" = "--update" ] ; then
		time=`ls -l --time-style="+%x %X" pki_ca.te | awk '{ printf "%s %s", $6, $7 }'`
		rules=`ausearch --start $time -m avc --raw -se pki_ca`
		if [ x"$rules" != "x" ] ; then
			echo "Found avc's to update policy with"
			echo -e "$rules" | audit2allow -R
			echo "Do you want these changes added to policy [y/n]?"
			read ANS
			if [ "$ANS" = "y" -o "$ANS" = "Y" ] ; then
				echo "Updating policy"
				echo -e "$rules" | audit2allow -R >> pki_ca.te
				# Fall though and rebuild policy
			else
				exit 0
			fi
		else
			echo "No new avcs found"
			exit 0
		fi
	else
		echo -e $USAGE
		exit 1
	fi
elif [ $# -ge 2 ] ; then
	echo -e $USAGE
	exit 1
fi

echo "Building and Loading Policy"
make -f /usr/share/selinux/devel/Makefile
