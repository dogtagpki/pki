#!/bin/sh -x

### To be used only while building pki-core. ###

if [ -z "$1" ]
then
  echo "PKI codebase home not specified. Could not scan the python scripts. Returning 0 - for SUCCESS"
  echo 0
  exit 0
fi

HOME_DIR=$1

SCRIPTPATH="$( cd $(dirname $0) ; pwd -P )"

PYLINT_RC_FILE_PATH="$SCRIPTPATH/dogtag.pylintrc"

PYTHON_PACKAGE_DIR="$HOME_DIR`python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"`"

cd $PYTHON_PACKAGE_DIR

FILES="pki/"
FILES="$FILES $HOME_DIR/usr/bin/pki"
FILES="$FILES $HOME_DIR/usr/sbin/pkispawn"
FILES="$FILES $HOME_DIR/usr/sbin/pkidestroy"
FILES="$FILES $HOME_DIR/usr/sbin/pki-upgrade"
FILES="$FILES $HOME_DIR/usr/sbin/pki-server"
FILES="$FILES $HOME_DIR/usr/sbin/pki-server-upgrade"
FILES="$FILES $(find $HOME_DIR/usr/share/pki/upgrade -type f)"
FILES="$FILES $(find $HOME_DIR/usr/share/pki/server/upgrade -type f)"

pylint --rcfile=$PYLINT_RC_FILE_PATH $FILES

exit $?
