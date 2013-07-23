#!/bin/sh -x

### To be used only while building pki-core. ###

if [ -z "$1" ]
then
  echo "PKI codebase home not specified. Could not scan the python scripts. Returning 0 - for SUCCESS"
  echo 0
  exit 0
fi

HOME_DIR=$1

PYLINT_RC_FILE_PATH="`cd $2/.. ; pwd`/dogtag.pylintrc"

PYTHON_PACKAGE_DIR="$HOME_DIR`python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"`"

PYLINT_REPORT_PATH="`cd $HOME_DIR/../.. ; pwd`/pylint-report"

cd $PYTHON_PACKAGE_DIR

rv=`pylint --rcfile=$PYLINT_RC_FILE_PATH pki/ $HOME_DIR/usr/sbin/pkispawn $HOME_DIR/usr/sbin/pkidestroy $HOME_DIR/usr/sbin/pki-upgrade $HOME_DIR/usr/sbin/pki-server-upgrade >> $PYLINT_REPORT_PATH`

status=$?

#Excerpt from pylint man page
#OUTPUT STATUS CODE
#       Pylint should leave with following status code:
#           * 0 if everything went fine
#           * 1 if a fatal message was issued
#           * 2 if an error message was issued
#           * 4 if a warning message was issued
#           * 8 if a refactor message was issued
#           * 16 if a convention message was issued
#           * 32 on usage error
#
#       status 1 to 16 will be bit-ORed so you can know which different categories has been issued by analysing pylint output status code

result=0
if [ $(($status&1)) -eq 1 ] || [ $(($status&2)) -eq 2 ] || [ $(($status&4)) -eq 4 ]
then
    echo -e "\n===============================================================================\n"
    echo -e "  Pylint has reported errors or warnings in the python code.\n"
    echo -e "  The report generated can be viewed at $PYLINT_REPORT_PATH.\n"
    echo -e "  If the issues shown are false positives, re-build pki-core after marking them"
    echo -e "  ignored in the configuration file dogtag.pylintrc, in the source code. \n"
    echo -e "===============================================================================\n"
    result=1
fi

exit $result
