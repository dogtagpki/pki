#! /bin/bash -ex

# Check if python linters are installed
rpm -q python3-pylint python3-flake8 python3-pyflakes

# Python files are present in python3-pki and pki-server packages. Get the list of the files
PYTHON_PKI_FILES=`rpm -ql python3-pki | grep .py$`
PYTHON_PKI_FILES="$PYTHON_PKI_FILES `rpm -ql pki-server | grep .py$`"

# Run pylint
pylint-3 \
    --rcfile=tools/pylintrc \
    ${PYTHON_PKI_FILES}

# Run flake8
python3-flake8 \
    --config tox.ini \
    ${PYTHON_PKI_FILES}
