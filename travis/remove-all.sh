#!/bin/bash
set -e

pkidestroy -v -i pkitest -s OCSP
pkidestroy -v -i pkitest -s KRA
pkidestroy -v -i pkitest -s CA

remove-ds.pl -f -i slapd-pkitest
