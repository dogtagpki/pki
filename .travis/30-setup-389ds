#!/bin/bash
set -e

setup-ds.pl \
    --silent \
    slapd.ServerIdentifier="pkitest" \
    General.SuiteSpotUserID=nobody \
    General.SuiteSpotGroup=nobody \
    slapd.ServerPort=389 \
    slapd.Suffix="dc=pki,dc=test" \
    slapd.RootDN="cn=Directory Manager" \
    slapd.RootDNPwd="DMSecret.123"
