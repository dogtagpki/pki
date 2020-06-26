# pki_healthcheck.conf 5 "June 29, 2020" PKI "PKI Healthcheck Configuration"

## NAME

pki_healthcheck.conf - PKI Healthcheck configuration file.

## DESCRIPTION

The healthcheck.conf configuration file is used to set the defaults when running pki-healthcheck tool.

## SYNTAX

The configuration options are not case sensitive. The values may be case sensitive, depending on the option.

Blank lines are ignored.
Lines beginning with # are comments and are ignored.

Valid lines consist of an option name, an equals sign and a value. Spaces surrounding equals sign are ignored. An option terminates at the end of a line.

Values should not be quoted, the quotes will not be stripped.

    # Wrong - don't include quotes
    verbose = "True"

    # Right - Properly formatted options
    verbose = True
    verbose=True

Options must appear in the section named *[default]* or *[dogtag]*. There are no other sections defined or used currently.

Options may be defined that are not used. Be careful of misspellings, they will not be rejected.

## OPTIONS

The following options are relevant for the healthcheck tool:

**cert_expiration_days**  
    The number of days left before a certificate expires to start displaying a warning. The default is 28.

**instance_name**  
    The name of the PKI instance. The default is **pki-tomcat**

## EXAMPLES

[default]  
cert_expiration_days = 30  

[dogtag]  
ca_instance_name = pki-ca  
kra_instance_name = pki-kra  
ocsp_instance_name = pki-ocsp  
tks_instance_name = pki-tks  
tps_instance_name = pki-tps  

## FILES

/etc/pki/healthcheck.conf

## SEE ALSO

pki-healthcheck (8)

## AUTHORS

Dinesh Prasanth M K \<dmoluguw@redhat.com>

## COPYRIGHT

Copyright (c) 2020 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is  available  at <http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>.
