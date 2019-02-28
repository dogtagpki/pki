# pki-server-cert 8 "February 1, 2019" PKI "pki-server-cert CLI"

## NAME

pki-server-cert - Command-Line Interface for managing System Certificates.

## SYNOPSIS

**pki-server** [*CLI-options*] cert  
**pki-server** [*CLI-options*] cert-find  
**pki-server** [*CLI-options*] cert-show *cert-ID*  
**pki-server** [*CLI-options*] cert-update *cert-ID*  
**pki-server** [*CLI-options*] cert-create *cert-ID*  
**pki-server** [*CLI-options*] cert-import *cert-ID*  
**pki-server** [*CLI-options*] cert-export *cert-ID*  
**pki-server** [*CLI-options*] cert-del *cert-ID*  
**pki-server** [*CLI-options*] cert-fix

## DESCRIPTION

The **pki-server cert** commands provide command-line interfaces to manage system certificates.

**pki-server cert** commands perform system certificate related operations on a specific CS instance.
All **pki-server cert** commands require specification of the *cert-ID* to identify the target certificate.

**pki-server** [*CLI-options*] cert  
    List all available cert commands.

**pki-server** [*CLI-options*] cert-find  
    List all available system certificates.

**pki-server** [*CLI-options*] cert-show *cert-ID*  
    Display details of a system certificate.

**pki-server** [*CLI-options*] cert-update *cert-ID*  
    Update corresponding subsystem's CS.cfg with the system certificate data and CSR from NSS db

**pki-server** [*CLI-options*] cert-create *cert-ID*  
    Create a new system certificate.

**pki-server** [*CLI-options*] cert-import *cert-ID*  
    Import a system certificate into NSS database and update the corresponding subsystem's CS.cfg.

**pki-server** [*CLI-options*] cert-export *cert-ID*  
    Export a system certificate or its CSR or its PKCS #12 to a file.

**pki-server** [*CLI-options*] cert-del *cert-ID*  
    Remove a system certificate from NSS db.

**pki-server** [*CLI-options*] cert-fix  
    Fix all expired certs in the PKI instance.

To view each command's usage, type **pki-server cert-&lt;command&gt; --help**.

All **pki-server** commands must be executed as the system administrator.

## OPTIONS

The other CLI options are described in **pki-server(8)**.

## SEE ALSO

**offline-cert-renewal(7)**

## AUTHORS

Dinesh Prasanth M K &lt;dmoluguw@redhat.com&gt; and Endi S Dewata &lt;edewata@redhat.com&gt;

## COPYRIGHT

Copyright (c) 2018 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is  available  at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
