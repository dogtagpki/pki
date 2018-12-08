pki-server-cert 8 "February 1, 2019" PKI "pki-server-cert CLI"
==============================================================

NAME
----

pki-server-cert - Command-Line Interface for managing System Certificates.

SYNOPSIS
--------

`pki-server` [CLI options] cert  
`pki-server` [CLI options] cert-find  
`pki-server` [CLI options] cert-show &lt;cert ID&gt;  
`pki-server` [CLI options] cert-update &lt;cert ID&gt;  
`pki-server` [CLI options] cert-create &lt;cert ID&gt;  
`pki-server` [CLI options] cert-import &lt;cert ID&gt;  
`pki-server` [CLI options] cert-export &lt;cert ID&gt;  
`pki-server` [CLI options] cert-del &lt;cert ID&gt;  
`pki-server` [CLI options] cert-fix

DESCRIPTION
-----------

The `pki-server cert` commands provide command-line interfaces to manage system certificates.

`pki-server cert` commands perform system certificate related operations on a specific CS
instance. All `pki-server cert` commands require specification of the &lt;cert ID&gt; to identify the
target certificate.

`pki-server` [CLI options] cert  
&nbsp;&nbsp;&nbsp;&nbsp;List all available cert commands.

`pki-server` [CLI options] cert-find  
&nbsp;&nbsp;&nbsp;&nbsp;List all available system certificates.

`pki-server` [CLI options] cert-show &lt;cert ID&gt;  
&nbsp;&nbsp;&nbsp;&nbsp;Display details of a system certificate.

`pki-server` [CLI options] cert-update &lt;cert ID&gt;  
&nbsp;&nbsp;&nbsp;&nbsp;Update corresponding subsystem's CS.cfg with the system certificate data and CSR from NSS db

`pki-server` [CLI options] cert-create &lt;cert ID&gt;  
&nbsp;&nbsp;&nbsp;&nbsp;Create a new system certificate.

`pki-server` [CLI options] cert-import &lt;cert ID&gt;  
&nbsp;&nbsp;&nbsp;&nbsp;Import a system certificate into NSS database and update the corresponding subsystem's CS.cfg.

`pki-server` [CLI options] cert-export &lt;cert ID&gt;  
&nbsp;&nbsp;&nbsp;&nbsp;Export a system certificate or its CSR or its PKCS #12 to a file.

`pki-server` [CLI options] cert-del &lt;cert ID&gt;  
&nbsp;&nbsp;&nbsp;&nbsp;Remove a system certificate from NSS db.

`pki-server` [CLI options] cert-fix  
&nbsp;&nbsp;&nbsp;&nbsp;Fix all expired certs in the PKI instance.

To view each command's usage, type `pki-server cert-<command> --help`.

All pki-server commands must be executed as the &lt;system administrator&gt;.

OPTIONS
-------

The other CLI options are described in pki-server(8).

SEE ALSO
--------

offline-cert-renewal (7)

AUTHORS
-------

Dinesh Prasanth M K &lt;dmoluguw@redhat.com&gt; and Endi S Dewata &lt;edewata@redhat.com&gt;

COPYRIGHT
---------

Copyright (c) 2018 Red Hat, Inc. This is licensed under the GNU General Public License, version 2 (GPLv2). A copy of this license is  available  at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
