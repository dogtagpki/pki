pki-server 8 "February 1, 2019" PKI "pki-server CLI"
====================================================

NAME
----

pki-server - Command-line interface for managing PKI server.

SYNOPSIS
--------

`pki-server` [CLI options] &lt;command&gt; [command arguments]

DESCRIPTION
-----------

The `pki-server` command provides a command-line interface allowing
administrators to perform various administrative operations on PKI server.
These services include starting/stopping instances, enabling/disabling subsystems,
performing certain migrations and enabling/disabling startup using `nuxwdog`.

Operations are performed using file system utilities,
and can only be performed by an administrative user on the local host.
This utility does not connect to any of the server's Web interfaces.

CLI OPTIONS
-----------

`--help`  
&nbsp;&nbsp;&nbsp;&nbsp;Prints additional help information.

`-d`  
&nbsp;&nbsp;&nbsp;&nbsp;Displays debug information.

`-v`  
&nbsp;&nbsp;&nbsp;&nbsp;Displays verbose information.

OPERATIONS
----------

To view available commands and options, simply type `pki-server`.

Some commands have sub-commands. To view the sub-commands, type `pki-server <command>`.
To view each command's usage, type `pki-server <command> --help`.

FILES
-----

*/usr/sbin/pki-server*

SEE ALSO
--------

**pki-server-instance**(8)  
&nbsp;&nbsp;&nbsp;&nbsp;PKI instance management commands.

**pki-server-subsystem**(8)  
&nbsp;&nbsp;&nbsp;&nbsp;PKI subsystem management commands.

**pki-server-migrate**(8)  
&nbsp;&nbsp;&nbsp;&nbsp;PKI server migration script management commands.

**pki-server-nuxwdog**(8)  
&nbsp;&nbsp;&nbsp;&nbsp;Commands to enable/disable startup using nuxwdog.

**pki-server-cert**(8)  
&nbsp;&nbsp;&nbsp;&nbsp;System certificate management commands.

AUTHORS
-------

Ade Lee &lt;alee@redhat.com&gt;, and Dinesh Prasanth M K &lt;dmoluguw@redhat.com&gt;

COPYRIGHT
----------

Copyright (c) 2019 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
