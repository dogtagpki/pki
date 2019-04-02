# pki-server-migrate 8 "July 15, 2015" PKI "PKI Migration Commands"

## NAME

pki-server-migrate - Command-Line Interface to run migration scripts on PKI servers.

## SYNOPSIS

**pki-server** [*CLI-options*] **migrate** [*command-options*]

## DESCRIPTION

Apache Tomcat instances are configured differently in Tomcat 7 and 8.
**pki-server migrate** makes the necessary changes in the instance configuration files and symbolic links
so that the instance will work with the target Tomcat version.

This command will migrate all instances to the target Apache Tomcat version.
To migrate a specific instance only, use **pki-server instance-migrate**.

## OPTIONS

The CLI options are described in **pki-server(8)**.

**--tomcat** *version*  
    Tomcat version.

## OPERATIONS

All **pki-server** commands must be executed as the system administrator.

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
