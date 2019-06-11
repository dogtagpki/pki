# pki-server-instance 8 "July 15, 2015" PKI "PKI Instance Management Commands"

## NAME

pki-server-instance - Command-line interface for managing PKI server instances.

## SYNOPSIS

**pki-server** [*CLI-options*] **instance**  
**pki-server** [*CLI-options*] **instance-cert**  
**pki-server** [*CLI-options*] **instance-cert-export**  
**pki-server** [*CLI-options*] **instance-find**  
**pki-server** [*CLI-options*] **instance-show** *instance-ID*  
**pki-server** [*CLI-options*] **instance-start** *instance-ID*  
**pki-server** [*CLI-options*] **instance-stop** *instance-ID*  
**pki-server** [*CLI-options*] **instance-migrate** **--tomcat** *version* *instance-ID*  
**pki-server** [*CLI-options*] **instance-nuxwdog-enable** *instance-ID*  
**pki-server** [*CLI-options*] **instance-nuxwdog-disable** *instance-ID*  
**pki-server** [*CLI-options*] **instance-externalcert-add** **-i** *instance-ID* **--cert-file** *path* **--trust-args** *args* **--nickname** *nickname* **--token** *token*  
**pki-server** [*CLI-options*] **instance-externalcert-del** **-i** *instance-ID* **--nickname** *nickname* **--token** *token*  

## DESCRIPTION

The **pki-server instance** commands provide command-line interfaces to manage PKI server instances.
A PKI server instance consists of a single Apache Tomcat instance that contains one or more subsystems.

Operations that are available include:
listing and showing details about local instances;
starting and stopping instances;
performing instance migrations;
and enabling or disabling password prompted instance startup using **nuxwdog**.

**pki-server** [*CLI-options*] **instance**  
    This command is to list available instance commands.

**pki-server** [*CLI-options*] **instance-cert**  
    This command is to list available instance certificate commands.

**pki-server** [*CLI-options*] **instance-cert-export**  
    This command is to export system certificates and keys to a PKCS #12 file.
    The output filename and either a password or a password file are required.
    If no nicknames are specified, all the system certificates will be exported.
    Otherwise, it is possible to extract individual certificates (with or without their keys and trust arguments),
    and to append to an existing PKCS #12 file.

**pki-server** [*CLI-options*] **instance-find**  
    This command is to list local PKI server instances.

**pki-server** [*CLI-options*] **instance-show** *instance-ID*  
    This command is to view a details about a particular instance.

**pki-server** [*CLI-options*] **instance-start** *instance-ID*  
    This command is to start a PKI server instance.
    Note that currently this command cannot be used to start **nuxwdog**-enabled instances.

**pki-server** [*CLI-options*] **instance-stop** *instance-ID*  
    This command is to stop a PKI server instance.
    Note that currently this command cannot be used to stop **nuxwdog**-enabled instances.

**pki-server** [*CLI-options*] **instance-migrate** **--tomcat** *version* *instance-ID*  
    There are differences in configuration between Apache Tomcat 7 and Apache Tomcat 8.
    This command reconfigures a PKI server instance to match the specified Tomcat version.
    This command can be used to migrate initially created under Tomcat 7 when Tomcat is upgraded.
    See **pki-server migrate(8)** for further details.

**pki-server** [*CLI-options*] **instance-nuxwdog-enable** *instance-ID*  
    This command is to convert a PKI server instance to start without access to a password file,
    using the **nuxwdog** daemon.  See **pki-server nuxwdog(8)** for further details.

**pki-server** [*CLI-options*] **instance-nuxwdog-disable** *instance-ID*  
    This command is to convert a PKI server instance to start with access to a password file,
    rather than using the **nuxwdog** daemon.  See **pki-server nuxwdog(8)** for further details.

**pki-server** [*CLI-options*] **instance-externalcert-add** **-i** *instance-ID* **--cert-file** *path* **--trust-args** *args* **--nickname** *nickname* **--token** *token*  
    This command is to add a certificate to the certificate database for a PKI server instance.
    The certificate will be kept track of in the configuration file **external_certs.conf**,
    and will automatically be exported when the system certificates are exported.
    To update a certificate, the old one needs to be removed first using the delete command below.
    The trust arguments are those defined for NSS databases, e.g. "CT,C,C".
    See **certutil(1)** for more details.  

**pki-server** [*CLI-options*] **instance-externalcert-del** **-i** *instance-ID* **--nickname** *nickname* **--token** *token*  
    This command is to remove a certificate from the certificate database for a PKI server instance.

## OPTIONS

The CLI options are described in **pki-server(8)**.

## OPERATIONS

To view available instance management commands, type **pki-server instance**.
To view each command's usage, type **pki-server instance-&lt;command&gt; --help**.

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
