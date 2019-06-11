# pki-server-subsystem 8 "July 15, 2015" PKI "PKI Subsystem Commands"

## NAME

pki-server-subsystem - Command-line interface for managing PKI subsystems.

## SYNOPSIS

**pki-server** [*CLI-options*] **subsystem**  
**pki-server** [*CLI-options*] **subsystem-find**  
**pki-server** [*CLI-options*] **subsystem-show** *subsystem-ID*  
**pki-server** [*CLI-options*] **subsystem-enable** *subsystem-ID*  
**pki-server** [*CLI-options*] **subsystem-disable** *subsystem-ID*  
**pki-server** [*CLI-options*] **subsystem-cert-find** *subsystem-ID*  
**pki-server** [*CLI-options*] **subsystem-cert-show** *subsystem-ID* *cert-ID*  
**pki-server** [*CLI-options*] **subsystem-cert-export** *subsystem-ID* *cert-ID*  
**pki-server** [*CLI-options*] **subsystem-cert-update** *subsystem-ID* *cert-ID*  

## DESCRIPTION

The **pki-server subsystem** commands provide command-line interfaces to manage PKI subsystems.
A PKI server instance consists of a single Apache Tomcat instance that contains one or more PKI subsystems.
Valid subsystem identifiers are **ca**, **kra**, **tks**, **ocsp** and **tps**.
No instance may have more than one of each type of subsystem.

**pki-server subsystem** commands perform operations on a specific subsystem within a PKI server instance.
Consequently, all **pki-server subsystem** commands require specification of the instance ID to completely identify the target subsystem.

Operations that are available include: listing subsystems in an instance;
showing details about a subsystem; and enabling and disabling subsystems.

**pki-server** [*CLI-options*] **subsystem**  
    This command is to list available subsystem commands.

**pki-server** [*CLI-options*] **subsystem-find**  
    This command is to list subsystems within a specific instance.

**pki-server** [*CLI-options*] **subsystem-show** *subsystem-ID*  
    This command is to view the details about a particular subsystem.

**pki-server** [*CLI-options*] **subsystem-enable** *subsystem-ID*  
    This command is to enable a particular subsystem.
    Each subsystem consists of a web application within the Apache Tomcat instance.
    Enabling a subsystem means deploying the web application so that the application initializes
    and is accessible via the HTTP and HTTPS ports for the Apache Tomcat instance.

**Note:** Each subsystem runs a set of self-tests on startup.
If these self-tests fail, the subsystem will be disabled by undeploying the web application.
The deployment status (enabled/disabled) of the subsystem can be determined from the output of **pki-server subsystem-show**.
Once the underlying problem is fixed, the subsystem should be re-enabled using **pki-server subsystem-enable**.

**pki-server** [*CLI-options*] **subsystem-disable** *subsystem-ID*  
    This command is to disable a subsystem by undeploying the web application corresponding to the subsystem.
    The subsystem will no longer be accessible through the web interfaces.
    This is useful when specific subsystems need to be made inaccessible for maintenance
    as Apache Tomcat allows web applications to be deployed/undeployed while the instance is still running (hot deployment).

**pki-server** [*CLI-options*] **subsystem-cert-find** *subsystem-ID*  
    This command is to list system certificates in a particular subsystem.

**pki-server** [*CLI-options*] **subsystem-cert-show** *subsystem-ID* *cert-ID*  
    This command is to view the details about a system certificate in a particular subsystem.

**pki-server** [*CLI-options*] **subsystem-cert-export** *subsystem-ID* *cert-ID*  
    This command is to export a system certificate in a particular subsystem.

**pki-server** [*CLI-options*] **subsystem-cert-update** *subsystem-ID* *cert-ID*  
    This command is to update a system certificate in a particular subsystem.

## OPTIONS

The CLI options are described in **pki-server(8)**.

## OPERATIONS

To view available subsystem management commands, type **pki-server subsystem**.
To view each command's usage, type **pki-server subsystem-&lt;command&gt; --help**.

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
