# pki-server-est 8 "Jul 1, 2022" PKI "PKI EST subsystem management commands"

## NAME

pki-server-est - Command-line interface for managing PKI EST subsystem.

## SYNOPSIS

**pki-server** [*CLI-options*] **est-create** [*command-options*]
**pki-server** [*CLI-options*] **est-remove** [*command-options*]
**pki-server** [*CLI-options*] **est-deploy** [*command-options*]
**pki-server** [*CLI-options*] **est-undeploy** [*command-options*]

## DESCRIPTION

The **pki-server est** commands provide command-line interfaces to manage
the PKI Enrollment over Secure Transport (EST) subsystem.

**pki-server** [*CLI-options*] **est** [*command-options*]
    List PKI EST management commands.

**pki-server** [*CLI-options*] **est-create** [*command-options*]
    Create the initial PKI EST subsystem configuration files in PKI server.
    The configuration files will be stored in in /var/lib/pki/&lt;instance&gt;/conf/est folder.
    The files can be customized before deployment.

**pki-server** [*CLI-options*] **est-remove** [*command-options*]
    Remove PKI EST responder configuration files from PKI server.
    The /var/lib/pki/&lt;instance&gt;/conf/est folder and its contents will be removed.

**pki-server** [*CLI-options*] **est-deploy** [*command-options*]
    Deploy and start the PKI EST service in PKI server.
    It creates a deployment descriptor at /var/lib/pki/&lt;instance&gt;/conf/Catalina/localhost/est.xml.

**pki-server** [*CLI-options*] **est-undeploy** [*command-options*]
    Stop and undeploy the PKI EST service from PKI server.
    It removes the deployment descriptor at /var/lib/pki/&lt;instance&gt;/conf/Catalina/localhost/est.xml.

## SEE ALSO

**pki-server(8)**
    PKI server management commands

## COPYRIGHT

Copyright (c) 2022 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
