# pki-server-acme 8 "Feb 24, 2020" PKI "PKI ACME Responder Management Commands"

## NAME

pki-server-acme - Command-line interface for managing PKI ACME responder.

## SYNOPSIS

**pki-server** [*CLI-options*] **acme-create** [*command-options*]  
**pki-server** [*CLI-options*] **acme-remove** [*command-options*]  
**pki-server** [*CLI-options*] **acme-deploy** [*command-options*]  
**pki-server** [*CLI-options*] **acme-undeploy** [*command-options*]  

## DESCRIPTION

The **pki-server acme** commands provide command-line interfaces to manage PKI ACME responder.

**pki-server** [*CLI-options*] **acme** [*command-options*]  
    This command is to list available PKI ACME responder management commands.

**pki-server** [*CLI-options*] **acme-create** [*command-options*]  
    This command is to create the initial PKI ACME responder configuration files in PKI server.
    The configuration files will be stored in in /var/lib/pki/&lt;instance&gt;/conf/acme folder.
    The files can be customized before deployment.

**pki-server** [*CLI-options*] **acme-remove** [*command-options*]  
    This command is to remove PKI ACME responder configuration files from PKI server.
    The /var/lib/pki/&lt;instance&gt;/conf/acme folder and its contents will be removed.

**pki-server** [*CLI-options*] **acme-deploy** [*command-options*]  
    This command is to deploy and start PKI ACME responder in PKI server.
    It will create a deployment descriptor at /var/lib/pki/&lt;instance&gt;/conf/Catalina/localhost/acme.xml.

**pki-server** [*CLI-options*] **acme-undeploy** [*command-options*]  
    This command is to shutdown and undeploy PKI ACME responder from PKI server.
    It will remove the deployment descriptor at /var/lib/pki/&lt;instance&gt;/conf/Catalina/localhost/acme.xml.

## SEE ALSO

**pki-server(8)**  
    PKI server management commands

## AUTHORS

Endi S. Dewata &lt;endisd@redhat.com&gt;

## COPYRIGHT

Copyright (c) 2020 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
