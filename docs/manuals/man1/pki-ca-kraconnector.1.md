# pki-ca-kraconnector 1 "June 10, 2016" PKI "PKI CA-KRA Connector Management Commands"

## NAME

pki-ca-kraconnector - Command-line interface for managing CA-KRA connectors.

## SYNOPSIS

**pki** [*CLI-options*] **ca-kraconnector**  
**pki** [*CLI-options*] **ca-kraconnector-show**  
**pki** [*CLI-options*] **ca-kraconnector-add** --input-file *input-file*  
**pki** [*CLI-options*] **ca-kraconnector-add** --host *KRA-host* --port *KRA-port*  
**pki** [*CLI-options*] **ca-kraconnector-del** --host *KRA-host* --port *KRA-port*  

## DESCRIPTION

The **pki-ca-kraconnector** commands provide command-line interfaces to manage CA-KRA connectors.
This command should be applied against CAs only.

When keys are archived, the CA communicates with the KRA through authenticated persistent connections called Connectors.
Because the CA initiates the communication, the connector configuration is performed on the CA only.
A Connector is automatically configured on the issuing CA whenever a KRA is set up by **pkispawn**.

A CA may have only one KRA connector.
This connector can be configured to talk to multiple KRAs (for high availability) only if the KRAs are clones.

**pki** [*CLI-options*] **ca-kraconnector**  
    This command is to list available KRA connector commands.

**pki** [*CLI-options*] **ca-kraconnector-show**  
    This command is to view the configuration settings for the CA-KRA connector configured on the CA.
    These details can be redirected to a file, modified as needed, and used as the input file for the **ca-kraconnector-add** command.

**pki** [*CLI-options*] **ca-kraconnector-add** --input-file *input-file*  
    This command is to configure the CA-KRA connector on the CA subsystem.
    The input file is an XML document as provided by the **pki ca-kraconnector-show** command.
    A CA-KRA connector can only be created from an input file only if a connector does not already exist.
    If one already exists, it should be removed first.

**pki** [*CLI-options*] **ca-kraconnector-add** --host *KRA-host* --port *KRA-port*  
    This command is to add a host to an existing CA-KRA connector.

**pki** [*CLI-options*] **ca-kraconnector-del** --host *KRA-host* --port *KRA-port*  
    This command is to delete a host from the CA-KRA connector on a CA.
    If the last KRA host is removed, the connector configuration is removed from the CA.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available CA-KRA connector commands, type **pki ca-kraconnector**.
To view each command's usage, type **pki ca-kraconnector-&lt;command&gt; --help**.

All CA-KRA connector commands must be executed as the CA administrator.

To retrieve the CA-KRA connector configuration from the CA:

```
$ pki <CA admin authentication> ca-kraconnector-show
```

One of the most common use cases for these commands is to add a KRA clone to an existing CA-KRA connector for high availability.
This can be done using the pki ca-kraconnector-add command as shown:

```
$ pki <CA admin authentication> ca-kraconnector-add --host kra2.example.com --port 8443
```

To delete a KRA clone from the connector:

```
$ pki <CA admin authentication> ca-kraconnector-del --host kra2.example.com --port 8443
```

## AUTHOR

Ade Lee &lt;alee@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
