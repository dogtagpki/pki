# pki-audit 1 "Jun 30, 2015" PKI "PKI Audit Management Commands"

## NAME

pki-audit - Command-line interface for managing PKI audit configuration.

## SYNOPSIS

**pki** [*CLI-options*] **&lt;subsystem&gt;-audit**  
**pki** [*CLI-options*] **&lt;subsystem&gt;-audit-show** [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-audit-mod** **--action** *action* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-audit-mod** **--input** *input-file* [*command-options*]  

## DESCRIPTION

The **pki-audit** commands provide command-line interfaces to manage audit configuration in the specified subsystem.
Currently the only supported subsystem is **tps**.

**pki** [*CLI-options*] **&lt;subsystem&gt;-audit**  
    This command is to list the available audit commands for the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-audit-show** [*command-options*]  
    This command is to show the audit configuration in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-audit-mod** **--action** *action* [*command-options*]  
    This command is to change the audit (enabled/disabled) status in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-audit-mod** **--input** *input-file* [*command-options*]  
    This command is to modify the audit configuration in the subsystem.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available audit commands, type **pki &lt;subsystem&gt;-audit**.
To view each command's usage, type **pki &lt;subsystem&gt;-audit-&lt;command&gt; --help**.

All audit commands must be executed with the subsystem's admin authentication
(the user must be in the Administrators group).
See also the Authentication section in **pki(1)**.

### Viewing audit configuration

To view the audit configuration in TPS execute the following command:

```
$ pki <TPS admin authentication> tps-audit-show
```

To download the audit configuration from TPS into a file execute the following command:

```
$ pki <TPS admin authentication> tps-audit-show --output <output file>
```

### Changing audit status

To enable/disable audit in TPS, execute the following command:

```
$ pki <TPS admin authentication> tps-audit-mod --action <action>
```

where action is enable or disable.

### Modifying audit configuration

To modify the audit configuration in TPS, download the current configuration
using the above **tps-audit-show** command, edit the file,
then execute the following command:

```
$ pki <TPS admin authentication> tps-audit-mod --input <input file>
```

Optionally, a --output *output-file* option may be specified
to download the effective configuration after the modification.

## SEE ALSO

**pki(1)**

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
