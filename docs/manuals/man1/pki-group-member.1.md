# pki-group-member 1 "Jun 3, 2015" PKI "PKI Group Member Management Commands"

## NAME

pki-group-member - Command-line interface for managing PKI group members.

## SYNOPSIS

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member**  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-find** *group-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-show** *group-ID* *member-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-add** *group-ID* *member-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-del** *group-ID* *member-ID* [*command-options*]  

## DESCRIPTION

The **pki &lt;subsystem&gt;-group-member** commands provide command-line interfaces to manage group members on the specified subsystem.

Valid subsystems are **ca**, **kra**, **ocsp**, **tks**, and **tps**.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member**  
    This command is to list available group member commands for the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-find** *group-ID* [*command-options*]  
    This command is to list group members in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-show** *group-ID* *member-ID* [*command-options*]  
    This command is to view a group member details in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-add** *group-ID* *member-ID* [*command-options*]  
    This command is to add a member to a group in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-member-del** *group-ID* *member-ID* [*command-options*]  
    This command is to delete a member from a group in the subsystem.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available group commands, type **pki &lt;subsystem&gt;-group-member**.
To view each command's usage, type **pki &lt;subsystem&gt;-group-member-<command> --help**.

All group commands must be executed as the subsystem administrator.

For example, to list members of a CA group execute the following command:

```
$ pki <CA admin authentication> ca-group-member-find testgroup
```

The results can be paged by specifying the (0-based) index of the first entry to return and the maximum number of entries returned:

```
$ pki <CA admin authentication> ca-group-member-find --start 20 --size 10
```

The above command will return entries #20 to #29.

To view a member of a CA group, specify the group ID and the member ID in the following command:

```
$ pki <CA admin authentication> ca-group-member-show testgroup testuser
```

To add a member to a CA group, specify the group ID and the member ID in the following command:

```
$ pki <CA admin authentication> ca-group-member-add testgroup testuser
```

To delete a member from a CA group, specify the group ID and the member ID in the following command:

```
$ pki <CA admin authentication> ca-group-member-del testgroup testuser
```

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
