# pki-group 1 "May 5, 2014" PKI "PKI Group Management Commands"

## NAME

pki-group - Command-line interface for managing PKI groups.

## SYNOPSIS

**pki** [*CLI-options*] **&lt;subsystem&gt;-group**  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-find** [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-show** *group-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-add** *group-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-mod** *group-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-group-del** *group-ID* [*command-options*]    

## DESCRIPTION

The **pki &lt;subsystem&gt;-group** commands provide command-line interfaces to manage groups on the specified subsystem.

Valid subsystems are **ca**, **kra**, **ocsp**, **tks**, and **tps**.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group**  
    This command is to list available group commands for the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-find** [*command-options*]  
    This command is to list groups in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-show** *group-ID* [*command-options*]  
    This command is to view a group details in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-add** *group-ID* [*command-options*]  
    This command is to add a group into the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-mod** *group-ID* [*command-options*]  
    This command is to modify a group in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-group-del** *group-ID* [*command-options*]  
    This command is to delete a group from the subsystem.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available group commands, type **pki &lt;subsystem&gt;-group**.
To view each command's usage, type **pki &lt;subsystem&gt;-group-&lt;command&gt; --help**.

All group commands must be executed as the subsystem administrator.

For example, to list groups in CA execute the following command:

```
$ pki <CA admin authentication> ca-group-find
```

The results can be paged by specifying the (0-based) index of the first entry to return and the maximum number of entries returned:

```
$ pki <CA admin authentication> ca-group-find --start 20 --size 10
```

The above command will return entries #20 to #29.

To view a CA group, specify the group ID in the following command:

```
$ pki <CA admin authentication> ca-group-show testgroup
```

To add a CA group, specify the group ID in the following command:

```
$ pki <CA admin authentication> ca-group-add testgroup
```

To modify a CA group, specify the group ID and the attributes to be modified in the following command:

```
$ pki <CA admin authentication> ca-group-mod testgroup --description "Test Group"
```

To delete a CA group, specify the group ID in the following command:

```
$ pki <CA admin authentication> ca-group-del testgroup
```

## SEE ALSO

**pki-group-member(1)**  
    Group member management commands

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi S. Dewata &lt;edewata@redhat.com&gt;,
and Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
