# pki-user-membership 1 "Aug 24, 2015" PKI "PKI User Membership Management Commands"

## NAME

pki-user-membership - Command-line interface for managing PKI user memberships.

## SYNOPSIS

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership**  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership-find** *user-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership-add** *user-ID* *group-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership-del** *user-ID* *group-ID* [*command-options*]  

## DESCRIPTION

The **pki &lt;subsystem&gt;-user-membership** commands provide command-line interfaces to manage user memberships on the specified subsystem.

Valid subsystems are **ca**, **kra**, **ocsp**, **tks**, and **tps**.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership**  
    This command is to list available user membership commands for the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership-find** *user-ID* [*command-options*]  
    This command is to list groups in which the subsystem user is a member.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership-add** *user-ID* *group-ID* [*command-options*]  
    This command is to add the subsystem user into a group.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-membership-del** *user-ID* *group-ID* [*command-options*]  
    This command is to delete the subsystem user from a group.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available user membership commands, type **pki &lt;subsystem&gt;-user-membership**.
To view each command's usage, type **pki &lt;subsystem&gt;-user-membership-&lt;command&gt; --help**.

All user membership commands must be executed as the subsystem administrator.

For example, to list groups in which a CA user is a member execute the following command:

```
$ pki <CA admin authentication> ca-user-membership-find testuser
```

The results can be paged by specifying the (0-based) index of the first entry to return and the maximum number of entries returned:

```
$ pki <CA admin authentication> ca-user-membership-find testuser --start 20 --size 10
```

The above command will return entries #20 to #29.

To add a CA user into a group, specify the user ID and the group ID in the following command:

```
$ pki <CA admin authentication> ca-user-membership-add testuser Administrators
```

To delete a CA user from a group, specify the user ID and the group ID in the following command:

```
$ pki <CA admin authentication> ca-user-membership-del testuser Administrators
```

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
