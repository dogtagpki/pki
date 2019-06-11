# pki-user 1 "May 5, 2014" PKI "PKI User Management Commands"

## NAME

pki-user - Command-line interface for managing PKI users.

## SYNOPSIS

**pki** [*CLI-options*] **&lt;subsystem&gt;-user**  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-find** [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-show** *user-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-add** *user-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-mod** *user-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-del** *user-ID* [*command-options*]  

## DESCRIPTION

The **pki &lt;subsystem&gt;-user** commands provide command-line interfaces to manage users on the specified subsystem.

Valid subsystems are **ca**, **kra**, **ocsp**, **tks**, and **tps**.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user**  
    This command is to list available user commands for the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-find** [*command-options*]  
    This command is to list users in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-show** *user-ID* [*command-options*]  
    This command is to view a user details in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-add** *user-ID* [*command-options*]  
    This command is to add a user into the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-mod** *user-ID* [*command-options*]  
    This command is to modify a user in the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-del** *user-ID* [*command-options*]  
    This command is to delete a user from the subsystem.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available user commands, type **pki &lt;subsystem&gt;-user**.
To view each command's usage, type **pki &lt;subsystem&gt;-user-&lt;command&gt; --help**.

All user commands must be executed as the subsystem administrator.

For example, to list users in CA execute the following command:

```
$ pki <CA admin authentication> ca-user-find
```

The results can be paged by specifying the (0-based) index of the first entry to return and the maximum number of entries returned:

```
$ pki <CA admin authentication> ca-user-find --start 20 --size 10
```

The above command will return entries #20 to #29.

To view the details of a CA user, specify the user ID in the following command:

```
$ pki <CA admin authentication> ca-user-show testuser
```

To add a new CA user, specify the user ID and at least the full name in the following command:

```
$ pki <CA admin authentication> ca-user-add testuser --fullName "Test User"
```

To modify a CA user, specify the user ID and the attributes to be changed in the following command:

```
$ pki <CA admin authentication> ca-user-mod testuser \
    --email testuser@example.com --phone 123-456-7890
```

To delete a CA user, specify the user ID in the following command:

```
$ pki <CA admin authentication> ca-user-del testuser
```

## SEE ALSO

**pki-user-cert(1)**  
    User certificate management commands

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi Dewata &lt;edewata@redhat.com&gt;, and Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
