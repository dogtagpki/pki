# pki-server-nuxwdog 8 "December 20, 2018" PKI "PKI Nuxwdog Management Commands"

## NAME

pki-server-nuxwdog - Command-line interface for enabling PKI server instances to start using **nuxwdog**.

## SYNOPSIS

**pki-server** [*CLI-options*] **nuxwdog**  
**pki-server** [*CLI-options*] **nuxwdog-enable**  
**pki-server** [*CLI-options*] **nuxwdog-disable**  

## DESCRIPTION

When a PKI server instance starts, it reads a plain text configuration file
(i.e. /etc/pki/*instance_name*/password.conf) to obtain passwords needed to initialize the server.
This could include passwords needed to access server keys in hardware or software cryptographic modules,
or passwords to establish database connections.

While this file is protected by file and SELinux permissions,
it is even more secure to remove this file entirely, and have the server prompt for these passwords on startup.
This means of course that it will not be possible to start the PKI server instance unattended,
including on server reboots.

**nuxwdog** is a mechanism to start PKI server without storing passwords in file (i.e. password.conf);
but prompt the administrator for the relevant passwords.
These passwords will be cached securely in the kernel keyring.
If the CS instance crashes unexpectedly, **systemd** will attempt to restart the instance using the cached passwords.

PKI server instances need to be reconfigured to use **nuxwdog** to start.
Not only are changes required in instance configuration files,
but instances need to use a different systemd unit file to start.
See details in the **Operations** section.

**pki-server nuxwdog** commands provide a mechanism to reconfigure instances
to either start or not start with **nuxwdog**.

**pki-server** [*CLI-options*] **nuxwdog**  
    This command is to list available **nuxwdog** commands.

**pki-server** [*CLI-options*] **nuxwdog-enable**  
    This command is to reconfigure ALL local PKI server instances to start using **nuxwdog**.
    To reconfigure a particular PKI server instance only, use **pki-server instance-nuxwdog-enable**.

**pki-server** [*CLI-options*] **nuxwdog-disable**  
    This command is to reconfigure ALL local PKI server instances to start without using **nuxwdog**.
    To reconfigure a particular PKI server instance only, use **pki-server instance-nuxwdog-disable**.
    Once this operation is complete, instances will need to read a  **password.conf** file in order to start up.

## OPTIONS

The CLI options are described in **pki-server(8)**.

## OPERATIONS

Configuring a PKI server instance to start using **nuxwdog** requires changes
to instance configuration files such as **server.xml**.
These changes are performed by **pki-server**.

Once a subsystem has been converted to using **nuxwdog**, the **password.conf** file is no longer needed.
It can be removed from the filesystem.
Be sure, of course, to note all passwords contained therein - some of which may be randomly generated during the install.

**Note:** If a subsystem stores any of its system certificates in a cryptographic token other than the internal NSS database,
it will have entries in **password.conf** that look like **hardware-TOKEN_NAME=password**.
In this case, an additional parameter must be added to CS.cfg.

```
cms.tokenList=TOKEN_NAME
```

When this parameter is added, nuxwdog will prompt the password for
**hardware-TOKEN_NAME** in addition to the other passwords.

An instance that is started by **nuxwdog** is started by a different systemd unit file (**pki-tomcatd-nuxwdog**).
Therefore, to start/stop/restart an instance using the following:

```
$ systemctl <start/stop/restart> pki-tomcatd-nuxwdog@<instance_id>.service
```

If the PKI server instance is converted back to not using **nuxwdog** to start,
then the usual systemd unit scripts can be invoked:

```
$ systemctl <start/stop/restart> pki-tomcatd@<instance_id>.service
```

## SEE ALSO

**pki-server(8)**  
    PKI server management commands

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt; and Dinesh Prasanth M K &lt;dmoluguw@redhat.com&gt;

## COPYRIGHT

Copyright (c) 2018 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
