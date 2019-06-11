# pki-securitydomain 1 "May 5, 2014" PKI "PKI Security Domain Management Commands"

## NAME

pki-securitydomain - Command-line interface for managing PKI security domain.

## SYNOPSIS

**pki** [*CLI-options*] **securitydomain**  
**pki** [*CLI-options*] **securitydomain-show** [*command-options*]  

## DESCRIPTION

The **pki-securitydomain** commands provide command-line interfaces to manage the security domain.

**pki** [*CLI-options*] **securitydomain**  
    This command is to list available security domain commands.

**pki** [*CLI-options*] **securitydomain-show** [*command-options*]  
    This command is to show the contents of the security domain.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available security domain commands, type **pki securitydomain**.
To view each command's usage, type **pki securitydomain-&lt;command&gt; --help**.

To show the contents of the security domain:

```
$ pki <security domain admin authentication> securitydomain-show
```

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi S. Dewata &lt;edewata@redhat.com&gt;, and Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
