# pki-ca-profile 1 "Sep 30, 2014" PKI "PKI CA Profile Management Commands"

## NAME

pki-profile - Command-line interface for managing PKI CA profiles.

## SYNOPSIS

**pki** [*CLI-options*] **ca-profile**  
**pki** [*CLI-options*] **ca-profile-find** [*command-options*]  
**pki** [*CLI-options*] **ca-profile-show** *profile-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-profile-add** *input-file* [*command-options*]  
**pki** [*CLI-options*] **ca-profile-mod** *input-file* [*command-options*]  
**pki** [*CLI-options*] **ca-profile-del** *profile-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-profile-enable** *profile-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-profile-disable** *profile-ID* [*command-options*]  

## DESCRIPTION

The **pki ca-profile** commands provide command-line interfaces to manage profiles on the CA.

**pki** [*CLI-options*] **ca-profile-find** [*command-options*]  
    This command is to list the profiles.

**pki** [*CLI-options*] **ca-profile-show** *profile-ID* [*command-options*]  
    This command is to view the details of a profile.

**pki** [*CLI-options*] **ca-profile-add** *input-file* [*command-options*]  
  This command is to create a new profile.

**pki** [*CLI-options*] **ca-profile-mod** *input-file* [*command-options*]  
    This command is to modify an existing profile.

**pki** [*CLI-options*] **ca-profile-del** *profile-ID* [*command-options*]  
    This command is to delete a profile.

**pki** [*CLI-options*] **ca-profile-enable** *profile-ID* [*command-options*]  
    This command is to enable a profile.

**pki** [*CLI-options*] **ca-profile-disable** *profile-ID* [*command-options*]  
    This command is to disable a profile.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available profile commands, type **pki ca-profile**.
To view each command's usage, type **pki ca-profile-&lt;command&gt; --help**.

All the **pki ca-profile** commands require CA agent authentication.

### Viewing the profiles

```
$ pki <CA agent authentication> ca-profile-find
```

The results can be paged using the **--start** and **--size** options described in **pki(1)**.

To view the contents of a profile:

A set of profile inputs, profile outputs, authenticators, policies and constraints are defined in a profile.
These contents can be viewed using the following command:

```
$ pki <CA agent authentication> ca-profile-show <profile ID>
```

To store the output of the above operation, the output option must be specified.

```
$ pki <CA agent authentication> ca-profile-show <profile ID> --output <file path>
```

This output file can be used for modifying the profile.
It can be used as a template for certificate enrollment as well but, a more suitable template can be fetched using the **pki cert-request-profile-show** command.
The **pki cert-request-profile-show** command does not require an agent/administrator level authentication and contains only the profile inputs section (which is required for certificate enrollment).

### Add/Modify/Delete a profile

```
$ pki <CA admin authentication> ca-profile-add <input file>
```

The contents of the input file must be in an XML format returned by the ca-profile-show command.
This data will be marshaled by the CLI client to create a new profile in the CA.
The profile must be disabled before it is modified. It must be enabled after modification to be used for
certificate enrollment.

To modify an existing profile:

```
$ pki <CA admin authentication> ca-profile-mod <input file>
```

The profile data can be retrieved using the ca-profile-show command and after editing the file,
it can be provided to the profile-mod command to modify an existing profile.

To delete a profile in the CA:

```
$ pki <CA admin authentication> ca-profile-del <profile ID>
```

### Enabling/Disabling a profile in the CA

To enable a profile in the CA:

```
$ pki <CA agent authenticaton> ca-profile-enable <profile ID>
```

A profile must be enabled before it can be used.

To disable a profile in the CA:

```
$ pki <CA agent authentication> ca-profile-disable <profile ID>
```

A profile must be disabled before it can be modified.

**Note:**
Modifying or deleting a profile requires user(s) that have two roles (admin and agent).
The same user may be in both roles.
An agent is needed to first disable the profile.
Once the profile is disabled, it can be modified/deleted by an admin user.
Then, an agent is needed to enable the profile for use by the CA.

## SEE ALSO

**pki(1)**

## AUTHORS

Abhishek Koneru &lt;akoneru@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
