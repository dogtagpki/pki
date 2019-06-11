# pki-tps-profile 1 "Jul 14, 2015" PKI "PKI TPS Profile Management Commands"

## NAME

pki-tps-profile - Command-line interface for managing PKI TPS profiles.

## SYNOPSIS

**pki** [*CLI-options*] **tps-profile**  
**pki** [*CLI-options*] **tps-profile-find** [*command-options*]  
**pki** [*CLI-options*] **tps-profile-show** *profile-ID* [*command-options*]  
**pki** [*CLI-options*] **tps-profile-add** --input *file-path* [*command-options*]  
**pki** [*CLI-options*] **tps-profile-mod** *profile-ID* --action *action* [*command-options*]  
**pki** [*CLI-options*] **tps-profile-mod** *profile-ID* --input *file-path* [*command-options*]  
**pki** [*CLI-options*] **tps-profile-del** *profile-ID* [*command-options*]  

## DESCRIPTION

The **pki tps-profile** commands provide command-line interfaces to manage profiles on the TPS.

**pki** [*CLI-options*] **tps-profile-find** [*command-options*]  
    This command is to list the profiles.

**pki** [*CLI-options*] **tps-profile-show** *profile-ID* [*command-options*]  
    This command is to view the details of a profile.

**pki** [*CLI-options*] **tps-profile-add** --input *file-path* [*command-options*]  
    This command is to create a new profile.

**pki** [*CLI-options*] **tps-profile-mod** *profile-ID* --action *action* [*command-options*]  
    This command is to change the status of a profile.

**pki** [*CLI-options*] **tps-profile-mod** *profile-ID* --input *file-path* [*command-options*]  
    This command is to modify an existing profile.

**pki** [*CLI-options*] **tps-profile-del** *profile-ID* [*command-options*]  
    This command is to delete a profile.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available profile commands, type **pki tps-profile**.
To view each command's usage, type **pki tps-profile-&lt;command&gt; --help**.

All the **pki tps-profile** commands require TPS admin or agent authentication.

### Listing profiles

To list all profile:

```
$ pki <TPS admin/agent authentication> tps-profile-find
```

The results can be paged using the **--start** and **--size** options described in **pki(1)**.

### Viewing a profile

To view the status and properties of a profile:

```
$ pki <TPS admin/agent authentication> tps-profile-show <profile ID>
```

To store the output of the above operation into a file:

```
$ pki <TPS admin/agent authentication> tps-profile-show <profile ID> --output <file path>
```

### Adding a profile

To add a new profile, prepare an input file specifying the profile properties in the following format:

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Profile id="..." xmlns:ns2="http://www.w3.org/2005/Atom">
    <Properties>
        <Property name="...">...</Property>
        ...
    </Properties>
</Profile>
```

The profile properties are described in **pki-tps-profile(5)**.
Then execute the following command:

```
$ pki <TPS admin authentication> tps-profile-add --input <file path>
```

### Changing profile status

To change the profile status execute the following command:

```
$ pki <TPS admin/agent authentication> tps-profile-mod <profile ID> --action <action>
```

Available actions for admins: submit, cancel.
Available actions for agents: approve, reject.
Available actions for users with both admin and agent rights: enable, disable.

### Modifying a profile

To modify a profile, first disable the profile using the **tps-profile-mod --action disable** command.
Then download the current profile properties using the **tps-profile-show --output** command.
Make the modifications in the file, then upload the updated file using the following command:

```
$ pki <TPS admin authentication> tps-profile-mod <profile ID> --input <file path>
```

Finally, the profile should be re-enabled using the **tps-profile-mod --action enable** command.

### Deleting a profile

To delete a profile, first disable the profile using the **tps-profile-mod --action disable** command, then execute:

```
$ pki <TPS admin authentication> tps-profile-del <profile ID>
```

## SEE ALSO

**pki(1)**, **pki-tps-profile(5)**

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
