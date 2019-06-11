# pki-upgrade 8 "Jul 22, 2013" PKI "PKI Upgrade Tool"

## NAME

pki-upgrade - Tool for upgrading system-wide PKI configuration.

## SYNOPSIS

**pki-upgrade** [*OPTIONS*]

## DESCRIPTION

There are two parts to upgrading PKI system: upgrading the system configuration files used by both the client
and the server processes and upgrading the server configuration files.

When upgrading PKI system, the existing system configuration files (e.g. /etc/pki/pki.conf)
may need to be upgraded because the content may have changed from one version to another.
The configuration upgrade is executed automatically during RPM upgrade.
However, in case there is a problem, the process can also be run manually using **pki-upgrade**.

The system upgrade process is done incrementally using upgrade scriptlets.
The upgrade process and scriptlet execution is monitored in upgrade trackers.
A counter shows the latest index number for the most recently executed scriptlet;
when all scriptlets have run, the component tracker shows the updated version number.

The upgrade scriptlets are stored in /usr/share/pki/upgrade/*version*/*index*-*name*.
The *version* is the system version to be upgraded.
The *index* is the script execution order.
The *name* is the scriptlet name.

During upgrade, the scriptlets will back up all changes to the filesystem into /var/log/pki/upgrade/*version*/*index*.
The *version* and *index* values indicate the scriptlet being executed.
A copy of the files and folders that are being modified or removed will be stored in **oldfiles**.
The names of the newly-added files and folders will be stored in **newfiles**.

The system upgrade process is tracked in /etc/pki/pki.version.
The file stores the current configuration version and the last successful scriptlet index.

## OPTIONS

### General options

**--silent**  
    Upgrade in silent mode.

**--status**  
    Show upgrade status only **without** performing the upgrade.

**--revert**  
    Revert the last version.

**-X**  
    Show advanced options.

**-v**, **--verbose**  
    Run in verbose mode.

**-h**, **--help**  
    Show this help message.

### Advanced options

The advanced options circumvent the normal component tracking process by changing the
scriptlet order or changing the tracker information.

**WARNING:** These options may render the system unusable.

**--scriptlet-version** *version*  
    Run scriptlets for a specific version only.

**--scriptlet-index** *index*  
    Run a specific scriptlet only.

**--remove-tracker**  
    Remove the tracker.

**--reset-tracker**  
    Reset the tracker to match the package version.

**--set-tracker** *version*  
    Set the tracker to a specific version.

## OPERATIONS

### Interactive mode

By default, **pki-upgrade** will run interactively.
It will ask for a confirmation before executing each scriptlet.

```
$ pki-upgrade
```

If there is an error, it will stop and show the error.

### Silent mode

The upgrade process can also be done silently without user interaction:

```
$ pki-upgrade --silent
```

If there is an error, it will stop and show the error.

### Checking upgrade status

It is possible to check the status of a running upgrade process.

```
$ pki-upgrade --status
```

### Troubleshooting

If there is an error, rerun the upgrade in verbose mode:

```
$ pki-upgrade --verbose
```

Check the scriptlet to see which operations are being executed.
Once the error is identified and corrected, the upgrade can be resumed by re-running **pki-upgrade**.

It is possible to rerun a failed script by itself, specifying the instance and subsystem,
version, and scriptlet index:

```
$ pki-upgrade --scriptlet-version 10.0.1 --scriptlet-index 1
```

### Reverting an upgrade

If necessary, the upgrade can be reverted:

```
$ pki-upgrade --revert
```

Files and folders that were created by the scriptlet will be removed.
Files and folders that were modified or removed by the scriptlet will be restored.

## FILES

/usr/sbin/pki-upgrade

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Ella Deon Lackey &lt;dlackey@redhat.com&gt;, and Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2013 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
