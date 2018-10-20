Signed Audit Logging Failures
=============================

## Overview

If a PKI subsystem is unable to write signed audit log to disk,
the subsystem will automatically shutdown to prevent it from
receiving and executing additional operations that cannot be
logged.

This situation may happen when the disk is full. In that case
the admin will need to provide additional disk space, then restart
the subsystem.

Note: auto-shutdown will only work if audit signing is enabled.

## Verifying Auto-Shutdown

To verify auto-shutdown on a CA instance, prepare a small
partition and assign the proper permissions:

```
$ mkdir -p /tmp/audit
$ mount -t tmpfs -o size=2M,mode=0755 tmpfs /tmp/audit
$ chown pkiuser:pkiuser /tmp/audit
$ semanage fcontext -a -t pki_tomcat_log_t /tmp/audit
$ restorecon -vR /tmp/audit
```

Configure CA to enable audit signing and to store the logs in the above partition:

```
$ pki-server ca-config-set log.instance.SignedAudit.logSigning true
$ pki-server ca-config-set log.instance.SignedAudit.fileName /tmp/audit/ca_audit
```

Restart the server:

```
$ systemctl restart pki-tomcatd@pki-tomcat.service
```

Create a big file to fill up the partition:

```
$ dd if=/dev/zero of=/tmp/audit/bigfile bs=1M count=2
```

Execute some operations to generate audit logs, for example:

```
$ pki ca-cert-find
```

When the partition becomes full, the server will no longer able
to write the signed audit log into the partition, so it will
generate the following message in console or systemd journal
(assuming the journal is stored in a different partition that
is not full):

```
Unable to flush log "/tmp/audit/ca_audit": No space left on device
```

Then the CA subsystem will shutdown automatically. The server itself
will still be running and accepting connections, but all requests
going to the CA subsystem will fail.

To resolve the issue, create more space in the partition by
removing the big file:

```
$ rm -f /tmp/audit/bigfile
```

Then re-enable the CA subsystem with the following command:

```
$ pki-server subsystem-enable -i pki-tomcat ca
```

or by restarting the server:

```
$ systemctl restart pki-tomcatd@pki-tomcat.service
```

