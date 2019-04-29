# pki-server-logging 5 "November 3, 2016" PKI "PKI Server Logging Configuration"

## NAME

pki-server-logging - PKI Server Logging Configuration

## LOCATION

/etc/pki/*instance*/logging.properties, /etc/pki/*instance*/*subsystem*/CS.cfg

## DESCRIPTION

PKI server logging can be configured using the following logging frameworks:

- [java.util.logging](https://docs.oracle.com/javase/8/docs/api/java/util/logging/package-summary.html)
- Internal Logging

### java.util.logging

Tomcat uses java.util.logging (JUL) as the default logging framework.
The configuration is described in [Tomcat 7 Logging](http://tomcat.apache.org/tomcat-7.0-doc/logging.html)
and [Tomcat 8 Logging](http://tomcat.apache.org/tomcat-8.0-doc/logging.html).

The default configuration is located at /usr/share/pki/server/conf/logging.properties.
During server deployment a link will be created at /etc/pki/*instance*/logging.properties.

By default only log messages with level WARNING or higher will be logged on the console (i.e. systemd journal).

```
java.util.logging.ConsoleHandler.level = ALL
java.util.logging.ConsoleHandler.formatter = java.util.logging.SimpleFormatter

java.util.logging.SimpleFormatter.format = %4$s: %5$s%6$s%n

.level = WARNING
.handlers = java.util.logging.ConsoleHandler
```

The systemd journal can be viewed with the following command:

```
$ journalctl -u pki-tomcatd@<instance>.service
```

For more information see the following documents:

- [java.util.logging.ConsoleHandler](https://docs.oracle.com/javase/8/docs/api/java/util/logging/ConsoleHandler.html)
- [java.util.logging.Level](https://docs.oracle.com/javase/8/docs/api/java/util/logging/Level.html)
- [java.util.logging.SimpleFormatter](https://docs.oracle.com/javase/8/docs/api/java/util/logging/SimpleFormatter.html)
- [java.util.Formatter](https://docs.oracle.com/javase/8/docs/api/java/util/Formatter.html)

### Internal Logging

Each PKI subsystem uses an internal logging framework for debugging purposes.

The logging configuration is stored in /etc/pki/*instance*/*subsystem*/CS.cfg.

```
debug.enabled=true
debug.level=0
debug.filename=/var/lib/pki/<instance>/logs/<subsystem>/debug
```

The **debug.enabled** determines whether the debug log is enabled. By default it is enabled.

The **debug.level** determines the amount of details to be logged.
The value ranges from 0 (most details) to 10 (least details).
The default is 0.

The **debug.filename** determines the debug log file location.
By default it is located at /var/lib/pki/*instance*/logs/*subsystem*/debug.

## CUSTOMIZATION

###  java.util.logging

To customize JUL configuration, replace the link with a copy of the default configuration:

```
$ rm -f /etc/pki/<instance>/logging.properties
$ cp /usr/share/pki/server/conf/logging.properties /etc/pki/<instance>
$ chown pkiuser.pkiuser /etc/pki/<instance>/logging.properties
```

Then edit the file as needed.
For example, to troubleshoot issues with PKI library add the following lines:

```
netscape.level = ALL
com.netscape.level = ALL
org.dogtagpki.level = ALL
```

To troubleshoot issues with RESTEasy add the following line:

```
org.jboss.resteasy.level = ALL
```

Then restart the server.

### Internal Logging

To customize the internal logging configuration, edit the CS.cfg as needed, then restart the server.

## AUTHORS

Dogtag PKI Team &lt;pki-devel@redhat.com&gt;.

## SEE ALSO

**pki-logging(5)**

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
