# pki-logging 5 "November 3, 2016" PKI "PKI Common Logging Configuration"

## NAME

pki-logging - PKI Common Logging Configuration

## LOCATION

/usr/share/pki/etc/logging.properties, /etc/pki/logging.properties

## DESCRIPTION

PKI clients and tools use [java.util.logging](https://docs.oracle.com/javase/8/docs/api/java/util/logging/package-summary.html)
(JUL) as the logging framework.

The default logging configuration is located at /usr/share/pki/etc/logging.properties.

By default only log messages with level WARNING or higher will be logged on the console.

```
java.util.logging.ConsoleHandler.level = ALL
java.util.logging.ConsoleHandler.formatter = java.util.logging.SimpleFormatter

java.util.logging.SimpleFormatter.format = %4$s: %5$s%6$s%n

.level = WARNING
.handlers = java.util.logging.ConsoleHandler
```

For more information see the following documents:

- [java.util.logging.ConsoleHandler](https://docs.oracle.com/javase/8/docs/api/java/util/logging/ConsoleHandler.html)
- [java.util.logging.Level](https://docs.oracle.com/javase/8/docs/api/java/util/logging/Level.html)
- [java.util.logging.SimpleFormatter](https://docs.oracle.com/javase/8/docs/api/java/util/logging/SimpleFormatter.html)
- [java.util.Formatter](https://docs.oracle.com/javase/8/docs/api/java/util/Formatter.html)

## CUSTOMIZATION

To customize the logging configuration, copy the default logging configuration into a new location:

```
$ cp /usr/share/pki/etc/logging.properties /etc/pki/logging.properties
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

Then specify the location of the custom logging configuration in the following parameter in /etc/pki/pki.conf:

```
PKI_LOGGING_CONFIG=/etc/pki/logging.properties
```

Then restart the application.

## SEE ALSO

**pki-server-logging(5)**

## AUTHORS

Dogtag PKI Team &lt;pki-devel@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
