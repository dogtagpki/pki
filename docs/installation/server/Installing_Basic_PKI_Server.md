# Installing Basic PKI Server

## Overview

This page describes the process to create and configure a basic PKI server without any of the PKI subsystems.
This would be useful to troubleshoot general server issues (e.g. SSL).

## Installation

To install PKI server packages:

```
$ dnf install pki-server
```

## Creating PKI Server

To create a PKI server:

```
$ pki-server create
```

This will create a PKI server in /var/lib/pki/pki-tomcat.

See also [PKI Server CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-CLI).

## Starting PKI Server

To start PKI server:

```
$ pki-server run
```

To stop the server, press Ctrl-C.

## See Also

- [Configuring HTTPS Connector](Configuring-HTTPS-Connector.adoc)
