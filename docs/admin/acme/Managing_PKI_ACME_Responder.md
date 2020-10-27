Managing PKI ACME Responder
===========================

## Overview

This document describes how to manage PKI ACME responder.

## Enabling/Disabling ACME Services

Users that belong to the Administrators group can enable or disable services in PKI ACME responder.
The user can authenticate either with basic authentication or client certificate authentication.

To enable/disable ACME services with basic authentication, specify the username and password:

```
$ pki -u <username> -p <password> acme-<enable/disable>
```

To enable/disable ACME services with client certificate authentication,
specify the certificate nickname and NSS database password:

```
$ pki -n <nickname> -c <password> acme-<enable/disable>
```


## See Also

* [Installing PKI ACME Responder](../../installation/acme/Installing_PKI_ACME_Responder.md)
* [Using PKI ACME Responder](../../user/acme/Using_PKI_ACME_Responder.md)
