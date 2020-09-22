Using PKI ACME Responder
========================

## Overview

This document describes how to use PKI ACME responder.

**Note:** The PKI ACME responder is currently a tech preview which means:
* It is not intended for production.
* It may corrupt your data.
* There is no guarantee for correctness, security, or performance.
* There is no guarantee for documentation or support.
* The API, configuration, or the database may change in the future.
* There may be no easy upgrade path to the future version.

## Checking PKI ACME Responder Status

To check the status of PKI ACME responder, execute the following command:

```
$ pki acme-info
  Status: Available
  Terms of Service: https://www.dogtagpki.org/wiki/PKI_ACME_Responder
  Website: https://www.dogtagpki.org
  CAA Identities: dogtagpki.org
  External Account Required: false
```

If the services are disabled, the command will show the following result:

```
$ pki acme-info
  Status: Unavailable
```

## Supported ACME Clients

* [Certbot](Using_PKI_ACME_Responder_with_Certbot.md)

## See Also

* [Installing PKI ACME Responder](../../installation/acme/Installing_PKI_ACME_Responder.md)
* [Managing PKI ACME Responder](../../admin/acme/Managing_PKI_ACME_Responder.md)
