Using PKI ACME Responder
========================

## Overview

This document describes how to use PKI ACME responder.

## Checking PKI ACME Responder Status

To check the status of PKI ACME responder, execute the following command:

```
$ pki acme-info
  Status: Available
  Terms of Service: https://www.example.com/acme/tos.pdf
  Website: https://www.example.com
  CAA Identities: example.com
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
