Deploying openshift-acme on OpenShift
=====================================

## Overview

This document describes the process to deploy [openshift-acme](https://github.com/tnozicka/openshift-acme)
to issue certificates for applications on OpenShift automatically using a PKI ACME responder.

## Prerequisite

Prepare a PKI ACME responder either as a [standalone server](../acme/Installing_PKI_ACME_Responder.md)
or as a [container deployed on OpenShift](Deploying_PKI_ACME_Responder_on_OpenShift.md).
A demo PKI ACME responder is available at https://pki.demo.dogtagpki.org/acme/directory.

| WARNING: Do not use the demo PKI ACME responder in production environment since it uses an untrusted CA certificate. |
| --- |

## Deploying openshift-acme with PKI ACME Responder

To deploy openshift-acme, get the source with the following commands:

```
$ git clone https://github.com/tnozicka/openshift-acme.git
$ cd openshift-acme
```

A sample openshift-acme configuration for a single namespace is available at:

- [deploy/single-namespace/role.yaml](https://github.com/tnozicka/openshift-acme/blob/master/deploy/single-namespace/role.yaml)
- [deploy/single-namespace/serviceaccount.yaml](https://github.com/tnozicka/openshift-acme/blob/master/deploy/single-namespace/serviceaccount.yaml)
- [deploy/single-namespace/issuer-letsencrypt-staging.yaml](https://github.com/tnozicka/openshift-acme/blob/master/deploy/single-namespace/issuer-letsencrypt-staging.yaml)
- [deploy/single-namespace/deployment.yaml](https://github.com/tnozicka/openshift-acme/blob/master/deploy/single-namespace/deployment.yaml)

Create a new issuer configuration (e.g. deploy/single-namespace/issuer-pki-demo.yaml)
based on the existing one (e.g. deploy/single-namespace/issuer-letsencrypt-staging.yaml),
and configure the **directoryUrl** to point to the PKI ACME responder.

```
kind: ConfigMap
apiVersion: v1
metadata:
  name: pki-demo
  annotations:
    "acme.openshift.io/priority": "50"
  labels:
    managed-by: "openshift-acme"
    type: "CertIssuer"
data:
  "cert-issuer.types.acme.openshift.io": >
    {
        "type": "ACME",
        "acmeCertIssuer": {
            "directoryUrl": "https://pki.demo.dogtagpki.org/acme/directory"
        }
    }
```

Deploy openshift-acme with the following commands:

```
$ oc apply -fdeploy/single-namespace/{role,serviceaccount,issuer-pki-demo,deployment}.yaml
$ oc create rolebinding openshift-acme \
    --role=openshift-acme \
    --serviceaccount="$( oc project -q ):openshift-acme" \
    --dry-run \
    -o yaml | oc apply -f -
```

## Deploying an Application on OpenShift with ACME Certificate

Deploy an application on OpenShift, for example:

```
$ git clone https://github.com/tnozicka/gohellouniverse.git
$ cd gohellouniverse
$ oc apply -fdeploy/{deployment,service}.yaml
```

Create a route for the application with the following command:

```
$ oc create route edge gohellouniverse --service=gohellouniverse --hostname=gohellouniverse.demo.dogtagpki.org
```

Create a CNAME record in DNS to map the route's hostname (e.g. gohellouniverse.demo.dogtagpki.org)
to the route's canonical hostname (e.g. elb.6923.rh-us-east-1.openshiftapps.com).
Verify the CNAME record with the following command:

```
$ dig gohellouniverse.demo.dogtagpki.org CNAME
...
gohellouniverse.demo.dogtagpki.org. 3600 IN CNAME elb.6923.rh-us-east-1.openshiftapps.com.
...
```

Enable ACME on the route with the following command:

```
$ oc patch route gohellouniverse -p '{"metadata":{"annotations":{"kubernetes.io/tls-acme":"true"}}}'
```

A certificate will be issued automatically by PKI ACME responder.
Verify the certificate with the following command:

```
$ nmap --script ssl-cert gohellouniverse.demo.dogtagpki.org -p 443
...
| ssl-cert: Subject:
| Subject Alternative Name: DNS:gohellouniverse.demo.dogtagpki.org
| Issuer: commonName=PKI Demo Certificate Authority
...
```

## See Also

* [Deploying PKI ACME Responder on OpenShift](Deploying_PKI_ACME_Responder_on_OpenShift.md)
