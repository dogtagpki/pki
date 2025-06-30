# Dogtag PKI

The Dogtag Certificate System is an enterprise-class open source Certificate Authority (CA). It is a full-featured system, and has been hardened by real-world deployments. It supports all aspects of certificate lifecycle management, including key archival, OCSP and smartcard management, and much more.

The Dogtag PKI suite provides the following subsystems:

- [Certificate Authority (CA)](https://github.com/dogtagpki/pki/wiki/Certificate-Authority)
- [Key Recovery Authority (KRA)](https://github.com/dogtagpki/pki/wiki/Key-Recovery-Authority)
- [Online Certificate Status Protocol (OCSP) Responder](https://github.com/dogtagpki/pki/wiki/OCSP-Responder)
- [Token Key Service (TKS)](https://github.com/dogtagpki/pki/wiki/Token-Key-Service)
- [Token Processing System (TPS)](https://github.com/dogtagpki/pki/wiki/Token-Processing-System)
- [Automatic Certificate Management Environment (ACME) Responder](https://github.com/dogtagpki/pki/wiki/ACME-Responder)

## Documentation

The best place to start learning about the product is the [Dogtag PKI Wiki](https://github.com/dogtagpki/pki/wiki).

## Installing

### Fedora

To install the whole Dogtag PKI suite:

````bash
$ sudo dnf install dogtag-pki
````

To install specific subsystems only:

````bash
$ sudo dnf install dogtag-pki-ca dogtag-pki-kra
````

To install the theme package:

````bash
$ sudo dnf install dogtag-pki-theme
````

## Deploying

After successful installation of the packages, follow the below steps to deploy intended subsystems:

- [Deploy CA](docs/installation/ca/Installing_CA.md)
- [Deploy KRA](docs/installation/kra/Installing_KRA.md)
- [Deploy OCSP](docs/installation/ocsp/Installing_OCSP.md)
- [Deploy TKS](docs/installation/tks/Installing_TKS.md)
- [Deploy TPS](docs/installation/tps/Installing_TPS.md)
- [Deploy ACME](docs/installation/acme/Installing_PKI_ACME_Responder.md)

For other types of deployments (Sub-CA, Clones, HSMs, etc) please see the [Installation Guide](https://github.com/dogtagpki/pki/wiki/Installation-Guide).

## Building

### Fedora/CentOS/RHEL

#### Prerequisites

````bash
$ sudo dnf install dnf-plugins-core rpm-build git

$ sudo dnf copr -y enable @pki/11.8

$ sudo dnf builddep -y --spec pki.spec
````

#### Build Procedure

After successfully installing the prerequisites, the project can be built with a one-line command:

````bash
$ ./build.sh rpm
````

The built RPMS will be placed in `~/build/pki/` directory.

See also [Building PKI](docs/development/Building_PKI.md).

## Testing

| Test           | Status                                                                                                                                                                        |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SonarCloud     | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=dogtagpki_pki&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dogtagpki_pki) |
| CA Tests       | [![CA Tests](https://github.com/dogtagpki/pki/actions/workflows/ca-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/ca-tests.yml)                     |
| CA Tests 2     | [![CA Tests 2](https://github.com/dogtagpki/pki/actions/workflows/ca-tests2.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/ca-tests2.yml)                 |
| CA Clone Tests | [![CA Clone Tests](https://github.com/dogtagpki/pki/actions/workflows/ca-clone-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/ca-clone-tests.yml)   |
| SubCA Tests    | [![SubCA Tests](https://github.com/dogtagpki/pki/actions/workflows/subca-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/subca-tests.yml)            |
| KRA Tests      | [![KRA Tests](https://github.com/dogtagpki/pki/actions/workflows/kra-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/kra-tests.yml)                  |
| OCSP Tests     | [![OCSP Tests](https://github.com/dogtagpki/pki/actions/workflows/ocsp-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/ocsp-tests.yml)               |
| TKS Tests      | [![TKS Tests](https://github.com/dogtagpki/pki/actions/workflows/tks-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/tks-tests.yml)                  |
| TPS Tests      | [![TPS Tests](https://github.com/dogtagpki/pki/actions/workflows/tps-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/tps-tests.yml)                  |
| ACME Tests     | [![ACME Tests](https://github.com/dogtagpki/pki/actions/workflows/acme-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/acme-tests.yml)               |
| EST Tests      | [![EST Tests](https://github.com/dogtagpki/pki/actions/workflows/est-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/est-tests.yml)                  |
| Server Tests   | [![Server Tests](https://github.com/dogtagpki/pki/actions/workflows/server-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/server-tests.yml)         |
| Python Tests   | [![Python Tests](https://github.com/dogtagpki/pki/actions/workflows/python-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/python-tests.yml)         |
| Tools Tests    | [![Tools Tests](https://github.com/dogtagpki/pki/actions/workflows/tools-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/tools-tests.yml)            |
| IPA Tests      | [![IPA Tests](https://github.com/dogtagpki/pki/actions/workflows/ipa-tests.yml/badge.svg)](https://github.com/dogtagpki/pki/actions/workflows/ipa-tests.yml)                  |

## Contributing

There are multiple ways for you to be part of this project. Please see [CONTRIBUTING]( CONTRIBUTING.md) to learn more.

## Contact Us

See [Contact Us](https://github.com/dogtagpki/pki/wiki/Contact-Us).

## License

[GPL-2.0 License](LICENSE)
