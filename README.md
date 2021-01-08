# Dogtag PKI

The Dogtag Certificate System is an enterprise-class open source Certificate Authority (CA). It is a full-featured system, and has been hardened by real-world deployments. It supports all aspects of certificate lifecycle management, including key archival, OCSP and smartcard management, and much more.

There are 6 different subsystems included in the Dogtag PKI suite:

1. [Certificate Authority (CA) subsystem](https://www.dogtagpki.org/wiki/Certificate_Authority)
2. [Key Recovery Authority (KRA) subsystem](https://www.dogtagpki.org/wiki/Key_Recovery_Authority)
3. [Online Certificate Status Protocol (OCSP) subsystem](https://www.dogtagpki.org/wiki/OCSP_Manager)
4. [Token Key Service (TKS) subsystem](https://www.dogtagpki.org/wiki/Token_Key_Service)
5. [Token Processing System (TPS) subsystem](https://www.dogtagpki.org/wiki/Token_Processing_System)
6. [ACME Responder](https://www.dogtagpki.org/wiki/PKI_ACME_Responder)

## Documentation

The best place to start learning about the product is the [Dogtag PKI Wiki](https://www.dogtagpki.org)

## Installing

### Fedora

To install the **whole Dogtag PKI suite**:

````bash
sudo dnf install dogtag-pki
````

To install **individual subsystems**:

````bash
sudo dnf install pki-ca pki-kra pki-ocsp pki-tks pki-tps
````

To install **web UI theme packages**:

````bash
sudo dnf install dogtag-pki-server-theme dogtag-pki-console-theme
````

## Deploying

After successful installation of the packages, follow the below steps to deploy intended subsystems:

- [Deploy CA](docs/installation/ca/Installing_CA.md)
- [Deploy KRA](docs/installation/kra/Installing_KRA.md)
- [Deploy OCSP](docs/installation/ocsp/Installing_OCSP.md)
- [Deploy TKS](docs/installation/tks/Installing_TKS.md)
- [Deploy TPS](docs/installation/tps/Installing_TPS.md)
- [Deploy ACME](docs/installation/acme/Installing_PKI_ACME_Responder.md)

For other types of deployments (Sub-CA, Clones, HSMs, etc) please see under [docs/installation](docs/installation)

## Building

### Fedora/CentOS/RHEL

#### Prerequisites

````bash
sudo dnf install dnf-plugins-core rpm-build git

# NOTE: Use the intendended branch name instead of "master" to pull right dependency version
sudo dnf copr enable @pki/master

sudo dnf builddep pki.spec
````

#### Build Procedure

After successfully installing the prerequisites, the project can be built with a one-line command:

````bash
./build.sh
````

The built RPMS will be placed in `~/build/pki/` directory.

See also [Building PKI](docs/development/Building_PKI.md)

## Testing

| Test      | Status                                                                               |
| --------- | ------------------------------------------------------------------------------------ |
| CA        | ![CA Tests](https://github.com/dogtagpki/pki/workflows/CA%20Tests/badge.svg)         |
| KRA       | ![KRA Tests](https://github.com/dogtagpki/pki/workflows/KRA%20Tests/badge.svg)       |
| OCSP      | ![OCSP Tests](https://github.com/dogtagpki/pki/workflows/OCSP%20Tests/badge.svg)     |
| TKS       | ![TKS Tests](https://github.com/dogtagpki/pki/workflows/TKS%20Tests/badge.svg)       |
| TPS       | ![TPS Tests](https://github.com/dogtagpki/pki/workflows/TPS%20Tests/badge.svg)       |
| ACME      | ![ACME Tests](https://github.com/dogtagpki/pki/workflows/ACME%20Tests/badge.svg)     |
| Python    | ![Python Tests](https://github.com/dogtagpki/pki/workflows/Python%20Tests/badge.svg) |
| Tools     | ![Python Tests](https://github.com/dogtagpki/pki/workflows/Tools%20Tests/badge.svg)  |
| QE        | ![QE Tests](https://github.com/dogtagpki/pki/workflows/QE%20Tests/badge.svg)         |
| IPA       | ![IPA Tests](https://github.com/dogtagpki/pki/workflows/IPA%20Tests/badge.svg)       |

## Contributing

There are multiple ways for you to be part of this project. Please see [CONTRIBUTING]( CONTRIBUTING.md) to learn more.

## Contact

You can reach the Dogtag PKI team over the **#dogtag-pki** channel on freenode.net. Note that you need to be a [registered user](https://freenode.net/kb/answer/registration) to message on this channel. You can also send an email to pki-users@redhat.com.

See also [Contact Us](https://www.dogtagpki.org/wiki/Contact_Us)

## License

[GPL-2.0 License](LICENSE)
