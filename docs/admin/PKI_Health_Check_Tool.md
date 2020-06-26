# PKI Health Check Tool

## Overview

Dogtag provides no way to do introspection to discover possible issues. A framework is needed to assist with the identification, diagnosis and potentially repair of problems. This has the benefit of increasing confidence in a PKI installation and reducing costs associated with addressing issues.

The purpose of the healthcheck tool is to find and report error conditions that may impact the PKI environment. Automated repair would be possible in some limited cases.

## Design

### Dependencies

The pki-healthcheck tool depends on `freeipa-healthcheck-core` package for the base framework, which is built along with `freeipa-healthcheck`. This is done to ensure that `pki-healthcheck` can integrate smoothly with the `freeipa-healthcheck` since FreeIPA project depends on PKI for CA/KRA backened.

You can read more on the base framework [here](https://www.freeipa.org/page/V4/Healthcheck)

### Delivery

PKI Health Check tool will be delivered via the `pki-server` package.

In the future, this tool can be delivered via PyPi.

### Test Severity Status

Severity of a problem is defined as:

| Value | Severity | Definition |
|-------|----------|------------|
| 0 | Success | The check executed and found no issue |
| 1 | Critical | Something is terribly wrong (e.g. a service is not started, certificates are expired, etc). |
| 2 | Error | Something is wrong but your PKI server is probably still working (e.g. clone conflict) |
| 3 | Warning | Not an issue yet, but may be (e.g. expiring certificate soon) |

### Checks Included

1. System certificate sync between CS.cfg and NSS database
2. System certificate expiry
3. System certificate trust flags in NSS database
4. Subsystem connectivity check

(More checks will be added in the future)

### Configuration

The `pki-healthcheck` tool will store its configuration in `/etc/pki/healthcheck.conf`. It will be an ini-style config file. The format is

    [global]
    plugin_timeout=300
    cert_expiration_days=30

    # Dogtag specific section
    [dogtag]
    instance_name=pki-tomcat

### Limitations

Currently, the healthcheck tool can only be executed on a **single machine** with **single PKI instance**.

### Testing

It is difficult to simulate some issues and so, unit tests will use [unittest.mock](https://docs.python.org/3/library/unittest.mock.html) library to run some unittests.

## How to use

Healthcheck executes a series of plugins to collect its information. Each plugin, referred to later as a source, is organized around a specific theme (system certificates, file system permissions and ownership, clones, etc.). A source is a collection of tests, refered to as checks, that should test one small piece of PKI.

The report will consist of a message describing what was run and the status. If the status is not successful, the message may include additional information, which can be used by the admin to correct the issue (e.g. a file has the wrong permissions, expected X and got Y).

### Manual Execution

To run it manually, execute:

    # pki-healthcheck

A specific check can be execuated as well:

    #  pki-healthcheck --source pki.server.healthcheck.meta.csconfig --check DogtagCertsConfigCheck

Output will be a list of sources and checks executed along with the status displayed in JSON format. It does not log to a file by default. `--output-file` can be used to write the JSON output to a file.

The default output looks like:

    {
        "source": "pki.server.healthcheck.meta.csconfig",
        "check": "DogtagCertsConfigCheck",
        "result": "SUCCESS",
        "uuid": "067ea8ab-e780-42a9-ae03-ae40869a242d",
        "when": "20200117190214Z",
        "duration": "0.194885",
        "kw": {
            "key": "ca_signing",
            "configfile": "/var/lib/pki/pki-tomcat/ca/conf/CS.cfg"
        }
    }

The `pki-healthcheck` command will exit with a returncode of 0, even if any checks discovered issues with the PKI installation. A non-zero returncode means that `pki-healthcheck` tool failed in a non-recoverable way.

For all available options, you can execute the tool with `--help` or read the `pki-healthcheck (8)` man page.

### Repairing Issues

Repairing an issue involves the administrator making the suggested changes to their system.

`pki-healthcheck` will make some recommendations but it is up to a human to apply them.
