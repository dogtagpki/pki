# pkispawn 8 "September 30, 2020" PKI "PKI Instance Creation Utility"

## NAME

pkispawn - Sets up a PKI subsystem.

## SYNOPSIS

**pkispawn** **-s** *subsystem* **-f** *config_file* [**-h**] [**-v**]

## DESCRIPTION

Sets up a PKI subsystem (CA, KRA, OCSP, TKS, or TPS) in a Tomcat instance.

**Note:**
A 389 Directory Server instance must be configured and running before this script can be run.
PKI server requires an internal directory database.
The default configuration assumes a Directory Server instance running on the same machine on port 389.
For more information on creating a Directory Server instance, see **dscreate(8)**.

An instance can contain multiple subsystems, although it may contain at most one of each type of subsystem on a single machine.
So, for example, an instance could contain CA and KRA subsystems, but not two CA subsystems.
To create an instance with a CA and a KRA, simply run pkispawn twice, with values **-s CA** and **-s KRA** respectively.

The instances are created based on values for configuration parameters in the default configuration
(i.e. /usr/share/pki/server/etc/default.cfg) and the user-provided configuration file.
The user-provided configuration file is read after the default configuration file,
so any parameters defined in that file will override parameters in the default configuration file.
In general, most users will store only those parameters which are different from the default configuration in their user-provided configuration file.

This configuration file contains parameters that are grouped into sections.
These sections are stacked, so that parameters defined in earlier sections can be overwritten by parameters defined in later sections.
The sections are read in the following order: [DEFAULT], [Tomcat], and the subsystem section ([CA], [KRA], [OCSP], [TKS], or [TPS]).
This allows the ability to specify parameters to be shared by all subsystems in [DEFAULT] or [Tomcat], and system-specific customization.

**Note:**
Any non-password related parameter values in the configuration file that needs to contain a **%** character must be properly escaped.
For example, a value of **foo%bar** would be specified as **foo%%bar** in the configuration file.

At a minimum, the user-defined configuration file must provide some passwords needed for the install.
An example configuration file is provided in the **EXAMPLES** section below.
For more information on the default configuration file and the parameters it contains (and can be customized),
see **pki_default.cfg(5)**.

The **pkispawn** run creates several different installation files that can be referenced later, if need be:

* For Tomcat-based instances, a Tomcat instance is created at /var/lib/pki/*pki_instance_name*, where **pki_instance_name** is defined in the configuration file.
* A log file of **pkispawn** operations is written to /var/log/pki/pki-*subsystem*-spawn.*timestamp*.log.
* A .p12 (PKCS #12) file containing a certificate for a subsystem administrator is stored in **pki_client_dir** defined in the configuration file.

When the utility is done running, the CA can be accessed by pointing a browser to https://*hostname*:*pki_https_port*/.
The agent pages can be accessed by importing the CA certificate and administrator certificate into the browser.

The PKI server instance can also be accessed using the **pki** command line interface. See **pki(1)**.
For more extensive documentation on how to use PKI features,
see the Red Hat Certificate System Documentation at https://access.redhat.com/knowledge/docs/Red_Hat_Certificate_System.

Instances created using **pkispawn** can be removed using **pkidestroy**.  See **pkidestroy(8)**.

**pkispawn** supersedes and combines the functionality of **pkicreate** and **pkisilent**, which were available in earlier releases of Certificate Server.  It is now possible to completely create and configure the Certificate Server subsystem in a single step using **pkispawn**.

**Note:**
Previously, as an alternative to using **pkisilent** to perform a non-interactive batch configuration,
a PKI instance could be interactively configured by a GUI-based configuration wizard via a Firefox browser.
GUI-based configuration of a PKI instance is unavailable in this version of the product.

## OPTIONS

**-s** *subsystem*  
    Specifies the subsystem to be installed and configured, where *subsystem* is CA, KRA, OCSP, TKS, or TPS.

**-f** *config_file*  
    Specifies the path to the user-defined configuration file.
    This file contains differences between the default configuration and the custom configuration.

**--precheck**  
    Execute pre-checks and exit.

**--skip-configuration**  
    Run the first step of the installation (i.e. skipping the instance configuration step).

**--skip-installation**  
    Run the second step of the installation (i.e. skipping the instance installation step).

**-h**, **--help**  
    Prints additional help information.

**-v**  
    Displays verbose information about the installation.
    This flag can be provided multiple times to increase verbosity.
    See **pkispawn -h** for details.

## SEPARATE VERSUS SHARED INSTANCES

### Separate PKI instances

As described above, this version of PKI continues to support separate PKI instances for all subsystems.

Separate PKI instances run as a single Java-based Apache Tomcat instance, contain a single PKI subsystem (CA, KRA, OCSP, TKS, or TPS), and must utilize unique ports if co-located on the same machine.

### Shared PKI instances

Additionally, this version of PKI introduces the notion of a shared PKI instance.

Shared PKI instances also run as a single Java-based Apache Tomcat instance, but may contain any combination of up to one of each type of PKI subsystem:

- CA
- TKS
- CA, KRA
- CA, OCSP
- TKS, TPS
- CA, KRA, TKS, TPS
- CA, KRA, OCSP, TKS, TPS
- etc.

Shared PKI instances allow all of their subsystems contained within that instance to share the same ports,
and must utilize unique ports if more than one shared PKI instance is co-located on the same machine.

Semantically, a shared PKI instance that contains a single PKI subsystem is identical to a separate PKI instance.

## INTERACTIVE MODE

If no options are specified, pkispawn will provide an interactive menu to
collect the parameters needed to install the Certificate Server instance.
Note that only the most basic installation options are provided. This
includes root CA, KRA, OCSP, TKS, and TPS connecting to an existing
directory server. More advanced setups such as cloned subsystems,
subordinate or externally signed CA, subsystems that connect to the
directory server using LDAPS, and subsystems that are customized beyond
the options described below require the use of a configuration file with
the **-f** option.

The interactive option is most useful for those users getting familiar with Certificate Server.
The parameters collected are written to the installation file of the subsystem,
which can be found at /etc/sysconfig/pki/tomcat/*instance_name*/*subsystem*/deployment.cfg.

The following parameters are queried interactively during the installation process.

### Subsystem Type

**Subsystem (CA/KRA/OCSP/TKS/TPS):**  
    The type of subsystem to be installed.
    Prompted when the -s option is not specified.
    The default value chosen is CA.

### Instance Specific Parameters

**Instance name:**  
    The name of the tomcat instance in which the subsystem is to be installed. The default value is pki-tomcat.

**Note:**
Only one subsystem of a given type (CA, KRA, OCSP, TKS, TPS) can exist within a given instance.

**HTTP port:**  
    The HTTP port of the Tomcat instance. The default value is 8080.

**Secure HTTP port:**  
    The HTTPS port of the Tomcat instance. The default value is 8443.

**AJP port:**  
    The AJP port of the Tomcat instance. The default value is 8009.

**Management port:**  
    The management port of the Tomcat instance. The default value is 8005.

**Note:**
When deploying a new subsystem into an existing instance,
pkispawn will attempt to read the ports from **deployment.cfg** files stored
for previously installed subsystems for this instance.
If successful, the installer will not prompt for these ports.

### Administrative User Parameters

**Username:**  
    The username of the administrator of this subsystem. The default value is \<ca/kra/ocsp/tks/tps>admin.

**Password:**  
    Password for the administrator user.

**Import certificate:**  
    An optional parameter that can be used to import an already available CA admin certificate into this instance.

**Export certificate:**  
    Setup the path where the admin certificate of this \<subsystem> should be stored.
    The default value is $HOME/.dogtag/pki-tomcat/\<ca/kra/ocsp/tks/tps>_admin.cert.

### Directory Server Parameters

**Hostname:**  
    Hostname of the directory server instance.  The default value is the hostname of the system.

**Use a secure LDAPS connection?**  
    Answering yes to this question will cause prompts for **Secure LDAPS Port:** and **Directory Server CA certificate pem file:**.
    Answering no to this question will cause a prompt for **LDAP Port**.
    The initial default value for this question is no.

**Secure LDAPS Port:**  
    Secure LDAPS port for the directory server instance. The default value is 636.

**Directory Server CA certificate PEM file:**  
    The fully-qualified path including the filename of the file which contains an exported copy of the Directory Server's CA certificate (e.g. $HOME/dscacert.pem).
    This file must exist prior to **pkispawn** being able to utilize it.
    For details on creation of this file see the **EXAMPLES** section below entitled **Installing PKI Subsystem with Secure LDAP Connection**.

**LDAP Port:**  
    LDAP port for the directory server instance. The default value is 389.

**Base DN:**  
    The Base DN to be used for the internal database for this subsystem.
    The default value is o=pki-tomcat-\<subsystem>.

**Bind DN:**  
    The bind DN required to connect for the directory server.
    This user must have sufficient permissions to install the required schema and database.
    The default value is cn=Directory Manager.

**Password:**  
    Password for the bind DN.

### Security Domain Parameters

**Name:**  
    The name of the security domain. Required only if installing a root CA.
    Default value: \<DNS domain name> Security Domain.

**Hostname:**  
    The hostname for the security domain CA. Required only for non-CA subsystems.
    The default value is the hostname of this system.

**Secure HTTP port:**  
    The https port for the security domain. Required only for non-CA subsystems. The default value is 8443.

**Username:**  
    The username of the security domain administrator of the CA.
    Required only for non-CA subsystems.
    The default value is caadmin.

**Password:**  
    Password for the security domain administrator. Required for all subsystems that are not root CAs.

## PRE-CHECK MODE

This option is only available when pkispawn is invoked in a non-interactive mode.
When the **--precheck** option is provided, a set of basic tests are performed to
ensure that the parameters provided to pkispawn are valid and consistent.

**pkispawn** will then exit with an exit code of 0 on success, or 1 on failure.
This mode can be used to perform basic tests prior to doing any actual installation of
the PKI server instance.

Flags are available to disable specific tests.
For instance, one might want to disable validation of the credentials for the internal database user
if the directory server instance has not yet been created.

See **pki_default.cfg(5)** for more details about available flags.

## TWO-STEP INSTALLATION MODE

**pkispawn** provides a number of parameters to customize an instance before it is created.
Usually, most other customization can be done after the server is created.
However, sometimes certain types of customization need to be done before the server is created,
but there are no parameters for that. For example, configuring session timeout,
adding CSR extensions, customizing certificate profiles, configuring TLS ciphers, etc.
To support such customization, **pkispawn** provides a two-step installation mode.

Generally, instance creation happens in one step (except for the external CA case).
Internally, the process happens in two stages.
In the first stage, pkispawn will install the instance files (e.g. CS.cfg, NSS database, profiles, etc.)
in the instance directory and customize them based on pkispawn parameters.
In the second stage, pkispawn will start the instance and configure the instance based on the instance
configuration files (e.g. initializing database, generating certificates, configuring connectors, etc.).
The two-step process allows the process to be stopped after the first stage,
allowing further customization to be done before running the second stage.

To use two-step installation mode, prepare a normal pkispawn configuration file, then
run **pkispawn** with the **--skip-configuration** parameter. For example:

```
$ pkispawn -s CA -f myconfig.txt --skip-configuration
```

Then customize the files in the instance directory as needed.
Finally, finish the installation by running pkispawn again with the **--skip-installation** parameter.
For example:

```
$ pkispawn -s CA -f myconfig.txt --skip-installation
```

## EXAMPLES

### Installing Root CA

To install a root CA in a new instance execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
```

Prior to running this command, a Directory Server instance should be created and running.
This command assumes that the Directory Server instance is using its default configuration:

- Installed on the local machine
- Listening on port 389
- The user is cn=Directory Manager, with the password specified in **pki_ds_password**

This invocation of **pkispawn** creates a Tomcat instance containing a CA
running on the local machine with secure port 8443 and unsecure port 8080.
To access this CA, simply point a browser to https://*hostname*:8443.

The instance name (defined by **pki_instance_name**) is pki-tomcat, and it is
located at /var/lib/pki/pki-tomcat. Logs for the instance are located
at /var/log/pki/pki-tomcat, and an installation log is written to
/var/log/pki/pki-*subsystem*-spawn.*timestamp*.log.

A PKCS #12 file containing the administrator certificate is created in
$HOME/.dogtag/pki-tomcat. This PKCS #12 file uses the password
designated by **pki_client_pkcs12_password** in the configuration file.

To access the agent pages, first import the CA certificate by accessing the CA
End Entity Pages and clicking on the Retrieval Tab. Be sure to trust the CA
certificate. Then, import the administrator certificate in the PKCS #12 file.

### Installing Root CA using ECC

To install a root CA in a new instance using ECC execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_admin_key_algorithm=SHA256withEC
pki_admin_key_size=nistp256
pki_admin_key_type=ecc
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_sslserver_key_algorithm=SHA256withEC
pki_sslserver_key_size=nistp256
pki_sslserver_key_type=ecc
pki_subsystem_key_algorithm=SHA256withEC
pki_subsystem_key_size=nistp256
pki_subsystem_key_type=ecc

[CA]
pki_ca_signing_key_algorithm=SHA256withEC
pki_ca_signing_key_size=nistp256
pki_ca_signing_key_type=ecc
pki_ca_signing_signing_algorithm=SHA256withEC
pki_ocsp_signing_key_algorithm=SHA256withEC
pki_ocsp_signing_key_size=nistp256
pki_ocsp_signing_key_type=ecc
pki_ocsp_signing_signing_algorithm=SHA256withEC
```

In order to utilize ECC, the SSL Server and Subsystem key algorithm, key size,
and key type should be changed from SHA256withRSA to SHA256withEC, 2048 to nistp256, and rsa to ecc, respectively.
To use an ECC admin key size and key type, the values should also be changed from 2048 to nistp256, and rsa to ecc.

Additionally, for a CA subsystem, both the CA and OCSP Signing key algorithm, key size, key type, and signing algorithm
should be changed from SHA256withRSA to SHA256withEC, 2048 to nistp256, rsa to ecc, and SHA256withRSA to SHA256withEC, respectively.

**Note:**
For all PKI subsystems including the CA, ECC is not supported for the corresponding Audit Signing parameters.
Similarly, for KRA subsystems, ECC is not supported for either of the corresponding Storage or Transport parameters.

### Installing KRA, OCSP, TKS, or TPS in Shared Instance

For this example, assume that a new CA instance has been installed by executing the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
```

To install a shared KRA in the same instance used by the CA execute the following command:

```
$ pkispawn -s KRA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
```

To install a shared OCSP in the same instance used by the CA execute the following command:

```
$ pkispawn -s OCSP -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
```

To install a shared TKS in the same instance used by the CA execute the following command:

```
$ pkispawn -s TKS -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
```

To install a shared TPS in the same instance used by the CA execute the following command:

```
$ pkispawn -s TPS -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123

[TPS]
# Shared TPS instances optionally utilize their shared KRA
# for server-side keygen
pki_enable_server_side_keygen=True
pki_authdb_basedn=dc=example,dc=com
```

**Note:**
For this particular example, the computed default values for a
PKI instance name including its ports, URLs, machine names, etc.
were utilized as defined in /usr/share/pki/server/etc/default.cfg.
Each subsystem in this example will reside under the
/var/lib/pki/pki-tomcat instance housed within their own
**ca**, **kra**, **ocsp**, **tks**, and **tps**
subdirectories, utilizing the same default port values of
8080 (http), 8443 (https), 8009 (ajp), 8005 (tomcat), using the
same computed hostname and URL information, and sharing a single
common PKI Administrator Certificate.

The **pki_security_domain_password** is the admin password of the
CA installed in the same instance. This command should be run after
a CA is installed. This installs another subsystem within the same
instance using the certificate generated for the CA administrator
for the subsystem's administrator. This allows a user to access
both subsystems on the browser with a single administrator
certificate. To access the new subsystem's functionality, simply
point the browser to https://*hostname*:8443 and click the
relevant top-level links.

To install TPS in a shared instance the following section must be
added to **myconfig.txt**:

```
[TPS]
pki_authdb_basedn=dc=example,dc=com
```

TPS requires an authentication database.
The **pki_authdb_basedn** specifies the base DN of the authentication database.

TPS also requires that a CA and a TKS subsystems are already installed in the same instance.
Since they are in the same instance, a shared secret key will automatically be generated in TKS and imported into TPS.

Optionally, server-side key generation can be enabled in TPS by adding the following parameter in [TPS]:

```
pki_enable_server_side_keygen=True
```

Enabling server-side key generation requires that a KRA subsystem is already installed in the same instance.

### Installing KRA, OCSP, TKS, or TPS in Separate Instance

For this example, assume that a new CA instance has been installed by executing the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
# Separated CA instance name and ports
pki_instance_name=pki-ca
pki_http_port=18080
pki_https_port=18443
# This Separated CA instance will be its own security domain
pki_security_domain_https_port=18443

[Tomcat]
# Separated CA Tomcat ports
pki_ajp_port=18009
pki_tomcat_server_port=18005
```

To install a separate KRA which connects to this remote CA execute the following command:

```
$ pkispawn -s KRA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
# Separated KRA instance name and ports
pki_instance_name=pki-kra
pki_http_port=28080
pki_https_port=28443
# Separated KRA instance security domain references
pki_issuing_ca=https://pki.example.com:18443
pki_security_domain_hostname=pki.example.com
pki_security_domain_https_port=18443
pki_security_domain_user=caadmin

[Tomcat]
# Separated KRA Tomcat ports
pki_ajp_port=28009
pki_tomcat_server_port=28005

[KRA]
# A Separated KRA instance requires its own
# PKI Administrator Certificate
pki_import_admin_cert=False
```

To install a separate OCSP which connects to this remote CA execute the following command:

```
$ pkispawn -s OCSP -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
# Separated OCSP instance name and ports
pki_instance_name=pki-ocsp
pki_http_port=29080
pki_https_port=29443
# Separated OCSP instance security domain references
pki_issuing_ca=https://pki.example.com:18443
pki_security_domain_hostname=pki.example.com
pki_security_domain_https_port=18443
pki_security_domain_user=caadmin

[Tomcat]
# Separated OCSP Tomcat ports
pki_ajp_port=29009
pki_tomcat_server_port=29005

[OCSP]
# A Separated OCSP instance requires its own
# PKI Administrator Certificate
pki_import_admin_cert=False
```

To install a separate TKS which connects to this remote CA execute the following command:

```
$ pkispawn -s TKS -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
# Separated TKS instance name and ports
pki_instance_name=pki-tks
pki_http_port=30080
pki_https_port=30443
# Separated TKS instance security domain references
pki_issuing_ca=https://pki.example.com:18443
pki_security_domain_hostname=pki.example.com
pki_security_domain_https_port=18443
pki_security_domain_user=caadmin

[Tomcat]
# Separated TKS Tomcat ports
pki_ajp_port=30009
pki_tomcat_server_port=30005

[TKS]
# A Separated TKS instance requires its own
# PKI Administrator Certificate
pki_import_admin_cert=False
```

To install a separate TPS which connects to this remote CA execute the following command:

```
$ pkispawn -s TPS -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
# Separated TPS instance name and ports
pki_instance_name=pki-tps
pki_http_port=31080
pki_https_port=31443
# Separated TPS instance security domain references
pki_issuing_ca=https://pki.example.com:18443
pki_security_domain_hostname=pki.example.com
pki_security_domain_https_port=18443
pki_security_domain_user=caadmin

[Tomcat]
# Separated TPS Tomcat ports
pki_ajp_port=31009
pki_tomcat_server_port=31005

[TPS]
# Separated TPS instances require specifying a remote CA
pki_ca_uri=https://pki.example.com:18443
# Separated TPS instances optionally utilize a remote KRA
# for server-side keygen
pki_kra_uri=https://pki.example.com:28443
pki_enable_server_side_keygen=True
pki_authdb_basedn=dc=example,dc=com
# Separated TPS instances require specifying a remote TKS
pki_tks_uri=https://pki.example.com:30443
pki_import_shared_secret=True
# A Separated TPS instance requires its own
# PKI Administrator Certificate
pki_import_admin_cert=False
```

**Note:**
For this particular example, besides passwords,
sample values were also utilized for PKI instance names, ports, URLs, machine names, etc.
Under no circumstances should these demonstrative values be construed to be required literal values.

A remote CA is one where the CA resides in another PKI server instance,
either on the local machine or a remote machine.
In this case, **myconfig.txt** must specify the connection information for the remote CA
and the information about the security domain
(the trusted collection of subsystems within an instance).

The subsystem section is [KRA], [OCSP], [TKS], or [TPS].
This example assumes that the specified CA hosts the security domain.
The CA must be running and accessible.

A new administrator certificate is generated for the new subsystem and stored in a PKCS #12 file
in $HOME/.dogtag/*pki_instance_name*.

As in a shared instance, to install TPS in a separate instance
the authentication database must be specified in the [TPS] section,
and optionally the server-side key generation can be enabled.
If the CA, KRA, or TKS subsystems required by TPS are running
on a remote instance the following parameters must be added into
the [TPS] section to specify their locations:

```
pki_ca_uri=https://<ca_hostname>:<ca_https_port>
pki_kra_uri=https://<kra_hostname>:<kra_https_port>
pki_tks_uri=https://<tks_hostname>:<tks_https_port>
```

If TPS and TKS are installed on separate instances the shared secret key
should be imported over the wire between the TKS and TPS automatically.

If the automated procedure fails for any unlikely reason the following
manual procedure will serve as a fallback. The key needs to be created
on the TKS side and imported into the TPS side in this case.

Generate the shared secret key (if needed) in TKS with the following command:

```
$ tkstool -T -d /var/lib/pki/pki-tomcat/alias -n sharedSecret
```

Verify the shared secret key in TKS with the following command:

```
$ tkstool -L -d /var/lib/pki/pki-tomcat/alias
```

Once TPS is installed, shutdown TPS instance, then import the shared secret key into TPS with the following command:

```
$ tkstool -I -d /var/lib/pki/pki-tomcat/alias -n sharedSecret
```

Verify the shared secret key in TPS with the following command:

```
$ tkstool -L -d /var/lib/pki/pki-tomcat/alias
```

The shared secret key nickname should be stored in the following property in the TPS's CS.cfg:

```
conn.tks1.tksSharedSymKeyName=sharedSecret
```

Finally, restart the TPS instance.

### Installing CA, KRA, OCSP, TKS, or TPS using HSM

This section provides sample **myconfig.txt** files
when a Hardware Security Module (HSM) is being utilized in a shared PKI instance.

For this example, assume that a new CA instance has been installed by executing the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
# Optionally keep client databases
pki_client_database_purge=False
# Provide HSM parameters
pki_hsm_enable=True
pki_hsm_libfile=<hsm_libfile>
pki_hsm_modulename=<hsm_modulename>
pki_token_name=<hsm_token_name>
pki_token_password=<pki_token_password>
# Provide PKI-specific HSM token names
pki_audit_signing_token=<hsm_token_name>
pki_sslserver_token=<hsm_token_name>
pki_subsystem_token=<hsm_token_name>

[CA]
# Provide CA-specific HSM token names
pki_ca_signing_token=<hsm_token_name>
pki_ocsp_signing_token=<hsm_token_name>
```

To install a shared KRA in the same instance used by the CA execute the following command:

```
$ pkispawn -s KRA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Provide HSM parameters
pki_hsm_enable=True
pki_hsm_libfile=<hsm_libfile>
pki_hsm_modulename=<hsm_modulename>
pki_token_name=<hsm_token_name>
pki_token_password=<pki_token_password>
# Provide PKI-specific HSM token names
pki_audit_signing_token=<hsm_token_name>
pki_sslserver_token=<hsm_token_name>
pki_subsystem_token=<hsm_token_name>

[KRA]
# Provide KRA-specific HSM token names
pki_storage_token=<hsm_token_name>
pki_transport_token=<hsm_token_name>
```

To install a shared OCSP in the same instance used by the CA execute the following command:

```
$ pkispawn -s OCSP -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Provide HSM parameters
pki_hsm_enable=True
pki_hsm_libfile=<hsm_libfile>
pki_hsm_modulename=<hsm_modulename>
pki_token_name=<hsm_token_name>
pki_token_password=<pki_token_password>
# Provide PKI-specific HSM token names
pki_audit_signing_token=<hsm_token_name>
pki_sslserver_token=<hsm_token_name>
pki_subsystem_token=<hsm_token_name>

[OCSP]
# Provide OCSP-specific HSM token names
pki_ocsp_signing_token=<hsm_token_name>
```

To install a shared TKS in the same instance used by the CA execute the following command:

```
$ pkispawn -s TKS -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Provide HSM parameters
pki_hsm_enable=True
pki_hsm_libfile=<hsm_libfile>
pki_hsm_modulename=<hsm_modulename>
pki_token_name=<hsm_token_name>
pki_token_password=<pki_token_password>
# Provide PKI-specific HSM token names
pki_audit_signing_token=<hsm_token_name>
pki_sslserver_token=<hsm_token_name>
pki_subsystem_token=<hsm_token_name>
```

To install a shared TPS in the same instance used by the CA execute the following command:

```
$ pkispawn -s TPS -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
# Provide HSM parameters
pki_hsm_enable=True
pki_hsm_libfile=<hsm_libfile>
pki_hsm_modulename=<hsm_modulename>
pki_token_name=<hsm_token_name>
pki_token_password=<pki_token_password>
# Provide PKI-specific HSM token names
pki_audit_signing_token=<hsm_token_name>
pki_sslserver_token=<hsm_token_name>
pki_subsystem_token=<hsm_token_name>

[TPS]
# Shared TPS instances optionally utilize their shared KRA
# for server-side keygen
pki_enable_server_side_keygen=True
pki_authdb_basedn=dc=example,dc=com
```

**Important:**
Since HSM keys are stored in the HSM, they cannot be backed up, moved, or copied to a PKCS #12 file.
For example, if **pki_hsm_enable** is set to **True**, **pki_backup_keys** should be set to **False** and
**pki_backup_password** should be left unset (the default values in /usr/share/pki/server/etc/default.cfg).
Similarly, for the case of clones using an HSM, this means that the HSM keys must be
shared between the master and its clones.
Therefore, if **pki_hsm_enable** is set to True, both **pki_clone_pkcs12_path** and **pki_clone_pkcs12_password**
should be left unset (the default values in /usr/share/pki/server/etc/default.cfg).
Failure to comply with these rules will result in **pkispawn** reporting an appropriate error and exiting.

### Installing CA Clone

To install a CA clone execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
pki_security_domain_hostname=<master_ca_hostname>
pki_security_domain_https_port=<master_ca_https_port>
pki_security_domain_user=caadmin
pki_security_domain_post_login_sleep_seconds=5

[Tomcat]
pki_clone=True
pki_clone_pkcs12_password=Secret.123
pki_clone_pkcs12_path=<path_to_pkcs12_file>
pki_clone_replicate_schema=True
pki_clone_uri=https://<master_ca_hostname>:<master_ca_https_port>
```

A cloned CA is a CA which uses the same signing, OCSP signing, and audit signing certificates as the master CA,
but issues certificates within a different serial number range.
It has its own internal database -- separate from the master CA database --
but using the same base DN, that keeps in sync with the master CA through replication agreements between the databases.
This is very useful for load sharing and disaster recovery.
To create a clone, the **myconfig.txt** uses pki_clone_* parameters in its [Tomcat] section
which identify the original CA to use as a master template.
Additionally, it connects to the master CA as a remote CA and uses its security domain.

Before the clone can be generated,
the Directory Server must be created that is separate from the master CA's Directory Server.
The example assumes that the master CA and cloned CA are on different machines,
and that their Directory Servers are on port 389.

In addition, since this example does not utilize an HSM, the master's system
certs and keys have been stored in a PKCS #12 file that is copied over to the
clone subsystem in the location specified in \<path_to_pkcs12_file>.
This file needs to be readable by the user the Certificate Server runs as
(by default, pkiuser) and be given the SELinux context **pki_tomcat_cert_t**.

The master's system certificates can be exported to a PKCS#12 file when the master is installed
if the parameter **pki_backup_keys** is set to **True** and the **pki_backup_password** is set.
The PKCS#12 file is then found under /var/lib/pki/\<instance_name>/alias.
Alternatively, the PKCS#12 file can be generated at any time post-installation using **PKCS12Export**.

The **pki_security_domain_post_login_sleep_seconds** config specifies sleep duration after logging into a security domain,
to allow the security domain session data to be replicated to subsystems on other hosts.
It is optional and defaults to 5 seconds.

An example invocation showing the export of the system certificates and keys, copying the keys to the replica subsystem,
and setting the relevant SELinux and file permissions is shown below.
**pwfile** is a text file containing the password for the masters NSS DB (found in /etc/pki/*instance_name*/password.conf).
**pkcs12_password_file** is a text file containing the password selected for the generated PKCS12 file.

```
master# PKCS12Export -d /etc/pki/pki-tomcat/alias -p pwfile \
        -w pkcs12_password_file -o backup_keys.p12
master# scp backup_keys.p12 clone:/backup_keys.p12

clone# chown pkiuser: /backup_keys.p12
clone# semanage -a -t pki_tomcat_cert_t /backup_keys.p12
```

**Note:**
From Dogtag 10.3, a slightly different mechanism has been provided to
create and specify the required PKCS#12 file to the clone subsystem.
This new method is provided in addition to the method above,
but will become the preferred method in future releases.

This method can be used if both master and clone are 10.3 or above.

To export the required keys from the master, use the **pki-server** command line tool.

```
master# pki-server ca-clone-prepare -i pki-tomcat \
        --pkcs12-file backup_keys.p12 \
        --pkcs12-password Secret123

master# scp backup_keys.p12 clone:/backup_keys.p12
master# scp /etc/pki/pki-tomcat/external_certs.conf \
         clone:/external_certs.conf
```

The **external_certs.conf** file contains information about third party certificates
that were added to the master's certificate database using the **pki-server**
command.  The certificates themselves are stored in the backup_keys.p12 file. If
there are no third-party certifcates that have been added, then the
**external_certs.conf** file may not exist and should be ignored.

The two files (**backup_keys.p12** and **external_certs.conf**) are specified
to pkispawn as below.

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
pki_security_domain_hostname=<master_ca_hostname>
pki_security_domain_https_port=<master_ca_https_port>
pki_security_domain_user=caadmin

[Tomcat]
pki_server_pkcs12_path=<path to pkcs12 file>
pki_server_pkcs12_password=Secret.123
pki_server_external_certs_path=<path to external_certs.conf file>
pki_clone=True
pki_clone_replicate_schema=True
pki_clone_uri=https://<master_ca_hostname>:<master_ca_https_port>
```

Note that the previous p12 parameters (pki_clone_pkcs12_*) are no longer needed, and will be ignored.

**Note:**
One current cloning anomaly to mention is the following scenario:

1. Create a clone of a CA or of any other subsystem.
2. Remove that just created clone.
3. Immediately attempt the exact same clone again, in place of the recently destroyed instance.
   Before recreating this clone,  make sure the **pki_ds_remove_data=True** is used in the clone's deployment config file.
   This will remove the old data from the previous clone.

Here the Director Server instance may have worked itself in into a state
where it no longer accepts connections, aborting the clone configuration quickly.

The fix to this is to simply restart the Directory Server instance before creating the clone for the second time.
After restarting the Directory Server it should be possible to create the mentioned clone instance.

### Installing KRA or TKS Clone

To install a KRA or TKS (OCSP and TPS unsupported as of now) execute the following command:

```
$ pkispawn -s <subsystem> -f myconfig.txt
```

where subsystem is KRA or TKS and **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
pki_security_domain_hostname=<master_ca_hostname>
pki_security_domain_https_port=<master_ca_https_port>
pki_security_domain_user=caadmin

[Tomcat]
pki_clone=True
pki_clone_pkcs12_password=Secret.123
pki_clone_pkcs12_path=<path_to_pkcs12_file>
pki_clone_replicate_schema=True
pki_clone_uri=https://<master_subsystem_host>:<master_subsystem_https_port>
pki_issuing_ca=https://<ca_hostname>:<ca_https_port>
```

As with a CA clone, a KRA or TKS clone uses the same certificates and basic configuration as the original subsystem.
The configuration points to the original subsystem to copy its configuration.
This example also assumes that the CA is on a remote machine and specifies the CA and security domain information.

The parameter **pki_clone_uri** should be modified to point to the required master (KRA or TKS).

As of 10.3, a slightly different mechanism has been introduced to generate and
specify the PKCS#12 file and any third-party certificates.
See the **Installing CA Clone** section for details.

### Installing CA Clone on the Same Host

For testing purposes, it is useful to configure cloned CAs which exist (with
their internal databases) on the same host as the master CA. To configure
the cloned CA execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret123
pki_client_database_password=Secret123
pki_client_pkcs12_password=Secret123
pki_ds_password=Secret123
pki_ds_ldap_port=<unique port different from master>
pki_ds_ldaps_port=<unique port different from master>
pki_http_port=<unique port different from master>
pki_https_port=<unique port different from master>
pki_instance_name=<unique name different from master>
pki_security_domain_hostname=<master_ca_hostname>
pki_security_domain_https_port=<master_ca_https_port>
pki_security_domain_password=Secret123

[Tomcat]
pki_ajp_port=<unique port different from master>
pki_clone=True
pki_clone_pkcs12_password=Secret123
pki_clone_pkcs12_path=<path_to_pkcs12_file>
pki_clone_uri=https://<master_ca_hostname>:<master_ca_https_port>
pki_tomcat_server_port=<unique port different from master>

[CA]
pki_ds_base_dn=<identical value as master>
pki_ds_database=<identical value as master>
```

In this case, because both CA Tomcat instances are on the same host, they must have distinct ports.
Similarly, each CA must use a distinct directory server instance for its internal database.
Like the Tomcat instances, these are distinguished by distinct ports.
The suffix being replicated (**pki_ds_base**), however, must be the same for both master and clone.

### Installing Subordinate CA in Existing Security Domain

To install a subordinate CA in an existing security domain execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
pki_security_domain_hostname=<security_domain_ca_hostname>
pki_security_domain_https_port=<security_domain_ca_https_port>
pki_security_domain_user=caadmin

[CA]
pki_subordinate=True
pki_issuing_ca=https://<master_ca_hostname>:<master_ca_https_port>
pki_ca_signing_subject_dn=cn=CA Subordinate Signing,o=example.com
```

A sub-CA derives its certificate configuration -- such as allowed extensions and validity periods --
from a superior or root CA.
Otherwise, the configuration of the CA is independent of the root CA,
so it is its own instance rather than a clone.
A sub-CA is configured using the **pki_subordinate** parameter
and a pointer to the CA which issues the sub-CA's certificates.

**Note:**
The value of **pki_ca_signing_subject_dn** of a subordinate CA should be different from the root CA's signing subject DN.

### Installing Subordinate CA in New Security Domain

To install a subordinate CA in a new security domain execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

where **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123
pki_security_domain_hostname=<master CA security domain hostname>
pki_security_domain_https_port=<master CA security domain https port>
pki_security_domain_user=caadmin

[CA]
pki_subordinate=True
pki_issuing_ca=https://<master_ca_hostname>:<master_ca_https_port>
pki_ca_signing_subject_dn=cn=CA Subordinate Signing,o=example.com
pki_subordinate_create_new_security_domain=True
pki_subordinate_security_domain_name=Subordinate CA Security Domain
```

In this section, the subordinate CA logs onto and registers with the security domain CA
(using parameters **pki_security_domain_hostname**, **pki_security_domain_user** and **pki_security_domain_password**) as in the previous section,
but also creates and hosts a new security domain.
To do this, **pki_subordinate_create_new_security_domain** must be set to **True**.
The subordinate CA security domain name can also be specified by specifying a value for **pki_subordinate_security_domain_name**.

**Note:**
The value of **pki_ca_signing_subject_dn** of a subordinate CA should be different from the root CA's signing subject DN.

### Installing Externally-Signed CA

To install an externally signed CA execute the following command:

```
$ pkispawn -s CA -f myconfig.txt
```

This is a two-step process.

In the first step, a certificate signing request (CSR) is generated for the
signing certificate and **myconfig.txt** contains the following text:

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123

[CA]
pki_external=True
pki_ca_signing_csr_path=/tmp/ca_signing.csr
pki_ca_signing_subject_dn=cn=CA Signing,ou=External,o=example.com
```

The CSR is written to **pki_ca_signing_csr_path**.
The **pki_ca_signing_subject_dn** should be different
from the subject DN of the external CA that is signing the request.
The **pki_ca_signing_subject_dn** parameter can be used to specify the signing certificate's subject DN.

The CSR is then submitted to the external CA,
and the resulting certificate and certificate chain are saved to files on the system.

In the second step, the configuration file has been modified to install the issued certificates.
In place of the original CSR, the configuration file now points to the issued CA certificate and certificate chain.
There is also a flag to indicate that this completes the installation process (**pki_external_step_two**).

```
[DEFAULT]
pki_admin_password=Secret.123
pki_client_database_password=Secret.123
pki_client_pkcs12_password=Secret.123
pki_ds_password=Secret.123
pki_security_domain_password=Secret.123

[CA]
pki_external=True
pki_external_step_two=True
pki_cert_chain_path=/tmp/ca_cert_chain.cert
pki_ca_signing_cert_path=/tmp/ca_signing.cert
pki_ca_signing_subject_dn=cn=CA Signing Certificate,ou=External,o=example.com
```

Then, the **pkispawn** command is run again:

```
$ pkispawn -s CA -f myconfig.txt
```

### Installing PKI Subsystem with Secure LDAP Connection

There are three scenarios in which a PKI subsystem (e.g. a CA) needs to
communicate securely via LDAPS with a directory server:

**Scenario 1:**
A directory server exists which is already running LDAPS using a CA
certificate that has been issued by some other CA.
For this scenario, the CA certificate must be made available via a PEM file
(e.g. $HOME/dscacert.pem) prior to running **pkispawn**
such that the new CA may be installed and configured to communicate
with this directory server using LDAPS.

**Scenario 2:**
A directory server exists which is currently running LDAP.
Once a CA has been created, there is a desire to use its CA certificate
to issue an SSL certificate for this directory server
so that this CA and this directory server can communicate via LDAPS.
For this scenario, since there is no need to communicate securely during the **pkispawn** installation/configuration,
simply use **pkispawn** to install and configure the CA using the LDAP port of the directory server,
issue an SSL certificate from this CA for the directory server,
and then reconfigure the CA and directory server to communicate with each other via LDAPS.

**Scenario 3:**
Similar to the previous scenario, a directory server exists which is currently running LDAP,
and the desire is to create a CA and use it to establish LDAPS communications between this CA and this directory server.
However, for this scenario, there is a need for the CA and the directory
server to communicate securely during **pkispawn** installation and configuration.
For this to succeed, the directory server must generate a temporary self-signed certificate
which then must be made available via a PEM file (e.g. $HOME/dscacert.pem) prior to running **pkispawn**.
Once the CA has been created, swap things out to reconfigure the CA and directory server
to utilize LDAPS through the desired certificates.

Set up a Directory Server instance with a self-signed CA certificate (see **dscreate(8)**), then export the certificate into a PEM file

Once the self-signed CA certificate is obtained, add the following parameters
into the [DEFAULT] section in **myconfig.txt**:

```
pki_ds_secure_connection=True
pki_ds_secure_connection_ca_pem_file=$HOME/dscacert.pem
```

Then execute **pkispawn** to create the CA subsystem.

### Managing PKI instance

To start a PKI instance named \<pki_instance_name>:

```
$ systemctl start pki-tomcatd@<pki_instance_name>.service
```

To stop a PKI instance named \<pki_instance_name>:

```
$ systemctl stop pki-tomcatd@<pki_instance_name>.service
```

To restart a PKI instance named \<pki_instance_name>:

```
$ systemctl restart pki-tomcatd@<pki_instance_name>.service
```

To obtain the status of a PKI instance named \<pki_instance_name>:

```
$ systemctl status pki-tomcatd@<pki_instance_name>.service
```

To obtain a detailed status of a Tomcat PKI instance named \<pki_instance_name>:

```
$ pki-server status <pki_instance_name>
```

To list all available PKI instances installed on a system:

```
$ pki-server instance-find
```

## SEE ALSO

**pkidestroy(8)**  
**pki_default.cfg(5)**  
**pki(1)**  
**dscreate(8)**  

## AUTHORS

Ade Lee \<alee@redhat.com> and Dinesh Prasanth M K \<dmoluguw@redhat.com>

## COPYRIGHT

Copyright (c) 2020 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
