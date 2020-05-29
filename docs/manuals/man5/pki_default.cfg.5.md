# pki_default.cfg 5 "December 13, 2012" PKI "PKI Server Default Deployment Configuration"

## NAME

pki_default.cfg - PKI server default deployment configuration file.

## LOCATION

/usr/share/pki/server/etc/default.cfg

## DESCRIPTION

This file contains the default settings for a Certificate Server instance created using **pkispawn**.
This file should not be edited, as it can be modified when the Certificate Server packages are updated.
Instead, when setting up a Certificate Server instance, a user should provide **pkispawn** with a configuration file
containing overrides to the defaults in /usr/share/pki/server/etc/default.cfg.
See **pkispawn(8)** for details.

## SECTIONS

**default.cfg** contains parameters that are grouped into sections.
These sections are stacked, so that parameters defined in earlier sections can be overwritten by parameters defined in later sections.
The sections are read in the following order: [DEFAULT], [Tomcat], and the subsystem section ([CA], [KRA], [OCSP], [TKS], or [TPS]).
This allows the ability to specify parameters to be shared by all subsystems in [DEFAULT] or [Tomcat],
and subsystem-specific customization.

There are a small number of bootstrap parameters which are passed in the configuration file by **pkispawn**.
Other parameter's values can be interpolated tokens rather than explicit values.
For example:

```
pki_ca_signing_nickname=caSigningCert cert-%(pki_instance_name)s CA
```

This substitutes the value of **pki_instance_name** into the parameter value.
It is possible to interpolate any non-password parameter within a section or in [DEFAULT].
Any parameter used in interpolation can **ONLY** be overridden within the same section.
So, for example, **pki_instance_name** should only be overridden in [DEFAULT];
otherwise, interpolations can fail.

**Note:**
Any non-password related parameter values in the configuration file that needs to contain a **%** character must be properly escaped.
For example, a value of **foo%bar** would be specified as **foo%%bar** in the configuration file.

## PRE-CHECK PARAMETERS

Once the configuration parameters have been constructed from the above sections and
overrides, pkispawn will perform a series of basic tests to determine if the parameters
being passed in are valid and consistent, before starting any installation.
In pre-check mode, these tests are executed and then pkispawn exits.

It is possible to disable specific tests by setting the directives below.
While all these tests should pass to ensure a successful installation,
it may be reasonable to skip tests in pre-check mode.

**pki_skip_ds_verify**  
Skip verification of the Directory Server credentials.
In this test, pkispawn attempts to bind to the directory server instance for the internal database using the provided credentials.
This could be skipped if the directory server instance does not yet exist or is inaccessible.
Defaults to False.

**pki_skip_sd_verify**  
Skip verification of the security domain user/password.
In this test, pkispawn attempts to log onto the security domain using the provided credentials.
This can be skipped if the security domain is unavailable.
Defaults to False.

## GENERAL INSTANCE PARAMETERS

The parameters described below, as well as the parameters located in the following sections, can be customized as part of a deployment.
This list is not exhaustive.

**pki_instance_name**  
Name of the instance. The instance is located at /var/lib/pki/*instance_name*.
For Java subsystems, the default is specified as pki-tomcat.

**pki_https_port**, **pki_http_port**  
Secure and unsecure ports.  Defaults to standard Tomcat ports 8443 and 8080, respectively.

**pki_ajp_port**, **pki_tomcat_server_port**  
Ports for Tomcat subsystems.  Defaults to standard Tomcat ports of 8009 and 8005, respectively.

**pki_ajp_host**  
Host on which to listen for AJP requests.  Defaults to localhost to listen to local traffic only.

**pki_proxy_http_port**, **pki_proxy_https_port**, **pki_enable_proxy**  
Ports for an Apache proxy server.
Certificate Server instances can be run behind an Apache proxy server,
which will communicate with the Tomcat instance through the AJP port.
See the [Red Hat Certificate System documentation](https://access.redhat.com/knowledge/docs/Red_Hat_Certificate_System) for details.

**pki_user, pki_group, pki_audit_group**  
Specifies the default administrative user, group, and auditor group identities for PKI instances.
The default user and group are both specified as **pkiuser**, and the default audit group is specified as **pkiaudit**.

**pki_token_name**, **pki_token_password**  
The token and password where this instance's system certificate and keys are stored.
Defaults to the NSS internal software token.

**pki_hsm_enable**, **pki_hsm_libfile**, **pki_hsm_modulename**  
If an optional hardware security module (HSM) is being utilized (rather than the default software security module included in NSS),
then the **pki_hsm_enable** parameter must be set to **True** (by default this parameter is **False**),
and values must be supplied for both the **pki_hsm_libfile** (e.g. /opt/nfast/toolkits/pkcs11/libcknfast.so)
and **pki_hsm_modulename** parameters (e.g. nethsm).

### SYSTEM CERTIFICATE PARAMETERS

**pkispawn** sets up a number of system certificates for each subsystem.
The system certificates which are required differ between subsystems.
Each system certificate is denoted by a tag, as noted below.
The different system certificates are:

* signing certificate ("ca_signing").
  Used to sign other certificates.
  Required for CA.
* OCSP signing certificate ("ocsp_signing" in CA, "signing" in OCSP).
  Used to sign CRLs.
  Required for OCSP and CA.
* storage certificate ("storage").
  Used to encrypt keys for storage in KRA.
  Required for KRA only.
* transport certificate ("transport").
  Used to encrypt keys in transport to the KRA.
  Required for KRA only.
* subsystem certificate ("subsystem").
  Used to communicate between subsystems within the security domain.
  Issued by the security domain CA.  Required for all subsystems.
* server certificate ("sslserver").
  Used for communication with the server.
  One server certificate is required for each Certificate Server instance.
* audit signing certificate ("audit_signing").
  Used to sign audit logs.
  Required for all subsystems except the RA.

Each system certificate can be customized using the parameters below:

**pki\_&lt;tag&gt;\_key\_type**, **pki\_&lt;type&gt;\_key\_size**, **pki\_&lt;tag&gt;\_key\_algorithm**  
Characteristics of the private key.
See the [Red Hat Certificate System documentation](https://access.redhat.com/knowledge/docs/Red_Hat_Certificate_System) for possible options.
The defaults are RSA for the type, 2048 bits for the key size, and SHA256withRSA for the algorithm.

**pki_&lt;tag&gt;_signing_algorithm**  
For signing certificates, the algorithm used for signing.
Defaults to SHA256withRSA.

**pki_&lt;tag&gt;_token**  
Location where the certificate and private key are stored.
Defaults to the internal software NSS token database.

**pki_&lt;tag&gt;_nickname**  
Nickname for the certificate in the token database.

**pki_&lt;tag&gt;_subject_dn**  
Subject DN for the certificate.
The subject DN for the SSL Server certificate must include CN=*hostname*.

All system certs can be configured to request the PSS variant of rsa signing algorithms (when applicable).

**pki_use_pss_rsa_signing_algorithm**

Set this to True if algs such as SHA256withRSA/PSS for each subsystem signing algorithm is desired. The default is false.
If set only, this setting will cause all other signing algorithm values to be promoted to <alg>/PSS.

Ex: (SHA256withRSA/PSS)

If this setting is not set, the standard default algorithms will continue to be used, without PSS support..
If higher than 256 support is desired, each algorithm must be set explicitly, example:

pki_ca_signing_key_algorithm=SHA512withRSA/PSS
...

### ADMIN USER PARAMETERS

**pkispawn** creates a bootstrap administrative user that is a member of all the necessary groups
to administer the installed subsystem.
On a security domain CA, the CA administrative user is also a member of the groups required
to register a new subsystem on the security domain.
The certificate and keys for this administrative user are stored in a PKCS #12 file in **pki_client_dir**,
and can be imported into a browser to administer the system.

**pki_admin_name**, **pki_admin_uid**  
Name and UID of this administrative user.  Defaults to caadmin for CA, kraadmin for KRA, etc.

**pki_admin_password**  
Password for the admin user.
This password is used to log into the pki-console (unless client authentication is enabled), as well as log into the security domain CA.

**pki_admin_email**  
Email address for the admin user.

**pki_admin_dualkey**, **pki_admin_key_size**, **pki_admin_key_type**, **pki_admin_key_algorithm**  
Settings for the administrator certificate and keys.

**pki_admin_subject_dn**  
Subject DN for the administrator certificate.  Defaults to cn=PKI Administrator, e=%(pki_admin_email)s, o=%(pki_security_domain_name)s.

**pki_admin_nickname**  
Nickname for the administrator certificate.

**pki_import_admin_cert**  
Set to True to import an existing admin certificate for the admin user, rather than generating a new one.
A subsystem-specific administrator will still be created within the subsystem's LDAP tree.
This is useful to allow multiple subsystems within the same instance to be more easily administered
from the same browser by using a single certificate.

By default, this is set to False for CA subsystems and true for KRA, OCSP, TKS, and TPS subsystems.
In this case, the admin certificate is read from the file ca_admin.cert in **pki_client_dir**.

Note that cloned subsystems do not create a new administrative user.
The administrative user of the master subsystem is used instead,
and the details of this master user are replicated during the install.

**pki_client_admin_cert_p12**  
Location for the PKCS #12 file containing the administrative user's certificate and keys.
For a CA, this defaults to **ca_admin_cert.p12** in the **pki_client_dir** directory.

### BACKUP PARAMETERS

**pki_backup_keys**, **pki_backup_file**, **pki_backup_password**  
Set **pki_backup_keys** to True to back up the subsystem certificates and keys to a PKCS #12 file
specified in **pki_backup_file** (default is /etc/pki/*instance_name*/alias/*subsystem*_backup_keys.p12).
**pki_backup_password** is the password of the PKCS#12 file.

**Important:**
Keys in HSM may not be extractable, so they may not be able to be exported into a PKCS #12 file.
Therefore, if **pki_hsm_enable** is set to **True**, **pki_backup_keys** should be set to **False**
and **pki_backup_password** should be left unset (the default values in /usr/share/pki/server/etc/default.cfg).
Failure to do so will result in **pkispawn** reporting this error and exiting.

### CLIENT DIRECTORY PARAMETERS

**pki_client_dir**  
This is the location where all client data used during the installation is stored.
At the end of the invocation of **pkispawn**, the administrative user's certificate and keys are stored in a PKCS #12 file in this location.

**Note:**
When using an HSM, it is currently recommended to NOT specify a value for **pki_client_dir** that is different from the default value.

**pki_client_database_dir**, **pki_client_database_password**  
Location where an NSS token database is created in order to generate a key for the administrative user.
Usually, the data in this location is removed at the end of the installation,
as the keys and certificates are stored in a PKCS #12 file in **pki_client_dir**.

**pki_client_database_purge**  
Set to True to remove **pki_client_database_dir** at the end of the installation.
Defaults to True.

### INTERNAL DATABASE PARAMETERS

**pki_ds_hostname**, **pki_ds_ldap_port**, **pki_ds_ldaps_port**  
Hostname and ports for the internal database.  Defaults to localhost, 389, and 636, respectively.

**pki_ds_bind_dn**, **pki_ds_password**  
Credentials to connect to the database during installation.
Directory Manager-level access is required during installation to set up the relevant schema and database.
During the installation, a more restricted PKI user is set up to client authentication connections to the database.
Some additional configuration is required, including setting up the directory server to use SSL.
See the documentation for details.

**pki_ds_secure_connection**  
Sets whether to require connections to the Directory Server using LDAPS.
This requires SSL to be set up on the Directory Server first.
Defaults to false.

**pki_ds_secure_connection_ca_nickname**  
Once a Directory Server CA certificate has been imported into the PKI security databases (see **pki_ds_secure_connection_ca_pem_file**),
**pki_ds_secure_connection_ca_nickname** will contain the nickname under which it is stored.
The **default.cfg** file contains a default value for this nickname.
This parameter is only utilized when **pki_ds_secure_connection** has been set to true.

**pki_ds_secure_connection_ca_pem_file**  
The **pki_ds_secure_connection_ca_pem_file** parameter will consist of the fully-qualified path including the filename of a file
which contains an exported copy of a Directory Server's CA certificate.
While this parameter is only utilized when **pki_ds_secure_connection** has been set to true,
a valid value is required for this parameter whenever this condition exists.

**pki_ds_remove_data**  
Sets whether to remove any data from the base DN before starting the installation.
Defaults to True.

**pki_ds_base_dn**  
The base DN for the internal database.
It is advised that the Certificate Server have its own base DN for its internal database.
If the base DN does not exist, it will be created during the running of **pkispawn**.
For a cloned subsystem, the base DN for the clone subsystem MUST be the same as for the master subsystem.

**pki_ds_database**  
Name of the back-end database.
It is advised that the Certificate Server have its own base DN for its internal database.
If the back-end does not exist, it will be created during the running of **pkispawn**.

### ISSUING CA PARAMETERS

**pki_issuing_ca_hostname**, **pki_issuing_ca_https_port**, **pki_issuing_ca_uri**  
Hostname and port, or URI of the issuing CA.
Required for installations of subordinate CA and non-CA subsystems.
This should point to the CA that will issue the relevant system certificates for the subsystem.
In a default install, this defaults to the CA subsystem within the same instance.
The URI has the format https://*ca_hostname*:*ca_https_port*.

### MISCELLANEOUS PARAMETERS

**pki_restart_configured_instance**  
Sets whether to restart the instance after configuration is complete.  Defaults to True.

**pki_enable_access_log**  
Located in the [Tomcat] section, this variable determines whether the instance will enable (True) or disable (False) Tomcat access logging.
Defaults to True.

**pki_enable_java_debugger**  
Sets whether to attach a Java debugger such as Eclipse to the instance for troubleshooting.
Defaults to False.

**pki_enable_on_system_boot**  
Sets whether or not PKI instances should be started upon system boot.

Currently, if this PKI subsystem exists within a shared instance, and it has been configured to start upon system boot,
then ALL other previously configured PKI subsystems within this shared instance will start upon system boot.

Similarly, if this PKI subsystem exists within a shared instance, and it has been configured to NOT start upon system boot,
then ALL other previously configured PKI subsystems within this shared instance will NOT start upon system boot.

Additionally, if more than one PKI instance exists, no granularity exists which allows one PKI instance to be enabled
while another PKI instance is disabled (i.e. PKI instances are either all enabled or all disabled).
To provide this capability, the PKI instances must reside on separate machines.

Defaults to True (see the following note on why this was previously 'False').

**Note:**
Since this parameter did not exist prior to Dogtag 10.2.3, the default behavior of PKI instances in Dogtag 10.2.2 and prior was False.
To manually enable this behavior, obtain superuser privileges, and execute '**systemctl enable pki-tomcatd.target**';
to manually disable this behavior, execute '**systemctl disable pki-tomcatd.target**'.

**pki_security_manager**  
Enables the Java security manager policies provided by the JDK to be used with the instance.  Defaults to True.

### SECURITY DOMAIN PARAMETERS

The security domain is a component that facilitates communication between subsystems.
The first CA installed hosts this component and is used to register subsequent subsystems with the security domain.
These subsystems can communicate with each other using their subsystem certificate, which is issued by the security domain CA.
For more information about the security domain component,
see the [Red Hat Certificate System documentation](https://access.redhat.com/knowledge/docs/Red_Hat_Certificate_System).

**pki_security_domain_hostname**, **pki_security_domain_https_port**  
Location of the security domain.
Required for KRA, OCSP, TKS, and TPS subsystems and for CA subsystems joining a security domain.
Defaults to the location of the CA subsystem within the same instance.

**pki_security_domain_user**, **pki_security_domain_password**  
Administrative user of the security domain.
Required for KRA, OCSP, TKS, and TPS subsystems, and for CA subsystems joining a security domain.
Defaults to the administrative user for the CA subsystem within the same instance (caadmin).

**pki_security_domain_name**  
The name of the security domain. This is required for the security domain CA.

### CLONE PARAMETERS

**pki_clone**  
Installs a clone, rather than original, subsystem.

**pki_clone_pkcs12_password**, **pki_clone_pkcs12_path**  
Location and password of the PKCS #12 file containing the system certificates for the master subsystem being cloned.
This file should be readable by the user that the Certificate Server is running as (default of pkiuser),
and have the correct selinux context (**pki_tomcat_cert_t**).
This can be achieved by placing the file in /var/lib/pki/*instance_name*/alias.

**Important:**
Keys in HSM may not be extractable, so they may not be able to be exported into a PKCS #12 file.
For the case of clones using an HSM, this means that the HSM keys must be shared between the master and its clones.
Therefore, if **pki_hsm_enable** is set to True, both **pki_clone_pkcs12_path** and **pki_clone_pkcs12_password**
should be left unset (the default values in /usr/share/pki/server/etc/default.cfg).
Failure to do so will result in **pkispawn** reporting this error and exiting.

**pki_clone_setup_replication**  
Defaults to True.
If set to False, the installer does not set up replication agreements from the master to the clone
as part of the subsystem configuration.
In this case, it is expected that the top level suffix already exists, and that the data has already been replicated.
This option is useful if you want to use other tools to create and manage your replication topology,
or if the baseDN is already replicated as part of a top-level suffix.

**pki_clone_reindex_data**  
Defaults to False.
This parameter is only relevant when **pki_clone_setup_replication** is set to False.
In this case, it is expected that the database has been prepared and replicated as noted above.
Part of that preparation could involve adding indexes and indexing the data.
If you would like the Dogtag installer to add the indexes and reindex the data instead, set **pki_clone_reindex_data** to True.

**pki_clone_replication_master_port**, **pki_clone_replication_clone_port**  
Ports on which replication occurs.
These are the ports on the master and clone databases respectively.
Defaults to the internal database port.

**pki_clone_replicate_schema**  
Replicate schema when the replication agreement is set up and the new instance (consumer) is initialized.
Otherwise, the schema must be installed in the clone as a separate step beforehand.
This does not usually have to be changed.
Defaults to True.

**pki_clone_replication_security**  
The type of security used for the replication data.
This can be set to SSL (using LDAPS), TLS, or None.
Defaults to None.
For SSL and TLS, SSL must be set up for the database instances beforehand.

**pki_master_hostname**, **pki_master_https_port**, **pki_clone_uri**  
Hostname and port, or URI of the subsystem being cloned.
The URI format is https://*master_hostname*:*master_https_port* where the default master hostname and https port
are set to be the security domain's hostname and https port.

### CA SERIAL NUMBER PARAMETERS

**pki_serial_number_range_start**, **pki_serial_number_range_end**  
Sets the range of serial numbers to be used when issuing certificates.
Values here are hexadecimal (without the 0x prefix).
It is useful to override these values when migrating data from another CA, so that serial number conflicts do not occur.
Defaults to 1 and 10000000 respectively.

**pki_request_number_range_start**, **pki_request_number_range_end**  
Sets the range of request numbers to be used by the CA.
Values here are decimal.
It is useful to override these values when migrating data from another CA, so that request number conflicts do not occur.
Defaults to 1 and 10000000 respectively.

**pki_replica_number_range_start**, **pki_replica_number_range_end**  
Sets the range of replica numbers to be used by the CA.
These numbers are used to identify database replicas in a replication topology.
Values here are decimal.
Defaults to 1 and 100 respectively.

### EXTERNAL CA CERTIFICATE PARAMETERS

**pki_external**  
Sets whether the new CA will have a signing certificate that will be issued by an external CA.
This is a two step process.
In the first step, a CSR to be presented to the external CA is generated.
In the second step, the issued signing certificate and certificate chain are provided to the **pkispawn** utility to complete the installation.
Defaults to False.

**pki_ca_signing_csr_path**  
Required in the first step of the external CA signing process.
The CSR will be printed to the screen and stored in this location.

**pki_req_ski**  
Include a Subject Key Identifier extension in the CSR.
The value is either a hex-encoded byte string (**without** leading "0x"),
or the string "DEFAULT" which will derive a value from the public key.

**pki_external_step_two**  
Specifies that this is the second step of the external CA process.  Defaults to False.

**pki_ca_signing_cert_path**, **pki_cert_chain_path**  
Required for the second step of the external CA signing process.
This is the location of the CA signing cert (as issued by the external CA) and the external CA's certificate chain.

### SUBORDINATE CA CERTIFICATE PARAMETERS

**pki_subordinate**  
Specifies whether the new CA which will be a subordinate of another CA.
The master CA is specified by **pki_issuing_ca**.
Defaults to False.

**pki_subordinate_create_new_security_domain**  
Set to **True** if the subordinate CA will host its own security domain.
Defaults to **False**.

**pki_subordinate_security_domain_name**  
Used when **pki_subordinate_create_security_domain** is set to **True**.
Specifies the name of the security domain to be hosted on the subordinate CA.

### STANDALONE PKI PARAMETERS

A stand-alone PKI subsystem is defined as a non-CA PKI subsystem that does not contain a CA as a part of its deployment,
and functions as its own security domain.
Currently, only stand-alone KRAs are supported.

**pki_standalone**  
Sets whether or not the new PKI subsystem will be stand-alone.
This is a two step process.
In the first step, CSRs for each of this stand-alone PKI subsystem's certificates
will be generated so that they may be presented to the external CA.
In the second step, the issued certificates, external CA certificate,
and external CA certificate chain are provided to the **pkispawn** utility to complete the installation.
Defaults to False.

**pki_external_admin_csr_path**  
Will be generated by the first step of a stand-alone PKI process.
This is the location of the file containing the administrator's CSR (which will be presented to the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_admin.csr'.

**pki_external_audit_signing_csr_path**  
Will be generated by the first step of a stand-alone PKI process.
This is the location of the file containing the audit signing CSR (which will be presented to the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_audit_signing.csr'.

**pki_external_sslserver_csr_path**  
Will be generated by the first step of a stand-alone PKI process.
This is the location of the file containing the SSL server CSR (which will be presented to the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_sslserver.csr'.

**pki_external_storage_csr_path**  
[KRA ONLY] Will be generated by the first step of a stand-alone KRA process.
This is the location of the file containing the storage CSR (which will be presented to the external CA).
Defaults to '%(pki_instance_configuration_path)s/kra_storage.csr'.

**pki_external_subsystem_csr_path**  
Will be generated by the first step of a stand-alone PKI process.
This is the location of the file containing the subsystem CSR (which will be presented to the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_subsystem.csr'.

**pki_external_transport_csr_path**  
[KRA ONLY] Will be generated by the first step of a stand-alone KRA process.
This is the location of the file containing the transport CSR (which will be presented to the external CA).
Defaults to '%(pki_instance_configuration_path)s/kra_transport.csr'.

**pki_external_step_two**  
Specifies that this is the second step of a standalone PKI process.
Defaults to False.

**pki_cert_chain_path**  
Required for the second step of a stand-alone PKI process.
This is the location of the file containing the external CA signing certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/external_ca.cert'.

**pki_ca_signing_cert_path**  
Required for the second step of a stand-alone PKI process.
This is the location of the file containing the external CA's certificate chain (as issued by the external CA).
Defaults to empty.

**pki_external_admin_cert_path**  
Required for the second step of a stand-alone PKI process.
This is the location of the file containing the administrator's certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_admin.cert'.

**pki_external_audit_signing_cert_path**  
Required for the second step of a stand-alone PKI process.
This is the location of the file containing the audit signing certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_audit_signing.cert'.

**pki_external_sslserver_cert_path**  
Required for the second step of a stand-alone PKI process.
This is the location of the file containing the sslserver certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_sslserver.cert'.

**pki_external_storage_cert_path**  
[KRA ONLY] Required for the second step of a stand-alone KRA process.
This is the location of the file containing the storage certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/kra_storage.cert'.

**pki_external_subsystem_cert_path**  
Required for the second step of a stand-alone PKI process.
This is the location of the file containing the subsystem certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/%(pki_subsystem_type)s_subsystem.cert'.

**pki_external_transport_cert_path**  
[KRA ONLY] Required for the second step of a stand-alone KRA process.
This is the location of the file containing the transport certificate (as issued by the external CA).
Defaults to '%(pki_instance_configuration_path)s/kra_transport.cert'.

### KRA PARAMETERS

**pki_kra_ephemeral_requests**  
Specifies to use ephemeral requests for archivals and retrievals.  Defaults to False.

### TPS PARAMETERS

**pki_authdb_basedn**  
Specifies the base DN of TPS authentication database.

**pki_authdb_hostname**  
Specifies the hostname of TPS authentication database. Defaults to localhost.

**pki_authdb_port**  
Specifies the port number of TPS authentication database. Defaults to 389.

**pki_authdb_secure_conn**  
Specifies whether to use a secure connection to TPS authentication database.
Defaults to False.

**pki_enable_server_side_keygen**  
Specifies whether to enable server-side key generation. Defaults to False.
The location of the KRA instance should be specified in the **pki_kra_uri** parameter.

**pki_ca_uri**  
Specifies the URI of the CA instance used by TPS to create and revoke user
certificates. Defaults to the instance in which the TPS is running.

**pki_kra_uri**  
Specifies the URI of the KRA instance used by TPS to archive and recover keys.
Required if server-side key generation is enabled using the **pki_enable_server_side_keygen** parameter.
Defaults to the instance in which the TPS is running.

**pki_tks_uri**  
Specifies the URI of the TKS instance used by TPS to generate symmetric keys.
Defaults to the instance in which the TPS is running.

## SEE ALSO

**pkispawn(8)**

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2012 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
