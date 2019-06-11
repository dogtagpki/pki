Installing OCSP with ECC
========================

Overview
--------

This page describes the process to install a OCSP subsystem with ECC.


Supported ECC Curves:
---------------------

Dogtag supports following ECC Curves.
- nistp256 
- nistp384
- nistp521

Supported ECC Key algorithms:

- SHA256withEC 
- SHA384withEC
- SHA512withEC

OCSP Subsystem Installation with ECC
----------------------------------

Prepare a file (eg. ocsp_ecc.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_instance_name = topology-ecc-OCSP
pki_https_port = 8443
pki_http_port = 8080

pki_token_password = SECret.123

pki_admin_password = SECret.123
pki_admin_key_type=ecc
pki_admin_key_size=nistp521
pki_admin_key_algorithm=SHA512withEC

pki_hostname = pki1.example.com
pki_security_domain_hostname = pki1.example.com
pki_security_domain_name = topology-ecc_Foobarmaster.org
pki_security_domain_password = SECret.123
pki_security_domain_https_port = 8443

pki_client_dir = /opt/topology-ecc-OCSP
pki_client_pkcs12_password = SECret.123
pki_client_database_password = SECret.123

pki_backup_keys = True
pki_backup_password = SECret.123

pki_ds_password = SECret.123
pki_ds_ldap_port = 389

pki_sslserver_key_algorithm=SHA512withEC
pki_sslserver_key_size=nistp521
pki_sslserver_key_type=ecc
pki_sslserver_nickname=sslserver

pki_subsystem_key_algorithm=SHA512withEC
pki_subsystem_key_size=nistp521
pki_subsystem_key_type=ecc
pki_subsystem_nickname=subsystem

pki_audit_signing_key_type=ecc
pki_audit_signing_key_size=nistp521
pki_audit_signing_key_algorithm=SHA512withEC
pki_audit_signing_signing_algorithm=SHA512withEC
pki_audit_signing_nickname=ocsp_audit_signing

[Tomcat]
pki_ajp_port = 8009
pki_tomcat_server_port = 8005

[OCSP]
pki_import_admin_cert = False
pki_admin_nickname= PKI OCSP Administrator for Example.Org


pki_ds_hostname = pki1.example.com

pki_ocsp_signing_key_algorithm=SHA512withEC
pki_ocsp_signing_key_size=nistp521
pki_ocsp_signing_nickname=ocsp_signing
```

Then execute the following command:
```
# pkispawn -f ocsp_ecc.cfg -s OCSP
```

It will install OCSP subsystem in a Tomcat instance topology-ecc-OCSP and create the following NSS databases:
* server NSS database: /etc/pki/topology-ecc-OCSP/alias
* server Admin certificate: /opt/topology-ecc-OCSP/ocsp_admin_cert.p12

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/topology-ecc-OCSP/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

CA Signing Certificate - topology-ecc_Foobarmaster.org       CT,C,C
subsystem                                                    u,u,u
ocsp_audit_signing                                           u,u,Pu
ocsp_signing                                                 u,u,u
sslserver                                                    u,u,u
```

Verifying Admin Certificate
---------------------------

Prepare a client NSS database (eg: /root/nssdb)

```
# pki -d /root/nssdb -c Secret.123 client-init --force
```

Import admin key and certificate:

```
# pki -d /root/nssdb -c Secret.123 client-cert-import \
  --pkcs12 /opt/topology-ecc-OCSP/ocsp_admin_cert.p12 \
  --pkcs12-password-file /opt/topology-ecc-OCSP/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the OCSP subsystem by executing the following command:

```
# pki -d /root/nssdb -c Secret.123 -n "PKI OCSP Administrator for Example.Org" ocsp-user-show ocspadmin
--------------
User "ocspadmin"
--------------
  User ID: ocspadmin
  Full name: ocspadmin
  Email: ocspadmin@example.com
  Type: adminType
  State: 1
```
