Installing KRA with ECC
======================

Overview
--------

This page describes the process to install a KRA subsystem with ECC.


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

KRA Subsystem Installation with ECC
----------------------------------

Prepare a file (eg. kra_ecc.cfg) that contains the deployment configuration, for example:
```
[DEFAULT]
pki_instance_name = topology-ecc-KRA
pki_https_port = 8443
pki_http_port = 8080

pki_token_password = SECret.123
pki_admin_password = SECret.123
pki_admin_key_type=ecc
pki_admin_key_size=nistp521
pki_admin_key_algorithm=SHA512withEC

pki_hostname = pki1.example.com
pki_security_domain_hostname = pki1.example.com
pki_security_domain_https_port = 8443
pki_security_domain_name = topology-ecc_Foobarmaster.org
pki_security_domain_password = SECret.123

pki_client_dir = /opt/topology-ecc-KRA
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

pki_audit_signing_key_algorithm=SHA512withEC
pki_audit_signing_key_size=nistp521
pki_audit_signing_key_type=ecc
pki_audit_signing_signing_algorithm=SHA512withEC
pki_audit_signing_nickname=kra_audit_signing

[Tomcat]
pki_ajp_port = 8009
pki_tomcat_server_port = 8005

[KRA]
pki_import_admin_cert = False
pki_admin_nickname = PKI KRA Administrator for Example.Org

pki_ds_hostname = pki1.example.com

pki_storage_key_algorithm=SHA512withRSA
pki_storage_key_size=2048
pki_storage_key_type=rsa
pki_storage_signing_algorithm=SHA512withRSA
pki_storage_nickname=kra_storage

pki_transport_key_algorithm=SHA512withRSA
pki_transport_key_size=2048
pki_transport_key_type=rsa
pki_transport_signing_algorithm=SHA512withRSA
pki_transport_nickname=kra_transport

```

Then execute the following command:

```
# pkispawn -f kra_ecc.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance topology-ecc-KRA and create the following NSS databases:
* server NSS database: /etc/pki/topology-ecc-KRA/alias
* server Admin certificate: /opt/topology-ecc-KRA/ca_admin_cert.p12

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/topology-ecc-KRA/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

CA Signing Certificate - topology-ecc_Foobarmaster.org       CT,C,C
kra_transport                                                u,u,u
kra_storage                                                  u,u,u
subsystem                                                    u,u,u
kra_audit_signing                                            u,u,Pu
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
  --pkcs12 /opt/topology-ecc-KRA/kra_admin_cert.p12 \
  --pkcs12-password-file /opt/topology-ecc-KRA/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the KRA subsystem by executing the following command:

```
# pki -d /root/nssdb -c Secret.123 -n "PKI KRA Administrator for Example.Org" kra-user-show kraadmin
--------------
User "kraadmin"
--------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```
