Installing CA with ECC
======================

Overview
--------

This page describes the process to install a CA subsystem with ECC self-signed CA signing certificate.

Before beginning with the installation, please ensure that you have configured the directory server and added base entries. The step is described [here](http://www.dogtagpki.org/wiki/Installing_DS).

Additionally, please verify that your FQDN is correctly reported by the following command:

    python -c 'import socket; print(socket.getfqdn())'

If it isn't, please add and entry at the beginning of the `/etc/hosts` file:

    127.0.0.1 server.example.com
    ::1 server.example.com

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

CA Subsystem Installation with ECC
----------------------------------

Prepare a file (eg. ca_ecc.cfg) that contains the deployment configuration, for example:
```
[DEFAULT]
pki_instance_name = topology-ecc-CA
pki_https_port =8443
pki_http_port = 8080

pki_token_password = SECret.123

pki_admin_password = SECret.123
pki_admin_key_type=ecc
pki_admin_key_size=nistp521
pki_admin_key_algorithm=SHA512withEC

pki_hostname = pki1.example.com
pki_security_domain_name = topology-ecc_Foobarmaster.org
pki_security_domain_password = SECret.123

pki_client_dir = /opt/topology-ecc-CA
pki_client_pkcs12_password = SECret.123
pki_backup_keys = True
pki_backup_password = SECret.123
pki_ds_password = SECret.123
pki_ds_ldap_port = 389

pki_sslserver_key_algorithm=SHA512withEC
pki_sslserver_key_size=nistp521
pki_sslserver_key_type=ecc

pki_subsystem_key_type=ecc
pki_subsystem_key_size=nistp521
pki_subsystem_key_algorithm=SHA512withEC

pki_audit_signing_key_algorithm=SHA512withEC
pki_audit_signing_key_size=nistp521
pki_audit_signing_key_type=ecc
pki_audit_signing_signing_algorithm=SHA512withEC

[Tomcat]
pki_ajp_port = 8009
pki_tomcat_server_port = 8005

[CA]
pki_import_admin_cert = False
pki_ds_hostname = pki1.example.com
pki_admin_nickname = PKI CA Administrator for Example.Org

pki_ca_signing_key_algorithm=SHA512withEC
pki_ca_signing_key_size=nistp521
pki_ca_signing_key_type=ecc
pki_ca_signing_signing_algorithm=SHA512withEC

pki_ocsp_signing_key_algorithm=SHA512withEC
pki_ocsp_signing_key_size=nistp521
pki_ocsp_signing_key_type=ecc
pki_ocsp_signing_signing_algorithm=SHA512withEC
```

Then execute the following command:

```
# pkispawn -f ca_ecc.cfg -s CA
```

It will install CA subsystem in a Tomcat instance topology-ecc-CA and create the following NSS databases:
* server NSS database: /etc/pki/topology-ecc-CA/alias
* server Admin certificate: /opt/topology-ecc-CA/ca_admin_cert.p12

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
# certutil -L -d /etc/pki/topology-ecc-CA/alias/

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ocspSigningCert cert-topology-ecc-CA CA                      u,u,u
subsystemCert cert-topology-ecc-CA                           u,u,u
caSigningCert cert-topology-ecc-CA CA                        CTu,Cu,Cu
auditSigningCert cert-topology-ecc-CA CA                     u,u,Pu
Server-Cert cert-topology-ecc-CA                             u,u,u

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
  --pkcs12 /opt/topology-ecc-CA/ca_admin_cert.p12 \
  --pkcs12-password-file /opt/topology-ecc-CA/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the CA subsystem by executing the following command:

```
# pki -d /root/nssdb -c Secret.123 -n "PKI CA Administrator for Example.Org" ca-user-show caadmin
--------------
User "caadmin"
--------------
  User ID: caadmin
  Full name: caadmin
  Email: caadmin@example.com
  Type: adminType
  State: 1
```
