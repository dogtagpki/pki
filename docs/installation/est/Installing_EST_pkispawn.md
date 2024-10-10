# EST installation using `pkispawn`

After the prerequisite in [Installing
EST](Installing_EST.md), it is possible to install **EST**.

## REALM user DB


**EST** subsystem has its own realm authentication with a separate
user DB. Out of the box *LDAP*, *PostreSQL* and file based DB are
supported. User management is currently not performed by the subsystem
so the DB has to be prepared in advance.

### LDAP based DB

Before adding users, please ensure that you have configured the
directory server and added base entries. The step is described
[here](https://github.com/dogtagpki/pki/wiki/DS-Installation).

The user DB requires a node containing the users (*inetOrgPerson*) and
a node containing the groups (*groupOfUniqueNames*). Therefore, if
the base dn is like `dc=pki,dc=example,dc=com` it is possible create a
tree with a user using the command:

```
ldapadd -x -H ldap://estds.example.com:3389 \
    -D "cn=Directory Manager"  -w Secret.123 << EOF
dn: dc=est,dc=pki,dc=example,dc=com
objectClass: domain
dc: est 
          
dn: ou=people,dc=est,dc=pki,dc=example,dc=com
ou: people
objectClass: top
objectClass: organizationalUnit
          
dn: ou=groups,dc=est,dc=pki,dc=example,dc=com
ou: groups
objectClass: top
objectClass: organizationalUnit
          
dn: uid=est-test-user,ou=people,dc=est,dc=pki,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: est-test-user
sn: EST TEST USER
cn: EST TEST USER
userPassword: Secret.123

dn: cn=estclient,ou=groups,dc=est,dc=pki,dc=example,dc=com
objectClass: top
objectClass: groupOfUniqueNames
cn: estclient
uniqueMember: uid=est-test-user,ou=People,dc=est,dc=pki,dc=example,dc=com
EOF
```

### PostgreSQL based DB

First, prepare a database (e.g. est) and a user (e.g. est) to access
the database. Verify the database connection with the following
command:

To use the *PostreSQL* DB the user tables should be created with the
sql file provided in
`/usr/share/pki/est/conf/realm/postgresql/create.sql` and then filled
with the user information. The tables can be created with the command:
```
$ psql -U est -t -A -f /tmp/create.sql est
```
Then fill the tables with the commands:
```
$ psql -U est -t -A -c "INSERT INTO users VALUES ('est-test-user', 'EST TEST USER', '<tomcat_digest>');"  est 
$ psql -U est -t -A -c "INSERT INTO groups VALUES ('estclient', 'EST TEST USERS');"  est 
$ psql -U est -t -A -c "INSERT INTO group_members VALUES ('estclient', 'est-test-user');"  est 
```

Note: the tomcat digest for the password can be obtained with the command:
```
$ tomcat-digest <user_password>
```

It is possible to use different schemas but in this case a custom
`statements.conf` file (provided in the same folder) has to be
provided in order to retrieve the user information from the DB.

Additionally, java driver for PostgreSQL need to be installed in the EST server and linked into library folder of pki:

```
# dnf install -y postgresql-jdbc
# ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib
# ln -s /usr/share/java/ongres-scram/client.jar /usr/share/pki/server/common/lib
# ln -s /usr/share/java/ongres-scram/common.jar /usr/share/pki/server/common/lib
# ln -s /usr/share/java/ongres-stringprep/saslprep.jar /usr/share/pki/server/common/lib/
# ln -s /usr/share/java/ongres-stringprep/stringprep.jar /usr/share/pki/server/common/lib/
```

## Installation

An example installation configuration is provided in
`/usr/share/pki/server/examples/installation/est.cfg`. To install EST
in the same instance of the CA and with the DS realm run the command:

```
# pkispawn \
    -f /usr/share/pki/server/examples/installation/est.cfg \
    -s EST \
    -D est_realm_url=ldap://estds.example.com:3389 \
    -v
```

The `est_realm_url` points to the user DB. The other configurations that could be modified according to the deployment are:

```
est_ca_profile=estServiceCert
est_ca_user_name=
est_ca_user_password=
est_ca_user_password_file=
est_ca_user_certificate=
est_realm_type=
est_realm_custom=
est_realm_url=
est_realm_auth_type=BasicAuth
est_realm_bind_dn=cn=Directory Manager
est_realm_bind_password=
est_realm_nickname=
est_realm_user=
est_realm_username=
est_realm_password=
est_realm_users_dn=ou=people,dc=est,dc=pki,dc=example,dc=com
est_realm_groups_dn=ou=groups,dc=est,dc=pki,dc=example,dc=com
est_realm_statements=/usr/share/pki/est/conf/realm/postgresql/statements.conf
est_authorizer_exec_path=/usr/share/pki/est/bin/estauthz
```

The `est_ca_*` provides information related to the user and profile
configured in the CA for the EST subsystem.

The `est_authorizer_exec_path` is the executable responsible to verify
the authorisation. The provided script checks only that the user has
the role *estclient*.

The `est_realm_*` options allow to customise the realm. Possible types
are: ds, postgresql and in-memory. As an example, to install EST with
PostgreSQL the command will be

```
# pkispawn \
    -f /usr/share/pki/server/examples/installation/est.cfg \
    -s EST \
    -D est_realm_url="jdbc:postgresql://postgresql.example.com:5432/est?ssl=true&sslmode=require" \
    -D est_realm_type=postgresql \
    -D est_realm_user=est \
    -D est_realm_password=mysecretpassword \
    -v
```

The `est_realm_custom` is a path to a custom realm configuration for
tomcat and if provided it will overwrite all other realm related
configurations.

### Installation on separate instance with certificates

In addition to the above, installating EST in a separate instance
requires some extra steps to configure the certificates.

The EST server cert (and a subsystem certificate to connect with the
CA) has to be pre-issued and provided to `pkispawn` with its full
chain in a **PKCS#12** bundle supplied via the `pki_server_pkcs12_*`
parameters on the `pkispawn` command line as exemplified below.

It is important that the certificate aliases in the PKCS#12 match with
the nickname used by EST. For SSL certificate the nickname configured
in `est.cfg` is `sslserver` but can be modified.

To create the PKCS12 with the certificate it is possible to
generate a server certificate for EST in the CA (end eventually the
user certificate) and then export them as in the following example:

```
# pki nss-cert-request --csr estSSLServer.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf --subject 'CN=est.example.com'

# pki -n caadmin \
    ca-cert-issue \
    --csr-file estSSLServer.csr \
    --profile caServerCert \
    --output-file estSSLServer.crt

# pki nss-cert-import --cert estSSLServer.crt sslserver

# pki pkcs12-cert-import sslserver --pkcs12-file $SHARED/est_server.p12 --pkcs12-password Secret.123
```

Similarly, to generate a subsystem certificate for EST, associate to
the EST user previously configured in the CA, and add in the same
PKCS12 of the SSL server certificate:

```
# pki nss-cert-request --csr estUser.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --subject 'CN=EST Subsystem Certificate,OU=pki-tomcat,O=EXAMPLE'

# pki -n caadmin -cert-issue \
    --csr-file estUser.csr \
    --profile caSubsystemCert \
    --output-file estUser.crt

# pki nss-cert-import --cert estUser.crt "EST subsystem cert"

# pki -n caadmin ca-user-cert-add est-ra-1 --input estUser.crt

# pki pkcs12-cert-import "EST subsystem cert" --pkcs12-file $SHARED/est_server.p12 --pkcs12-password Secret.123 --append
```


Using the generate bundle, the command to deploy EST is:

```
# pkispawn \
    -f /usr/share/pki/server/examples/installation/est.cfg \
    -s EST \
    -D est_realm_url=ldap://estds.example.com:3389 \
    -D pki_ca_uri=https://ca.example.com:8443 \
    -D est_ca_user_password= \
    -D est_ca_user_certificate=estUser \
    -D pki_server_pkcs12_path=est_server.p12 \
    -D pki_server_pkcs12_password=Secret.123 \
    -v
```


### Installation on separate instance without certificates

If the bundle certificates is not provided to `pkispawn`, during the installation,
the EST server cert will be issued like the certificates for EST clients using the configured profile.
In this case, beside the CA URL, it is needed only the CA signing certificate for the installation.
Retrieving the certificate can be done in the CA server with the command:

```
# pki-server cert-export ca_signing --cert-file ca_signing.crt
```

After moving the CA signing certificate to the EST server, it is possible to install EST with:

```
# pkispawn \
    -f /usr/share/pki/server/examples/installation/est.cfg \
    -s EST \
    -D est_realm_url=ldap://estds.example.com:3389 \
    -D pki_ca_uri=https://ca.example.com:8443 \
    -D pki_cert_chain_path=ca_signing.crt \
    -D pki_cert_chain_nickname=caSigning \
    -v
```

After the installation it is recommended to update the EST nssdb certificates using proper profile.

## Removing EST

To remove the EST subsystem it is possible to use the `pkidestroy` command as follow:

```
# pkidestroy -s CA -v
```

Note: the configuration and log folders are not removed. To remove
everything add the the options: `--remove-conf` `--remove-logs`.
