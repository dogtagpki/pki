# EST installation using `pki-server`

After the prerequisite in [Installing EST](Installing_EST.md), it is
possible to install **EST**.

An instance has to be already available, if it is not present then it
is possible to create a new one with `pki-server create`, more details
[here](https://github.com/dogtagpki/pki/wiki/PKI-Server-Create-CLI).


Create the *EST subsytem* inside the pki server instance:

```
# pki-server est-create
```

Configure the issuance backend. The class `org.dogtagpki.est.DogtagRABackend` is used for the *Dogtag CA*. This requires:

- the **url** parameter pointing to the CA subsystem;
- credentials of an RA account, **username** and **password**, that is authorised to issue certificates using the configured profile;
  - is also possible to use TLS client certificate authentication to authenticate to the CA subsystem.
- the **profile**.


```
# cat >/var/lib/pki/pki-tomcat/conf/est/backend.conf <<EOF
class=org.dogtagpki.est.DogtagRABackend
url=https://$(hostname):8443
profile=estServiceCert
username=est-ra-1
password=password4ESTUser
EOF
```

Configure request authorization. The class
`org.dogtagpki.est.ExternalProcessRequestAuthorizer` allows to
delegate the authorization to an external process configured with the
paramter **executable**:

```
# cat >/var/lib/pki/pki-tomcat/conf/est/authorizer.conf <<EOF
class=org.dogtagpki.est.ExternalProcessRequestAuthorizer
executable=/usr/share/pki/est/bin/estauthz
EOF
```

The executable script perform a simple check of the user role and it
is available [here](/base/est/bin/estauthz). It can be replaced if
more complex authorization framework has to be adopted.


Deploy the EST application:

```
# pki-server est-deploy
```

Configure the authentication. The authentication allows to use realms from *tomcat* or developed for dogtag. As an example we use an in memory realm:

```
# cat >/var/lib/pki/pki-tomcat/conf/est/realm.conf <<EOF
class=com.netscape.cms.realm.PKIInMemoryRealm
username=alice
password=4me2Test
roles=estclient
EOF
```

Finally, restart the server:

```
# pki-server restart --wait
```

