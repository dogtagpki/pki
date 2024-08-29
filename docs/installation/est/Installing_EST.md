Installing EST
==============

Overview
--------

This page describes the process to install a *EST subsystem*.


Prerequisite
--------------------------

Create a Dogtag user group for EST RA accounts (**EST RA Agents**), and an EST RA
account (**est-ra-1**). The EST subsystem will use this account to authenticate to
the CA subsystem and issue certificates on behalf of EST clients.

```
# pki -n caadmin ca-group-add "EST RA Agents"
---------------------------
Added group "EST RA Agents"
---------------------------
  Group ID: EST RA Agents

# pki -n caadmin ca-user-add \
      est-ra-1 --fullName "EST RA 1" --password ************
---------------------
Added user "est-ra-1"
---------------------
  User ID: est-ra-1
  Full name: EST RA 1
# pki -d nssdb -c 4me2Test -n caadmin ca-group-member-add "EST RA Agents" est-ra-1
-----------------------------
  Added group member "est-ra-1"
-----------------------------
  User: est-ra-1	    
```

Add the EST profile `estServerCert.cfg` (it is available in `/usr/share/pki/ca/profiles/ca`):

```
# pki -d nssdb -c 4me2Test -n caadmin ca-profile-add --raw estServerCert.cfg
----------------------------
Added profile estServiceCert
----------------------------
# pki -n caadmin ca-profile-enable estServiceCert
--------------------------------
Enabled profile "estServiceCert"
--------------------------------
```


EST Subsystem Installation
--------------------------
Install the *EST subsystem* via dnf command.

```
# dnf install dogtag-pki-est
```

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
password=est4ever
EOF
```

Configure request authorization. The class `org.dogtagpki.est.ExternalProcessRequestAuthorizer` allows to delegate the authorization to an external process configured with the paramter **executable**:

```
# cat >/var/lib/pki/pki-tomcat/conf/est/authorizer.conf <<EOF
class=org.dogtagpki.est.ExternalProcessRequestAuthorizer
executable=/usr/local/libexec/estauthz
EOF
```

The executable should exist and have the right permission. Here an example:

```
# cat >/usr/local/libexec/estauthz <<EOF
#!/usr/bin/python3
import json, sys
ALLOWED_ROLE = 'estclient'
obj = json.loads(sys.stdin.read())
if not ALLOWED_ROLE in obj['authzData']['principal']['roles']:
    print(f'Principal does not have required role {ALLOWED_ROLE!r}')
    sys.exit(1)
EOF
# chmod +x /usr/local/libexec/estauthz
	
```

Deploy the EST application:

```
# pki-server est-deploy
```

Configure the authentication. The authentication is build on `com.netscape.cms.tomcat.ProxyRealm` class which allows to use realms from *tomcat* or developed for dogtag. As an example we use an in memory realm:

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



Verifying EST
-----------------------------

Use `curl` to verify that the *EST subsystem* is deployed and is able to communicate with the *CA subsystem*.


```
$ curl https://$EST_HOSTNAME:$EST_PORT/.well-known/est/cacerts
HTTP/1.1 200
Content-Type: application/pkcs7-mime
Transfer-Encoding: chunked
Date: Tue, 26 Jul 2022 05:47:49 GMT

<...certificate base64…>

```
Replace `$EST_HOSTNAME` and `$EST_PORT` with the hostname and port of the *EST subsystem*, respectively.

If successful, the server CA certificate chain will be printed on standard output and the command will exit with status 0 (success).
