# pki-tps-connector 5 "April 22, 2014" PKI "PKI TPS Connector Configuration"

## NAME

pki-tps-connector - PKI TPS Connector Configuration

## LOCATION

/var/lib/pki/*instance*/conf/tps/CS.cfg

## DESCRIPTION

TPS connector provides a mechanism for TPS to communicate with other PKI subsystems.
There are three supported connector types: CA, KRA, and TKS.
The connectors are defined using properties in the TPS configuration file.

## CA CONNECTOR

A CA connector is defined using properties that begin with tps.connector.ca&lt;n&gt;
where n is a positive integer indicating the ID of the CA connector.

**tps.connector.ca&lt;n&gt;.enable**  
This property contains a boolean value indicating whether the connector is enabled.

**tps.connector.ca&lt;n&gt;.host**  
In no-failover configuration, the property contains the hostname of the CA.

In failover configuration, the property contains a list of hostnames and port numbers of the CA subsystems.
The format is hostname:port separated by spaces.

**tps.connector.ca&lt;n&gt;.port**  
In no-failover configuration, the property contains the port number of the CA.

**tps.connector.ca&lt;n&gt;.nickName**  
This property contains the nickname of the TPS subsystem certificate for SSL client authentication to the CA.

**tps.connector.ca&lt;n&gt;.minHttpConns**  
This property contains the minimum number of HTTP connections.

**tps.connector.ca&lt;n&gt;.maxHttpConns**  
This property contains the maximum number of HTTP connections.

**tps.connector.ca&lt;n&gt;.uri.&lt;op&gt;**  
This property contains the URI to contact CA for the operation &lt;op&gt;.
Example ops: enrollment, renewal, revoke, unrevoke, getcert.

**tps.connector.ca&lt;n&gt;.timeout**  
This property contains the connection timeout.

**tps.connCAList**  
This property is used for **Revocation Routing**.
It contains a list of ordered ca id's separated by ',' that the revocation attempt should be made to.
Example:
tps.connCAList=ca1,ca2

**tps.connector.ca&lt;n&gt;.caNickname**  
This property is used for **Revocation Routing**.
It contains the nickname of the CA signing certificate that represents this ca&lt;n&gt;.

**tps.connector.ca&lt;n&gt;.caSKI**  
This property is used for **Revocation Routing**.
It contains the Subject Key Identifier of the CA signing certificate of this ca&lt;n&gt;.
This value is automatically calculated by TPS once and should not need handling by the administrator.

## KRA CONNECTOR

A KRA connector is defined using properties that begin with tps.connector.kra&lt;n&gt; where
n is a positive integer indicating the ID of the KRA connector.

**tps.connector.kra&lt;n&gt;.enable**  
This property contains a boolean value indicating whether the connector is enabled.

**tps.connector.kra&lt;n&gt;.host**  
In no-failover configuration, the property contains the hostname of the KRA.

In failover configuration, the property contains a list of hostnames and port numbers
of the KRA subsystems. The format is hostname:port separated by spaces.

**tps.connector.kra&lt;n&gt;.port**  
In no-failover configuration, the property contains the port number of the KRA.

**tps.connector.kra&lt;n&gt;.nickName**  
This property contains the nickname of the TPS subsystem certificate for SSL client
authentication to the KRA.

**tps.connector.kra&lt;n&gt;.minHttpConns**  
This property contains the minimum number of HTTP connections.

**tps.connector.kra&lt;n&gt;.maxHttpConns**  
This property contains the maximum number of HTTP connections.

**tps.connector.kra&lt;n&gt;.uri.&lt;op&gt;**  
This property contains the URI to contact KRA for the operation &lt;op&gt;.
Example ops: GenerateKeyPair, TokenKeyRecovery.

**tps.connector.kra&lt;n&gt;.timeout**  
This property contains the connection timeout.

## TKS CONNECTOR

A TKS connector is defined using properties that begin with tps.connector.tks&lt;n&gt; where
n is a positive integer indicating the ID of the TKS connector.

**tps.connector.tks&lt;n&gt;.enable**  
This property contains a boolean value indicating whether the connector is enabled.

**tps.connector.tks&lt;n&gt;.host**  
In no-failover configuration, the property contains the hostname of the TKS.

In failover configuration, the property contains a list of hostnames and port numbers
of the TKS subsystems. The format is hostname:port separated by spaces.

**tps.connector.tks&lt;n&gt;.port**  
In no-failover configuration, the property contains the port number of the TKS.

**tps.connector.tks&lt;n&gt;.nickName**  
This property contains the nickname of the TPS subsystem certificate for SSL client
authentication to the TKS.

**tps.connector.tks&lt;n&gt;.minHttpConns**  
This property contains the minimum number of HTTP connections.

**tps.connector.tks&lt;n&gt;.maxHttpConns**  
This property contains the maximum number of HTTP connections.

**tps.connector.tks&lt;n&gt;.uri.&lt;op&gt;**  
This property contains the URI to contact TKS for the operation &lt;op&gt;.
Example ops: computeRandomData, computeSessionKey, createKeySetData, encryptData.

**tps.connector.tks&lt;n&gt;.timeout**  
This property contains the connection timeout.

**tps.connector.tks&lt;n&gt;.generateHostChallenge**  
This property contains a boolean value indicating whether to generate host challenge.

**tps.connector.tks&lt;n&gt;.serverKeygen**  
This property contains a boolean value indicating whether to generate keys on server side.

**tps.connector.tks&lt;n&gt;.keySet**  
This property contains the key set to be used on TKS.

**tps.connector.tks&lt;n&gt;.tksSharedSymKeyName**  
This property contains the shared secret key name.

## EXAMPLE

```
tps.connector.ca1.enable=true
tps.connector.ca1.host=server.example.com
tps.connector.ca1.port=8443
tps.connector.ca1.minHttpConns=1
tps.connector.ca1.maxHttpConns=15
tps.connector.ca1.nickName=subsystemCert cert-pki-tomcat TPS
tps.connector.ca1.timeout=30
tps.connector.ca1.uri.enrollment=/ca/ee/ca/profileSubmitSSLClient
tps.connector.ca1.uri.renewal=/ca/ee/ca/profileSubmitSSLClient
tps.connector.ca1.uri.revoke=/ca/ee/subsystem/ca/doRevoke
tps.connector.ca1.uri.unrevoke=/ca/ee/subsystem/ca/doUnrevoke
# in case of Revocation Routing
# note that caSKI is automatically calculated by TPS
tps.connCAList=ca1,ca2
tps.connector.ca1.caNickname=caSigningCert cert-pki-tomcat CA
tps.connector.ca1.caSKI=hAzNarQMlzit4BymAlbduZMwVCc
# ca2 connector in case of Revocation Routing
tps.connector.ca2.<etc.>

tps.connector.kra1.enable=true
tps.connector.kra1.host=server.example.com
tps.connector.kra1.port=8443
tps.connector.kra1.minHttpConns=1
tps.connector.kra1.maxHttpConns=15
tps.connector.kra1.nickName=subsystemCert cert-pki-tomcat TPS
tps.connector.kra1.timeout=30
tps.connector.kra1.uri.GenerateKeyPair=/kra/agent/kra/GenerateKeyPair
tps.connector.kra1.uri.TokenKeyRecovery=/kra/agent/kra/TokenKeyRecovery

tps.connector.tks1.enable=true
tps.connector.tks1.host=server.example.com
tps.connector.tks1.port=8443
tps.connector.tks1.minHttpConns=1
tps.connector.tks1.maxHttpConns=15
tps.connector.tks1.nickName=subsystemCert cert-pki-tomcat TPS
tps.connector.tks1.timeout=30
tps.connector.tks1.generateHostChallenge=true
tps.connector.tks1.serverKeygen=false
tps.connector.tks1.keySet=defKeySet
tps.connector.tks1.tksSharedSymKeyName=sharedSecret
tps.connector.tks1.uri.computeRandomData=/tks/agent/tks/computeRandomData
tps.connector.tks1.uri.computeSessionKey=/tks/agent/tks/computeSessionKey
tps.connector.tks1.uri.createKeySetData=/tks/agent/tks/createKeySetData
tps.connector.tks1.uri.encryptData=/tks/agent/tks/encryptData
```

## AUTHORS

Dogtag PKI Team &lt;pki-devel@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
