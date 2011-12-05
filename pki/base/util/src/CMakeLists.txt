project(pki-cmsutil_java Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(OSUTIL_JAR
    NAMES
        osutil.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XALAN_JAR
    NAMES
        xalan-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

set(pki-nsutil_java_SRCS
    netscape/net/TransferProtocolClient.java
    netscape/net/smtp/SmtpProtocolException.java
    netscape/net/smtp/SmtpClient.java
    netscape/net/NetworkClient.java
    netscape/security/pkcs/ParsingException.java
    netscape/security/pkcs/PKCS9Attribute.java
    netscape/security/pkcs/EncodingException.java
    netscape/security/pkcs/SignerInfo.java
    netscape/security/pkcs/PKCS10Attribute.java
    netscape/security/pkcs/PKCS9Attributes.java
    netscape/security/pkcs/ContentInfo.java
    netscape/security/pkcs/PKCS10.java
    netscape/security/pkcs/PKCS10Attributes.java
    netscape/security/pkcs/PKCS7.java
    netscape/security/pkcs/PKCS8Key.java
    netscape/security/x509/OIDName.java
    netscape/security/x509/CertificateChain.java
    netscape/security/x509/CertificateVersion.java
    netscape/security/x509/LdapV3DNStrConverter.java
    netscape/security/x509/IssuerAlternativeNameExtension.java
    netscape/security/x509/PolicyMappingsExtension.java
    netscape/security/x509/CRLExtensions.java
    netscape/security/x509/X500NameAttrMap.java
    netscape/security/x509/CertificatePolicySet.java
    netscape/security/x509/X509Cert.java
    netscape/security/x509/NSCCommentExtension.java
    netscape/security/x509/Attribute.java
    netscape/security/x509/PrivateKeyUsageExtension.java
    netscape/security/x509/X509CRLImpl.java
    netscape/security/x509/X500Signer.java
    netscape/security/x509/CPSuri.java
    netscape/security/x509/AlgorithmId.java
    netscape/security/x509/SerialNumber.java
    netscape/security/x509/X509CertImpl.java
    netscape/security/x509/CertificatePolicyInfo.java
    netscape/security/x509/CertException.java
    netscape/security/x509/CRLNumberExtension.java
    netscape/security/x509/GeneralNameInterface.java
    netscape/security/x509/PolicyQualifiers.java
    netscape/security/x509/AVA.java
    netscape/security/x509/CertificateX509Key.java
    netscape/security/x509/RFC822Name.java
    netscape/security/x509/Extensions.java
    netscape/security/x509/FreshestCRLExtension.java
    netscape/security/x509/UserNotice.java
    netscape/security/x509/ReasonFlags.java
    netscape/security/x509/InvalidIPAddressException.java
    netscape/security/x509/IPAddressName.java
    netscape/security/x509/SubjectKeyIdentifierExtension.java
    netscape/security/x509/GenericValueConverter.java
    netscape/security/x509/CRLReasonExtension.java
    netscape/security/x509/CertificateAlgorithmId.java
    netscape/security/x509/DisplayText.java
    netscape/security/x509/CertificateValidity.java
    netscape/security/x509/PKIXExtensions.java
    netscape/security/x509/PrintableConverter.java
    netscape/security/x509/SubjectDirAttributesExtension.java
    netscape/security/x509/CRLDistributionPoint.java
    netscape/security/x509/NameConstraintsExtension.java
    netscape/security/x509/X509AttributeName.java
    netscape/security/x509/RFC1779StrConverter.java
    netscape/security/x509/X500Name.java
    netscape/security/x509/DNSName.java
    netscape/security/x509/URIName.java
    netscape/security/x509/CertAndKeyGen.java
    netscape/security/x509/RevocationReason.java
    netscape/security/x509/AVAValueConverter.java
    netscape/security/x509/CRLDistributionPointsExtension.java
    netscape/security/x509/GeneralSubtree.java
    netscape/security/x509/X509Key.java
    netscape/security/x509/PolicyConstraintsExtension.java
    netscape/security/x509/X509CertInfo.java
    netscape/security/x509/LdapDNStrConverter.java
    netscape/security/x509/X509ExtensionException.java
    netscape/security/x509/AuthorityKeyIdentifierExtension.java
    netscape/security/x509/NoticeReference.java
    netscape/security/x509/IA5StringConverter.java
    netscape/security/x509/UniqueIdentity.java
    netscape/security/x509/RevokedCertificate.java
    netscape/security/x509/CertificateExtensions.java
    netscape/security/x509/HoldInstructionExtension.java
    netscape/security/x509/IssuingDistributionPoint.java
    netscape/security/x509/GeneralName.java
    netscape/security/x509/CertificateIssuerName.java
    netscape/security/x509/IssuingDistributionPointExtension.java
    netscape/security/x509/AlgIdDSA.java
    netscape/security/x509/DeltaCRLIndicatorExtension.java
    netscape/security/x509/GeneralSubtrees.java
    netscape/security/x509/BasicConstraintsExtension.java
    netscape/security/x509/CertAttrSet.java
    netscape/security/x509/GeneralNamesException.java
    netscape/security/x509/ACertAttrSet.java
    netscape/security/x509/Qualifier.java
    netscape/security/x509/KeyIdentifier.java
    netscape/security/x509/CertificateSerialNumber.java
    netscape/security/x509/KeyUsageExtension.java
    netscape/security/x509/SubjectAlternativeNameExtension.java
    netscape/security/x509/CertificateSubjectUniqueIdentity.java
    netscape/security/x509/CertificateSubjectName.java
    netscape/security/x509/GeneralNames.java
    netscape/security/x509/Extension.java
    netscape/security/x509/CertificatePoliciesExtension.java
    netscape/security/x509/CertificateIssuerExtension.java
    netscape/security/x509/RDN.java
    netscape/security/x509/CertificatePolicyMap.java
    netscape/security/x509/DirStrConverter.java
    netscape/security/x509/CertificateIssuerUniqueIdentity.java
    netscape/security/x509/PolicyQualifierInfo.java
    netscape/security/x509/EDIPartyName.java
    netscape/security/x509/InvalidityDateExtension.java
    netscape/security/x509/CertificatePolicyId.java
    netscape/security/x509/CertParseError.java
    netscape/security/x509/OIDMap.java
    netscape/security/x509/PolicyConstraint.java
    netscape/security/x509/RevokedCertImpl.java
    netscape/security/x509/OtherName.java
    netscape/security/util/BigInt.java
    netscape/security/util/DerOutputStream.java
    netscape/security/util/ASN1CharStrConvMap.java
    netscape/security/util/ByteToCharUnicode.java
    netscape/security/util/DerValue.java
    netscape/security/util/CharToByteIA5String.java
    netscape/security/util/DerInputBuffer.java
    netscape/security/util/CharToBytePrintable.java
    netscape/security/util/ObjectIdentifier.java
    netscape/security/util/DerEncoder.java
    netscape/security/util/ExtPrettyPrint.java
    netscape/security/util/ByteArrayLexOrder.java
    netscape/security/util/BitArray.java
    netscape/security/util/CrlPrettyPrint.java
    netscape/security/util/CertPrettyPrint.java
    netscape/security/util/ByteArrayTagOrder.java
    netscape/security/util/PrettyPrintResources.java
    netscape/security/util/PrettyPrintFormat.java
    netscape/security/util/CharToByteUniversalString.java
    netscape/security/util/ByteToCharIA5String.java
    netscape/security/util/PubKeyPrettyPrint.java
    netscape/security/util/ByteToCharPrintable.java
    netscape/security/util/DerInputStream.java
    netscape/security/util/ByteToCharUniversalString.java
    netscape/security/provider/DSA.java
    netscape/security/provider/DSAPrivateKey.java
    netscape/security/provider/DSAParameters.java
    netscape/security/provider/DSAPublicKey.java
    netscape/security/provider/SystemIdentity.java
    netscape/security/provider/RSAPublicKey.java
    netscape/security/provider/SHA.java
    netscape/security/provider/SystemSigner.java
    netscape/security/provider/MD5.java
    netscape/security/provider/DSAParameterGenerator.java
    netscape/security/provider/CMS.java
    netscape/security/provider/DSAKeyPairGenerator.java
    netscape/security/provider/DSAKeyFactory.java
    netscape/security/provider/Sun.java
    netscape/security/provider/X509CertificateFactory.java
    netscape/security/extensions/SubjectInfoAccessExtension.java
    netscape/security/extensions/GenericASN1Extension.java
    netscape/security/extensions/NSCertTypeExtension.java
    netscape/security/extensions/CertificateScopeEntry.java
    netscape/security/extensions/KerberosName.java
    netscape/security/extensions/CertificateRenewalWindowExtension.java
    netscape/security/extensions/PresenceServerExtension.java
    netscape/security/extensions/OCSPNoCheckExtension.java
    netscape/security/extensions/CertInfo.java
    netscape/security/extensions/AccessDescription.java
    netscape/security/extensions/InhibitAnyPolicyExtension.java
    netscape/security/extensions/CertificateScopeOfUseExtension.java
    netscape/security/extensions/AuthInfoAccessExtension.java
    netscape/security/extensions/ExtendedKeyUsageExtension.java
    netscape/security/acl/AclImpl.java
    netscape/security/acl/AllPermissionsImpl.java
    netscape/security/acl/PrincipalImpl.java
    netscape/security/acl/AclEntryImpl.java
    netscape/security/acl/OwnerImpl.java
    netscape/security/acl/WorldGroupImpl.java
    netscape/security/acl/GroupImpl.java
    netscape/security/acl/PermissionImpl.java
)

set(pki-cmsutil_java_SRCS
    com/netscape/cmsutil/ldap/LDAPUtil.java
    com/netscape/cmsutil/xml/XMLObject.java
    com/netscape/cmsutil/scep/CRSPKIMessage.java
    com/netscape/cmsutil/util/Cert.java
    com/netscape/cmsutil/util/Fmt.java
    com/netscape/cmsutil/util/HMACDigest.java
    com/netscape/cmsutil/util/Utils.java
    com/netscape/cmsutil/net/ISocketFactory.java
    com/netscape/cmsutil/crypto/Token.java
    com/netscape/cmsutil/crypto/Module.java
    com/netscape/cmsutil/crypto/CryptoUtil.java
    com/netscape/cmsutil/password/PlainPasswordReader.java
    com/netscape/cmsutil/password/IPasswordWriter.java
    com/netscape/cmsutil/password/IPasswordStore.java
    com/netscape/cmsutil/password/IPasswordReader.java
    com/netscape/cmsutil/password/PlainPasswordWriter.java
    com/netscape/cmsutil/password/PlainPasswordFile.java
    com/netscape/cmsutil/radius/FramedProtocolAttribute.java
    com/netscape/cmsutil/radius/TerminationActionAttribute.java
    com/netscape/cmsutil/radius/NASPortTypeAttribute.java
    com/netscape/cmsutil/radius/LoginLATServiceAttribute.java
    com/netscape/cmsutil/radius/VendorSpecificAttribute.java
    com/netscape/cmsutil/radius/ServiceTypeAttribute.java
    com/netscape/cmsutil/radius/FramedAppleTalkLinkAttribute.java
    com/netscape/cmsutil/radius/RadiusConn.java
    com/netscape/cmsutil/radius/StateAttribute.java
    com/netscape/cmsutil/radius/Attribute.java
    com/netscape/cmsutil/radius/ReplyMessageAttribute.java
    com/netscape/cmsutil/radius/ResponseAuthenticator.java
    com/netscape/cmsutil/radius/GenericAttribute.java
    com/netscape/cmsutil/radius/AccessChallenge.java
    com/netscape/cmsutil/radius/FramedMTUAttribute.java
    com/netscape/cmsutil/radius/NASPortAttribute.java
    com/netscape/cmsutil/radius/CallingStationIdAttribute.java
    com/netscape/cmsutil/radius/UserNameAttribute.java
    com/netscape/cmsutil/radius/PacketFactory.java
    com/netscape/cmsutil/radius/UserPasswordAttribute.java
    com/netscape/cmsutil/radius/NASPacket.java
    com/netscape/cmsutil/radius/FramedRoutingAttribute.java
    com/netscape/cmsutil/radius/LoginLATNodeAttribute.java
    com/netscape/cmsutil/radius/AttributeSet.java
    com/netscape/cmsutil/radius/RequestAuthenticator.java
    com/netscape/cmsutil/radius/CHAPPasswordAttribute.java
    com/netscape/cmsutil/radius/FramedIPNetmaskAttribute.java
    com/netscape/cmsutil/radius/LoginLATPortAttribute.java
    com/netscape/cmsutil/radius/CallbackNumberAttribute.java
    com/netscape/cmsutil/radius/RejectException.java
    com/netscape/cmsutil/radius/ChallengeException.java
    com/netscape/cmsutil/radius/NASClassAttribute.java
    com/netscape/cmsutil/radius/LoginTCPPortAttribute.java
    com/netscape/cmsutil/radius/IdleTimeoutAttribute.java
    com/netscape/cmsutil/radius/AccessReject.java
    com/netscape/cmsutil/radius/SessionTimeoutAttribute.java
    com/netscape/cmsutil/radius/FramedIPAddressAttribute.java
    com/netscape/cmsutil/radius/FramedRouteAttribute.java
    com/netscape/cmsutil/radius/AccessAccept.java
    com/netscape/cmsutil/radius/FramedAppleTalkNetworkAttribute.java
    com/netscape/cmsutil/radius/ProxyStateAttribute.java
    com/netscape/cmsutil/radius/FilterIdAttribute.java
    com/netscape/cmsutil/radius/NASIdentifierAttribute.java
    com/netscape/cmsutil/radius/LoginIPHostAttribute.java
    com/netscape/cmsutil/radius/LoginServiceAttribute.java
    com/netscape/cmsutil/radius/PortLimitAttribute.java
    com/netscape/cmsutil/radius/AttributeFactory.java
    com/netscape/cmsutil/radius/ServerPacket.java
    com/netscape/cmsutil/radius/FramedAppleTalkZoneAttribute.java
    com/netscape/cmsutil/radius/CHAPChallengeAttribute.java
    com/netscape/cmsutil/radius/AccessRequest.java
    com/netscape/cmsutil/radius/CallerStationIdAttribute.java
    com/netscape/cmsutil/radius/Packet.java
    com/netscape/cmsutil/radius/CallbackIdAttribute.java
    com/netscape/cmsutil/radius/FramedIPXNetworkAttribute.java
    com/netscape/cmsutil/radius/LoginLATGroupAttribute.java
    com/netscape/cmsutil/radius/Authenticator.java
    com/netscape/cmsutil/radius/NASIPAddressAttribute.java
    com/netscape/cmsutil/radius/FramedCompressionAttribute.java
    com/netscape/cmsutil/http/ConnectAsync.java
    com/netscape/cmsutil/http/JssSSLSocketFactory.java
    com/netscape/cmsutil/http/HttpClient.java
    com/netscape/cmsutil/http/HttpMessage.java
    com/netscape/cmsutil/http/HttpRequest.java
    com/netscape/cmsutil/http/HttpResponse.java
    com/netscape/cmsutil/http/Http.java
    com/netscape/cmsutil/http/HttpEofException.java
    com/netscape/cmsutil/http/HttpProtocolException.java
    com/netscape/cmsutil/ocsp/Signature.java
    com/netscape/cmsutil/ocsp/RevokedInfo.java
    com/netscape/cmsutil/ocsp/TBSRequest.java
    com/netscape/cmsutil/ocsp/CertID.java
    com/netscape/cmsutil/ocsp/NameID.java
    com/netscape/cmsutil/ocsp/KeyHashID.java
    com/netscape/cmsutil/ocsp/OCSPRequest.java
    com/netscape/cmsutil/ocsp/Response.java
    com/netscape/cmsutil/ocsp/GoodInfo.java
    com/netscape/cmsutil/ocsp/SingleResponse.java
    com/netscape/cmsutil/ocsp/BasicOCSPResponse.java
    com/netscape/cmsutil/ocsp/ResponseBytes.java
    com/netscape/cmsutil/ocsp/OCSPResponse.java
    com/netscape/cmsutil/ocsp/UnknownInfo.java
    com/netscape/cmsutil/ocsp/OCSPResponseStatus.java
    com/netscape/cmsutil/ocsp/CertStatus.java
    com/netscape/cmsutil/ocsp/ResponseData.java
    com/netscape/cmsutil/ocsp/Request.java
    com/netscape/cmsutil/ocsp/ResponderID.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${LDAPJDK_JAR} ${XALAN_JAR} ${XERCES_JAR}
    ${JSS_JAR} ${OSUTIL_JAR})

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

# build pki-nsutil
set(CMAKE_JAR_CLASSES_PREFIX netscape)
add_jar(pki-nsutil ${pki-nsutil_java_SRCS})
add_dependencies(pki-nsutil osutil)
install_jar(pki-nsutil ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_NSUTIL_JAR ${pki-nsutil_JAR_FILE} CACHE INTERNAL "pki-nsutil jar file")

# build pki-cmsutil
set(CMAKE_JAR_CLASSES_PREFIX com/netscape/cmsutil)
add_jar(pki-cmsutil ${pki-cmsutil_java_SRCS})
add_dependencies(pki-cmsutil osutil pki-nsutil)
install_jar(pki-cmsutil ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_CMSUTIL_JAR ${pki-cmsutil_JAR_FILE} CACHE INTERNAL "pki-cmsutil jar file")

create_javadoc(pki-util-${APPLICATION_VERSION}
    PACKAGES com.netscape.cmsutil.crypto
             com.netscape.cmsutil.http
             com.netscape.cmsutil.ldap
             com.netscape.cmsutil.net
             com.netscape.cmsutil.ocsp
             com.netscape.cmsutil.password
             com.netscape.cmsutil.radius
             com.netscape.cmsutil.scep
             com.netscape.cmsutil.util
             com.netscape.cmsutil.xml
    SOURCEPATH ${CMAKE_CURRENT_SOURCE_DIR}
    CLASSPATH ${CMAKE_JAVA_INCLUDE_PATH}
    WINDOWTITLE "pki-util"
    WINDOWTITLE "pki-util"
    DOCTITLE "<h1>dogtag</h1>"
    AUTHOR TRUE
    USE TRUE
    VERSION TRUE
)
add_dependencies(pki-util-${APPLICATION_VERSION}_javadoc pki-cmsutil)
