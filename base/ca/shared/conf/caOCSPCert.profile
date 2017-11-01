#
# OCSP CA Profile
#
id=caOCSPCert.profile
name=All Purpose CA OCSP Profile
description=This profile creates a CA OCSP certificate that is valid for all signing purposes.
profileIDMapping=caOCSPCert
profileSetIDMapping=ocspCertSet
list=2,4,8,9,10
2.default.class=com.netscape.cms.profile.def.ValidityDefault
2.default.name=Validity Default
2.default.params.range=720
2.default.params.startTime=0
4.default.class=com.netscape.cms.profile.def.AuthorityKeyIdentifierExtDefault
4.default.name=Authority Key Identifier Default
7.default.class=com.netscape.cms.profile.def.SubjectKeyIdentifierExtDefault
7.default.name=Subject Key Identifier Extension Default
7.default.params.critical=false
8.default.class=com.netscape.cms.profile.def.AuthInfoAccessExtDefault
8.default.name=AIA Extension Default
8.default.params.authInfoAccessADEnable_0=true
8.default.params.authInfoAccessADLocationType_0=URIName
8.default.params.authInfoAccessADLocation_0=
8.default.params.authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1
8.default.params.authInfoAccessCritical=false
8.default.params.authInfoAccessNumADs=1
9.default.class=com.netscape.cms.profile.def.ExtendedKeyUsageExtDefault
9.default.name=Extended Key Usage Extension Default
9.default.params.exKeyUsageCritical=false
9.default.params.exKeyUsageOIDs=1.3.6.1.5.5.7.3.9
10.default.class=com.netscape.cms.profile.def.OCSPNoCheckExtDefault
10.default.name=OCSP No Check Extension Default
10.default.params.ocspNoCheckCritical=false
