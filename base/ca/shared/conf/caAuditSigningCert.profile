#
# CA Audit Signing Cert Profile
#
id=caAuditSigningCert.profile
name=CA Audit Signing Certificate Profile
description=This profile creates a CA Audit signing certificate that is valid for audit log signing purpose.
profileIDMapping=caAuditSigningCert
profileSetIDMapping=auditSigningCertSet
list=2,4,6,8
2.default.class=com.netscape.cms.profile.def.ValidityDefault
2.default.name=Validity Default
2.default.params.range=720
2.default.params.startTime=0
4.default.class=com.netscape.cms.profile.def.AuthorityKeyIdentifierExtDefault
4.default.name=Authority Key Identifier Default
6.default.class=com.netscape.cms.profile.def.KeyUsageExtDefault
6.default.name=Key Usage Default
6.default.params.keyUsageCritical=true
6.default.params.keyUsageDigitalSignature=true
6.default.params.keyUsageNonRepudiation=true
6.default.params.keyUsageDataEncipherment=false
6.default.params.keyUsageKeyEncipherment=false
6.default.params.keyUsageKeyAgreement=false
6.default.params.keyUsageKeyCertSign=false
6.default.params.keyUsageCrlSign=false
6.default.params.keyUsageEncipherOnly=false
6.default.params.keyUsageDecipherOnly=false
8.default.class=com.netscape.cms.profile.def.AuthInfoAccessExtDefault
8.default.name=AIA Extension Default
8.default.params.authInfoAccessADEnable_0=true
8.default.params.authInfoAccessADLocationType_0=URIName
8.default.params.authInfoAccessADLocation_0=
8.default.params.authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1
8.default.params.authInfoAccessCritical=false
8.default.params.authInfoAccessNumADs=1
