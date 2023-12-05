#
# CA Profile
#
id=caCert.profile
name=All Purpose CA Profile
description=This profile creates a CA certificate that is valid for all signing purposes.
profileIDMapping=caCACert
profileSetIDMapping=caCertSet
list=2,7,4,5,6
2.default.class=com.netscape.cms.profile.def.CAValidityDefault
2.default.name=CA Certificate Validity Default
2.default.params.range=7305
2.default.params.startTime=0
4.default.class=com.netscape.cms.profile.def.AuthorityKeyIdentifierExtDefault
4.default.name=Authority Key Identifier Default
4.default.params.localKey=true
5.default.class=com.netscape.cms.profile.def.BasicConstraintsExtDefault
5.default.name=Basic Constraints Extension Default
5.default.params.basicConstraintsCritical=true
5.default.params.basicConstraintsIsCA=true
5.default.params.basicConstraintsPathLen=-1
6.default.class=com.netscape.cms.profile.def.KeyUsageExtDefault
6.default.name=Key Usage Default
6.default.params.keyUsageCritical=true
6.default.params.keyUsageDigitalSignature=true
6.default.params.keyUsageNonRepudiation=true
6.default.params.keyUsageDataEncipherment=false
6.default.params.keyUsageKeyEncipherment=false
6.default.params.keyUsageKeyAgreement=false
6.default.params.keyUsageKeyCertSign=true
6.default.params.keyUsageCrlSign=true
6.default.params.keyUsageEncipherOnly=false
6.default.params.keyUsageDecipherOnly=false
7.default.class=com.netscape.cms.profile.def.SubjectKeyIdentifierExtDefault
7.default.name=Subject Key Identifier Extension Default
7.default.params.critical=false
