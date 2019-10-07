# Authors:
#     Jack Magne <jmagne@rehdat.com> based on work <ftweedal@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful',

# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not', write to the Free Software Foundation', Inc.',
# 51 Franklin Street', Fifth Floor', Boston', MA 02110-1301 USA.
#
# Copyright (C) 2017 Red Hat', Inc.
# All rights reserved.

from __future__ import absolute_import
import os.path
from lxml import etree
import socket

import pki
from pki.server.upgrade import PKIServerUpgradeScriptlet

op_format = 'op.format.externalRegISEtoken'
op_enroll = 'op.enroll.externalRegISEtoken'
op_enroll_keygen_auth = op_enroll + '.keyGen.authentication'
op_enroll_keygen_auth_rec = op_enroll_keygen_auth + '.recovery'
op_enroll_keygen_enc = op_enroll + '.keyGen.encryption'
op_enroll_keygen_enc_rec = op_enroll_keygen_enc + '.recovery'
op_enroll_keygen_sign = op_enroll + '.keyGen.signing'
op_enroll_keygen_sign_rec = op_enroll_keygen_sign + '.recovery'

proplist = [
    (op_format + '.auth.enable', 'true'),
    (op_format + '.auth.id', 'ldap1'),
    (op_format + '.ca.conn', 'ca1'),
    (op_format + '.cardmgr_instance', 'A0000000030000'),
    (op_format + '.cuidMustMatchKDD', 'false'),
    (op_format + '.enableBoundedGPKeyVersion', 'true'),
    (op_format + '.issuerinfo.enable', 'true'),
    (op_format + '.issuerinfo.value', 'http://[PKI_HOSTNAME]:[PKI_UNSECURE_PORT]/tps/phoneHome'),
    (op_format + '.loginRequest.enable', 'true'),
    (op_format + '.maximumGPKeyVersion', 'FF'),
    (op_format + '.minimumGPKeyVersion', '01'),
    (op_format + '.revokeCert', 'false'),
    (op_format + '.revokeCert.reason', '0'),
    (op_format + '.rollbackKeyVersionOnPutKeyFailure', 'false'),
    (op_format + '.tks.conn', 'tks1'),
    (op_format + '.update.applet.directory', '/usr/share/pki/tps/applets'),
    (op_format + '.update.applet.emptyToken.enable', 'true'),
    (op_format + '.update.applet.encryption', 'true'),
    (op_format + '.update.applet.requiredVersion', '1.4.58768072'),
    (op_format + '.update.symmetricKeys.enable', 'false'),
    (op_format + '.update.symmetricKeys.requiredVersion', '1'),
    (op_format + '.validateCardKeyInfoAgainstTokenDB', 'true'),
    (op_enroll + '._000', '#########################################'),
    (op_enroll + '._001', '# Enrollment for externalReg'),
    (op_enroll + '._002', '#     ID, Signing,Encryption'),
    (op_enroll + '._003', '#    controlled by registration user record'),
    (op_enroll + '._004', '#########################################'),
    (op_enroll + '.auth.enable', 'true'),
    (op_enroll + '.auth.id', 'ldap1'),
    (op_enroll + '.cardmgr_instance', 'A0000000030000'),
    (op_enroll + '.cuidMustMatchKDD', 'false'),
    (op_enroll + '.enableBoundedGPKeyVersion', 'true'),
    (op_enroll + '.issuerinfo.enable', 'true'),
    (op_enroll + '.issuerinfo.value', 'http://[PKI_HOSTNAME]:[PKI_UNSECURE_PORT]/tps/phoneHome'),
    (op_enroll_keygen_auth + '.SANpattern', '$auth.edipi$.$auth.pcc$@EXAMPLE.com'),
    (op_enroll_keygen_auth + '.ca.conn', 'ca1'),
    (op_enroll_keygen_auth + '.ca.profileId', 'caTokenUserDelegateAuthKeyEnrollment'),
    (op_enroll_keygen_auth + '.certAttrId', 'c3'),
    (op_enroll_keygen_auth + '.certId', 'C3'),
    (op_enroll_keygen_auth + '.cuid_label', '$cuid$'),
    (op_enroll_keygen_auth + '.dnpattern',
     'cn=$auth.firstname$.$auth.lastname$.$auth.edipi$,e=$auth.mail$,o=TMS Org'),
    (op_enroll_keygen_auth + '.keySize', '1024'),
    (op_enroll_keygen_auth + '.keyUsage', '0'),
    (op_enroll_keygen_auth + '.keyUser', '0'),
    (op_enroll_keygen_auth + '.label', 'authentication key for $userid$'),
    (op_enroll_keygen_auth + '.overwrite', 'true'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.decrypt', 'false'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.derive', 'false'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.encrypt', 'false'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.private', 'true'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.sensitive', 'true'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.sign', 'true'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.signRecover', 'true'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.token', 'true'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.unwrap', 'false'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.verify', 'false'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.verifyRecover', 'false'),
    (op_enroll_keygen_auth + '.private.keyCapabilities.wrap', 'false'),
    (op_enroll_keygen_auth + '.privateKeyAttrId', 'k6'),
    (op_enroll_keygen_auth + '.privateKeyNumber', '6'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.decrypt', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.derive', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.encrypt', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.private', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.sensitive', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.sign', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.signRecover', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.token', 'true'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.unwrap', 'false'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.verify', 'true'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.verifyRecover', 'true'),
    (op_enroll_keygen_auth + '.public.keyCapabilities.wrap', 'false'),
    (op_enroll_keygen_auth + '.publicKeyAttrId', 'k7'),
    (op_enroll_keygen_auth + '.publicKeyNumber', '7'),
    (op_enroll_keygen_auth_rec + '.destroyed.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_auth_rec + '.destroyed.revokeCert', 'false'),
    (op_enroll_keygen_auth_rec + '.destroyed.revokeCert.reason', '0'),
    (op_enroll_keygen_auth_rec + '.destroyed.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_auth_rec + '.destroyed.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_auth_rec + '.keyCompromise.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_auth_rec + '.keyCompromise.revokeCert', 'false'),
    (op_enroll_keygen_auth_rec + '.keyCompromise.revokeCert.reason', '1'),
    (op_enroll_keygen_auth_rec + '.keyCompromise.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_auth_rec + '.keyCompromise.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_auth_rec + '.onHold.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_auth_rec + '.onHold.revokeCert', 'false'),
    (op_enroll_keygen_auth_rec + '.onHold.revokeCert.reason', '6'),
    (op_enroll_keygen_auth_rec + '.onHold.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_auth_rec + '.onHold.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_auth_rec + '.terminated.holdRevocationUntilLastCredential', 'true'),
    (op_enroll_keygen_auth_rec + '.terminated.revokeCert', 'true'),
    (op_enroll_keygen_auth_rec + '.terminated.revokeCert.reason', '1'),
    (op_enroll_keygen_auth_rec + '.terminated.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_auth_rec + '.terminated.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_auth + '.serverKeygen.archive', 'false'),
    (op_enroll_keygen_auth + '.serverKeygen.drm.conn', 'kra1'),
    (op_enroll_keygen_auth + '.serverKeygen.enable', 'false'),
    (op_enroll_keygen_enc + '.SANpattern', '$auth.mail$,$auth.edipi$.$auth.pcc$@EXAMPLE.com'),
    (op_enroll_keygen_enc + '._000', '#########################################'),
    (op_enroll_keygen_enc + '._001', '# encryption cert/keys are "recovered" for this profile'),
    (op_enroll_keygen_enc + '._002', '# controlled from User Registartion db'),
    (op_enroll_keygen_enc + '._003', '#########################################'),
    (op_enroll_keygen_enc + '.ca.conn', 'ca1'),
    (op_enroll_keygen_enc + '.ca.profileId', 'caTokenUserEncryptionKeyEnrollment'),
    (op_enroll_keygen_enc + '.certAttrId', 'c2'),
    (op_enroll_keygen_enc + '.certId', 'C2'),
    (op_enroll_keygen_enc + '.cuid_label', '$cuid$'),
    (op_enroll_keygen_enc + '.dnpattern',
     'cn=$auth.firstname$.$auth.lastname$.$auth.exec-edipi$,e=$auth.mail$,o=TMS Org'),
    (op_enroll_keygen_enc + '.keySize', '1024'),
    (op_enroll_keygen_enc + '.keyUsage', '0'),
    (op_enroll_keygen_enc + '.keyUser', '0'),
    (op_enroll_keygen_enc + '.label', 'encryption key for $userid$'),
    (op_enroll_keygen_enc + '.overwrite', 'true'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.decrypt', 'true'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.derive', 'false'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.encrypt', 'false'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.private', 'true'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.sensitive', 'true'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.sign', 'false'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.signRecover', 'false'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.token', 'true'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.unwrap', 'true'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.verify', 'false'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.verifyRecover', 'false'),
    (op_enroll_keygen_enc + '.private.keyCapabilities.wrap', 'false'),
    (op_enroll_keygen_enc + '.privateKeyAttrId', 'k4'),
    (op_enroll_keygen_enc + '.privateKeyNumber', '4'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.decrypt', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.derive', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.encrypt', 'true'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.private', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.sensitive', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.sign', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.signRecover', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.token', 'true'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.unwrap', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.verify', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.verifyRecover', 'false'),
    (op_enroll_keygen_enc + '.public.keyCapabilities.wrap', 'true'),
    (op_enroll_keygen_enc + '.publicKeyAttrId', 'k5'),
    (op_enroll_keygen_enc + '.publicKeyNumber', '5'),
    (op_enroll_keygen_enc_rec + '.destroyed.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_enc_rec + '.destroyed.revokeCert', 'false'),
    (op_enroll_keygen_enc_rec + '.destroyed.revokeCert.reason', '0'),
    (op_enroll_keygen_enc_rec + '.destroyed.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_enc_rec + '.destroyed.scheme', 'RecoverLast'),
    (op_enroll_keygen_enc_rec + '.keyCompromise.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_enc_rec + '.keyCompromise.revokeCert', 'false'),
    (op_enroll_keygen_enc_rec + '.keyCompromise.revokeCert.reason', '1'),
    (op_enroll_keygen_enc_rec + '.keyCompromise.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_enc_rec + '.keyCompromise.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_enc_rec + '.onHold.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_enc_rec + '.onHold.revokeCert', 'false'),
    (op_enroll_keygen_enc_rec + '.onHold.revokeCert.reason', '6'),
    (op_enroll_keygen_enc_rec + '.onHold.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_enc_rec + '.onHold.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_enc_rec + '.terminated.holdRevocationUntilLastCredential', 'true'),
    (op_enroll_keygen_enc_rec + '.terminated.revokeCert', 'true'),
    (op_enroll_keygen_enc_rec + '.terminated.revokeCert.reason', '1'),
    (op_enroll_keygen_enc_rec + '.terminated.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_enc_rec + '.terminated.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_enc + '.serverKeygen.archive', 'true'),
    (op_enroll_keygen_enc + '.serverKeygen.drm.conn', 'kra1'),
    (op_enroll_keygen_enc + '.serverKeygen.enable', 'True'),
    (op_enroll + '.keyGen.keyType.num', '3'),
    (op_enroll + '.keyGen.keyType.value.0', 'signing'),
    (op_enroll + '.keyGen.keyType.value.1', 'authentication'),
    (op_enroll + '.keyGen.keyType.value.2', 'encryption'),
    (op_enroll + '.keyGen.recovery.destroyed.keyType.num', '3'),
    (op_enroll + '.keyGen.recovery.destroyed.keyType.value.0', 'signing'),
    (op_enroll + '.keyGen.recovery.destroyed.keyType.value.1', 'authentication'),
    (op_enroll + '.keyGen.recovery.destroyed.keyType.value.2', 'encryption'),
    (op_enroll + '.keyGen.recovery.keyCompromise.keyType.num', '3'),
    (op_enroll + '.keyGen.recovery.keyCompromise.keyType.value.0', 'signing'),
    (op_enroll + '.keyGen.recovery.keyCompromise.keyType.value.1', 'authentication'),
    (op_enroll + '.keyGen.recovery.keyCompromise.keyType.value.2', 'encryption'),
    (op_enroll + '.keyGen.recovery.onHold.keyType.num', '3'),
    (op_enroll + '.keyGen.recovery.onHold.keyType.value.0', 'signing'),
    (op_enroll + '.keyGen.recovery.onHold.keyType.value.1', 'authentication'),
    (op_enroll + '.keyGen.recovery.onHold.keyType.value.2', 'encryption'),
    (op_enroll_keygen_sign + '.SANpattern', '$auth.mail$'),
    (op_enroll_keygen_sign + '.ca.conn', 'ca1'),
    (op_enroll_keygen_sign + '.ca.profileId', 'caTokenUserDelegateSigningKeyEnrollment'),
    (op_enroll_keygen_sign + '.certAttrId', 'c1'),
    (op_enroll_keygen_sign + '.certId', 'C1'),
    (op_enroll_keygen_sign + '.cuid_label', '$cuid$'),
    (op_enroll_keygen_sign + '.dnpattern',
     'cn=$auth.firstname$.$auth.lastname$.$auth.edipi$,e=$auth.mail$,o=TMS Org'),
    (op_enroll_keygen_sign + '.keySize', '1024'),
    (op_enroll_keygen_sign + '.keyUsage', '0'),
    (op_enroll_keygen_sign + '.keyUser', '0'),
    (op_enroll_keygen_sign + '.label', 'signing key for $userid$'),
    (op_enroll_keygen_sign + '.overwrite', 'true'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.decrypt', 'false'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.derive', 'false'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.encrypt', 'false'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.private', 'true'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.sensitive', 'true'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.sign', 'true'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.signRecover', 'true'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.token', 'true'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.unwrap', 'false'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.verify', 'false'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.verifyRecover', 'false'),
    (op_enroll_keygen_sign + '.private.keyCapabilities.wrap', 'false'),
    (op_enroll_keygen_sign + '.privateKeyAttrId', 'k2'),
    (op_enroll_keygen_sign + '.privateKeyNumber', '2'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.decrypt', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.derive', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.encrypt', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.private', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.sensitive', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.sign', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.signRecover', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.token', 'true'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.unwrap', 'false'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.verify', 'true'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.verifyRecover', 'true'),
    (op_enroll_keygen_sign + '.public.keyCapabilities.wrap', 'false'),
    (op_enroll_keygen_sign + '.publicKeyAttrId', 'k3'),
    (op_enroll_keygen_sign + '.publicKeyNumber', '3'),
    (op_enroll_keygen_sign_rec + '.destroyed.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_sign_rec + '.destroyed.revokeCert', 'false'),
    (op_enroll_keygen_sign_rec + '.destroyed.revokeCert.reason', '0'),
    (op_enroll_keygen_sign_rec + '.destroyed.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_sign_rec + '.destroyed.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_sign_rec + '.keyCompromise.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_sign_rec + '.keyCompromise.revokeCert', 'false'),
    (op_enroll_keygen_sign_rec + '.keyCompromise.revokeCert.reason', '1'),
    (op_enroll_keygen_sign_rec + '.keyCompromise.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_sign_rec + '.keyCompromise.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_sign_rec + '.onHold.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_sign_rec + '.onHold.revokeCert', 'false'),
    (op_enroll_keygen_sign_rec + '.onHold.revokeCert.reason', '6'),
    (op_enroll_keygen_sign_rec + '.onHold.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_sign_rec + '.onHold.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_sign_rec + '.terminated.holdRevocationUntilLastCredential', 'false'),
    (op_enroll_keygen_sign_rec + '.terminated.revokeCert', 'true'),
    (op_enroll_keygen_sign_rec + '.terminated.revokeCert.reason', '1'),
    (op_enroll_keygen_sign_rec + '.terminated.revokeExpiredCerts', 'false'),
    (op_enroll_keygen_sign_rec + '.terminated.scheme', 'GenerateNewKey'),
    (op_enroll_keygen_sign + '.serverKeygen.archive', 'false'),
    (op_enroll_keygen_sign + '.serverKeygen.drm.conn', 'kra1'),
    (op_enroll_keygen_sign + '.serverKeygen.enable', 'false'),
    (op_enroll + '.keyGen.tokenName', '$auth.cn$'),
    (op_enroll + '.loginRequest.enable', 'true'),
    (op_enroll + '.maximumGPKeyVersion', 'FF'),
    (op_enroll + '.minimumGPKeyVersion', '01'),
    (op_enroll + '.pinReset.enable', 'true'),
    (op_enroll + '.pinReset.pin.maxLen', '10'),
    (op_enroll + '.pinReset.pin.maxRetries', '127'),
    (op_enroll + '.pinReset.pin.minLen', '4'),
    (op_enroll + '.pkcs11obj.compress.enable', 'true'),
    (op_enroll + '.pkcs11obj.enable', 'true'),
    (op_enroll + '.renewal._000', '#########################################'),
    (op_enroll + '.renewal._001', '# Token Renewal.'),
    (op_enroll + '.renewal._002', '#'),
    (op_enroll + '.renewal._003', '# For each token in TPS UI, set the'),
    (op_enroll + '.renewal._004', '# following to trigger renewal'),
    (op_enroll + '.renewal._005', '# operations:'),
    (op_enroll + '.renewal._006', '#'),
    (op_enroll + '.renewal._007', '#     RENEW=YES'),
    (op_enroll + '.renewal._008', '#'),
    (op_enroll + '.renewal._009', '# Optional grace period enforcement'),
    (op_enroll + '.renewal._010', '# must coincide exactly with what'),
    (op_enroll + '.renewal._011', '# the CA enforces.'),
    (op_enroll + '.renewal._012', '#'),
    (op_enroll + '.renewal._013', '# In case of renewal, encryption certId'),
    (op_enroll + '.renewal._014', '# values are for completeness only, server'),
    (op_enroll + '.renewal._015', '# code calculates actual values used.'),
    (op_enroll + '.renewal._016', '#'),
    (op_enroll + '.renewal._017', '#########################################'),
    (op_enroll + '.renewal.authentication.ca.conn', 'ca1'),
    (op_enroll + '.renewal.authentication.ca.profileId', 'caTokenUserDelegateAuthKeyRenewal'),
    (op_enroll + '.renewal.authentication.certAttrId', 'c3'),
    (op_enroll + '.renewal.authentication.certId', 'C3'),
    (op_enroll + '.renewal.authentication.enable', 'true'),
    (op_enroll + '.renewal.authentication.gracePeriod.after', '30'),
    (op_enroll + '.renewal.authentication.gracePeriod.before', '30'),
    (op_enroll + '.renewal.authentication.gracePeriod.enable', 'false'),
    (op_enroll + '.renewal.keyType.num', '2'),
    (op_enroll + '.renewal.keyType.value.0', 'signing'),
    (op_enroll + '.renewal.keyType.value.1', 'authentication'),
    (op_enroll + '.renewal.signing.ca.conn', 'ca1'),
    (op_enroll + '.renewal.signing.ca.profileId', 'caTokenUserSigningKeyRenewal'),
    (op_enroll + '.renewal.signing.certAttrId', 'c1'),
    (op_enroll + '.renewal.signing.certId', 'C1'),
    (op_enroll + '.renewal.signing.enable', 'true'),
    (op_enroll + '.renewal.signing.gracePeriod.after', '30'),
    (op_enroll + '.renewal.signing.gracePeriod.before', '30'),
    (op_enroll + '.renewal.signing.gracePeriod.enable', 'false'),
    (op_enroll + '.rollbackKeyVersionOnPutKeyFailure', 'false'),
    (op_enroll + '.temporaryToken.tokenType', 'externalRegISEtokenTemporary'),
    (op_enroll + '.tks.conn', 'tks1'),
    (op_enroll + '.update.applet.directory', '/usr/share/pki/tps/applets'),
    (op_enroll + '.update.applet.emptyToken.enable', 'true'),
    (op_enroll + '.update.applet.enable', 'true'),
    (op_enroll + '.update.applet.encryption', 'true'),
    (op_enroll + '.update.applet.requiredVersion', '1.4.58768072'),
    (op_enroll + '.update.symmetricKeys.enable', 'false'),
    (op_enroll + '.update.symmetricKeys.requiredVersion', '1'),
    (op_enroll + '.validateCardKeyInfoAgainstTokenDB', 'true')
]


class AddTPSExternalRegISEtokenParams(PKIServerUpgradeScriptlet):
    def __init__(self):
        super(AddTPSExternalRegISEtokenParams, self).__init__()
        self.parser = etree.XMLParser(remove_blank_text=True)
        self.message = 'Add token profile params for externalRegISEtoken for TPS CS.cfg'

    def upgrade_subsystem(self, instance, subsystem):
        if subsystem.name == 'tps':
            self.upgrade_config(instance, subsystem)

    def upgrade_config(self, instance, subsystem):  # pylint: disable=W0613

        filename = os.path.join(subsystem.conf_dir, 'CS.cfg')
        server_xml = os.path.join(instance.conf_dir, 'server.xml')

        self.backup(filename)

        properties = pki.PropertyFile(filename)
        properties.read()

        # Get the unsecure phone home url out of the server.xml

        tps_unsecure_port = None
        hostname = socket.gethostname()

        document = etree.parse(server_xml, self.parser)
        server = document.getroot()
        connectors = server.findall('.//Connector')

        for connector in connectors:
            # find the Secure connector
            name = connector.get('name')
            if name != 'Unsecure':
                continue
            else:
                tps_unsecure_port = connector.get('port')

        # if the property exists, leave it alone', otherwise set
        # it to the value defined above
        # replace the standard non secure phone home url with value
        # from the server.xml file, which is known correct

        for k, v in proplist:

            cur = properties.get(k)

            if cur is not None:
                continue

            properties.set(k, v)

            if not k.endswith('.issuerinfo.value'):
                continue

            if tps_unsecure_port is None:
                continue

            properties.set(
                k,
                'http://' + hostname + ':' + tps_unsecure_port + '/tps/phoneHome')

        properties.write()
