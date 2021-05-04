// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.processor;

import org.dogtagpki.server.tps.channel.SecureChannel.TokenKeyType;
import org.dogtagpki.server.tps.cms.CARenewCertResponse;
import org.dogtagpki.server.tps.cms.CARetrieveCertResponse;
import org.dogtagpki.server.tps.cms.KRARecoverKeyResponse;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.main.ObjectSpec;

public class CertEnrollInfo {

    private TokenKeyType keyTypeEnum;
    private String profileId;
    private String certId;
    private String certAttrId;
    private String privateKeyAttrId;
    private String publicKeyAttrId;
    private String publisherId;
    private String keyType;
    private String keyTypePrefix;

    private CARetrieveCertResponse recoveredCertData;
    private KRARecoverKeyResponse  recoveredKeyData;
    private TokenRecord toBeRecoveredRecord;

    private CARenewCertResponse renewedCertData;

    private int keySize;
    private int algorithm;
    private int keyUsage;
    private int keyUser;
    private int privateKeyNumber;
    private int publicKeyNumber;
    private int startProgress;
    private int endProgress;

    private TPSEngine.ENROLL_MODES enrollmentMode = TPSEngine.ENROLL_MODES.MODE_ENROLL;

    public void setEnrollmentMode(TPSEngine.ENROLL_MODES mode) {
        enrollmentMode = mode;
    }

    public TPSEngine.ENROLL_MODES getEnrollmentMode() {
        return enrollmentMode;
    }

    public void setRecoveredCertData(CARetrieveCertResponse cData) {
        recoveredCertData = cData;
    }

    public CARetrieveCertResponse getRecoveredCertData() {
        return recoveredCertData;
    }

    public void setRecoveredKeyData(KRARecoverKeyResponse kData) {
        recoveredKeyData = kData;
    }

    public KRARecoverKeyResponse getRecoveredKeyData() {
        return recoveredKeyData;
    }


    public void setStartProgressValue(int progress) {
        startProgress = progress;
    }

    public int getStartProgressValue() {
        return startProgress;
    }

    public void setEndProgressValue(int progress) {
        endProgress = progress;
    }

    public int getEndProgressValue() {
        return endProgress;
    }

    public void setKeyTypeEnum(TokenKeyType keyTypeEnum) {
        this.keyTypeEnum = keyTypeEnum;
    }

    public TokenKeyType getKeyTypeEnum() {
        return keyTypeEnum;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    public String getProfileId() {
        return profileId;
    }

    public void setCertId(String certId) {
        this.certId = certId;
    }

    public String getCertId() {
        return certId;
    }

    public void setCertAttrId(String certAttrId) {
        this.certAttrId = certAttrId;
    }

    public String getCertAttrId() {
        return certAttrId;
    }

    public void setPrivateKeyAttrId(String priKeyAttrId) {
        privateKeyAttrId = priKeyAttrId;
    }

    public String getPrivateKeyAttrId() {
        return privateKeyAttrId;
    }

    public void setPublicKeyAttrId(String publicKeyAttrId) {
        this.publicKeyAttrId = publicKeyAttrId;
    }

    public String getPublicKeyAttrId() {
        return publicKeyAttrId;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setPublisherId(String publisherId) {
        this.publisherId = publisherId;
    }

    public String getPublisherId() {
        return publisherId;
    }

    public void setAlgorithm(int algorithm) {
        this.algorithm = algorithm;
    }

    public int getAlgorithm() {
        return algorithm;
    }

    public void setKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
    }

    public int getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUser(int keyUser) {
        this.keyUser = keyUser;
    }

    public int getKeyUser() {
        return keyUser;
    }

    public void setPrivateKeyNumber(int priKeyNumber) {
        privateKeyNumber = priKeyNumber;
    }

    public int getPrivateKeyNumber() {
        return privateKeyNumber;
    }

    public void setPublicKeyNumber(int pubKeyNumber) {
        publicKeyNumber = pubKeyNumber;
    }

    public int getPublicKeyNumber() {
        return publicKeyNumber;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyTypePrefix(String keyTypePrefix) {
        this.keyTypePrefix = keyTypePrefix;
    }

    public String getKeyTypePrefix() {
        return keyTypePrefix;
    }

    public boolean getIsRecoveryMode() {
        if (enrollmentMode == TPSEngine.ENROLL_MODES.MODE_RECOVERY) {
            return true;
        }

        return false;
    }

    public boolean getIsRenewalMode() {
        if (enrollmentMode == TPSEngine.ENROLL_MODES.MODE_RENEWAL) {
            return true;
        }

        return false;
    }

    public boolean getIsEnrollmentMode() {
        if (enrollmentMode == TPSEngine.ENROLL_MODES.MODE_ENROLL) {
            return true;
        }

        return false;
    }

    public void setTokenToBeRecovered(TokenRecord toBeRecovered) {
        toBeRecoveredRecord = toBeRecovered;

    }

    public TokenRecord getTokenToBeRecovered() {
        return toBeRecoveredRecord;
    }

    public void setRenewedCertData(CARenewCertResponse certResponse) {
        renewedCertData = certResponse;
    }

    public CARenewCertResponse getRenewedCertData() {
        return renewedCertData;
    }

    public int getCertIdIndex() {
        int result = 0;
        long objectID = 0;

        objectID = ObjectSpec.createObjectID(certId);
        result = ObjectSpec.getObjectIndex(objectID);

        return result;
    }

}
