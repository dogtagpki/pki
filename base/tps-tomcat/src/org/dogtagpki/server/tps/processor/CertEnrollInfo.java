package org.dogtagpki.server.tps.processor;

import org.dogtagpki.server.tps.processor.TPSEnrollProcessor.TokenKeyType;

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

    private int keySize;
    private int algorithm;
    private int keyUsage;
    private int keyUser;
    private int privateKeyNumber;
    private int publicKeyNumber;
    private int startProgress;
    private int endProgress;

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

}
