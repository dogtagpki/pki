package org.dogtagpki.server.tps.channel;

import org.dogtagpki.tps.main.TPSBuffer;

public class PlatformAndSecChannelProtoInfo {

    private String platform ;
    private byte protocol;
    private TPSBuffer oidCardRecognitionData;
    private TPSBuffer oidCardManagementTypeAndVer;
    private TPSBuffer oidCardIdentificationScheme;
    private TPSBuffer keysetInfoData;

    private byte implementation;
    public PlatformAndSecChannelProtoInfo(String platform, byte protocol, byte implementation) {
        // TODO Auto-generated constructor stub
        this.platform = platform;
        this.protocol = protocol;
        this.implementation = implementation;
    }
    public PlatformAndSecChannelProtoInfo() {
        setPlatform(SecureChannel.GP201);
        setProtocol(SecureChannel.SECURE_PROTO_01);
        setImplementation((byte)0);
    }
    public String getPlatform() {
        return platform;
    }
    public void setPlatform(String platform) {
        this.platform = platform;
    }
    public byte getProtocol() {
        return protocol;
    }

    public boolean isGP201() {
        if(SecureChannel.GP201.equals(platform)) {
            return true;
        }

        return false;
    }

    public boolean isGP211() {
        if(SecureChannel.GP211.equals(platform)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isSCP01() {
        if(protocol == SecureChannel.SECURE_PROTO_01) {
            return true;
        }
        return false;
    }

    public boolean isSCP02() {
        if(protocol == SecureChannel.SECURE_PROTO_02) {
            return true;
        }
        return false;
    }

    public boolean isSCP03() {
        if(protocol == SecureChannel.SECURE_PROTO_03) {
            return true;
        }
        return false;
    }

    public void setProtocol(byte protocol) {
        this.protocol = protocol;
    }
    public void setOidCardRecognitionData(TPSBuffer oidCardRecognitionData) {
        // TODO Auto-generated method stub
        this.oidCardRecognitionData = oidCardRecognitionData;

    }

    public TPSBuffer getOidCardRecognitionData() {
        return oidCardRecognitionData;
    }
    public void setOidCardManagementTypeAndVer(TPSBuffer oidCardManagementTypeAndVer) {
        // TODO Auto-generated method stub
        this.oidCardManagementTypeAndVer = oidCardManagementTypeAndVer;
    }

    public TPSBuffer getOidCardManagementTypeAndVer() {
        return oidCardManagementTypeAndVer;
    }
    public void setOidCardIdentificationScheme(TPSBuffer oidCardIdentificationScheme) {
        this.oidCardIdentificationScheme = oidCardIdentificationScheme;

    }

    public TPSBuffer getOidCardIdentificationScheme() {
        return oidCardIdentificationScheme;
    }

    public void setImplementation(byte implementation) {
        this.implementation = implementation;
    }

    public byte getImplementation() {
        return implementation;
    }
    public TPSBuffer getKeysetInfoData() {
        return keysetInfoData;
    }
    public void setKeysetInfoData(TPSBuffer keysetInfoData) {
        this.keysetInfoData = keysetInfoData;
    }

}
