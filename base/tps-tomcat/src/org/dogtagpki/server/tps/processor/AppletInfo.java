package org.dogtagpki.server.tps.processor;

import org.dogtagpki.tps.main.TPSBuffer;


public class AppletInfo {

    private byte majorVersion;
    private byte minorVersion;
    private byte appMajorVersion;
    private byte appMinorVersion;


    private TPSBuffer cuid;
    private TPSBuffer msn;

    public AppletInfo(byte appletMajorVer,byte appletMinorVer,byte appMajorVer,byte appMinorVer) {

        majorVersion = appletMajorVer;
        minorVersion = appletMinorVer;
        appMajorVersion = appMajorVer;
        appMinorVersion = appMinorVer;

    }

    public void setCUID(TPSBuffer theCuid) {
        cuid = new TPSBuffer(theCuid);
    }

    public TPSBuffer getCUID() {
        return cuid;
    }

    public void setMSN(TPSBuffer theMsn) {
        msn = new TPSBuffer(theMsn);
    }

    public TPSBuffer getMSN() {
        return msn;
    }

    public String getCUIDString() {
        if(cuid != null) {
            return cuid.toHexString();
        }

        return null;
    }

    public String getMSNString() {
        if(msn != null) {
            return msn.toHexString();
        }
        return null;
    }

    public byte getMajorVersion() {
        return majorVersion;
    }

    public byte getMinorVersion() {
        return minorVersion;
    }

    public byte getAppMinorVersion() {
        return appMinorVersion;
    }

    public byte getAppMajorVersion() {
        return appMajorVersion;
    }

    public static void main(String[] args) {

    }

}
