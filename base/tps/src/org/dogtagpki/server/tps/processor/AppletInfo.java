package org.dogtagpki.server.tps.processor;

import org.dogtagpki.tps.main.TPSBuffer;


public class AppletInfo {

    private byte majorVersion;
    private byte minorVersion;
    private byte appMajorVersion;
    private byte appMinorVersion;

    private TPSBuffer aid;
    private TPSBuffer cuid;
    private TPSBuffer msn;
    private int totalMem;
    private int freeMem;

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

    public String getCUIDhexString(){
        if(cuid != null) {
            return cuid.toHexString();
        }

        return null;
    }

    /*
     * getCUIDhexString2 returns hex string without the '%'
     */
    public String getCUIDhexStringPlain() {
        if(cuid != null) {
            return cuid.toHexStringPlain();
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

    public void setTotalMem(int total_mem) {
        totalMem = total_mem;

    }

    public int getTotalMem() {
        return totalMem;
    }

    public void setFreeMem(int free_mem) {
        freeMem = free_mem;
    }

    public int getFreeMem() {
        return freeMem;
    }

    public TPSBuffer getAid() {
        return aid;
    }

    public void setAid(TPSBuffer aid) {
        this.aid = aid;
    }

}
