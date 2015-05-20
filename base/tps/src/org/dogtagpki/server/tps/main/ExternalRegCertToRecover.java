package org.dogtagpki.server.tps.main;

import java.math.BigInteger;

public class ExternalRegCertToRecover {

    BigInteger keyid;
    BigInteger serial;
    String caConn;
    String kraConn;
    boolean isRetainable;
    CertStatus certStatus = CertStatus.UNINITIALIZED;

    public ExternalRegCertToRecover() {
        isRetainable = false;
    }

    public void setKeyid(BigInteger keyid) {
        this.keyid = keyid;
    }

    public BigInteger getKeyid() {
        return keyid;
    }

    public void setSerial(BigInteger serial) {
        this.serial = serial;
    }

    public BigInteger getSerial() {
        return serial;
    }

    public void setCaConn(String conn) {
        caConn = conn;
    }

    public String getCaConn() {
        return caConn;
    }

    public void setKraConn(String conn) {
        kraConn = conn;
    }

    public String getKraConn() {
        return kraConn;
    }

    public void setIsRetainable(boolean retainable) {
        isRetainable = retainable;
    }

    public boolean getIsRetainable() {
        return isRetainable;
    }

    public void setCertStatus(CertStatus status) {
        this.certStatus = status;
    }

    public CertStatus getCertStatus() {
        return certStatus;
    }

    public enum CertStatus {
        UNINITIALIZED("uninitialized"),
        ACTIVE("active"),
        REVOKED("revoked"),
        EXPIRED("expired")
        ;

        private final String certStatusString;
        private CertStatus(final String status) {
            this.certStatusString = status;
        }

        @Override
        public String toString() {
            return certStatusString;
        }
    }
}


