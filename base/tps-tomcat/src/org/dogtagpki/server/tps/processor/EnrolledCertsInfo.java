package org.dogtagpki.server.tps.processor;

import java.util.ArrayList;

import org.dogtagpki.server.tps.main.PKCS11Obj;
import org.dogtagpki.tps.main.TPSBuffer;
import org.mozilla.jss.pkix.cert.Certificate;

public class EnrolledCertsInfo {

    EnrolledCertsInfo() {
    }

    EnrolledCertsInfo(PKCS11Obj obj, TPSBuffer wrappedChallenge, TPSBuffer plainChallenge, int keyTypeNum) {
        this.wrappedChallenge = wrappedChallenge;
        plaintextChallenge = plainChallenge;
        pkcs11objx = obj;
        numCertsToEnroll = keyTypeNum;
    }

    //Tables that will get set during processing
    private ArrayList<String> origins;
    private ArrayList<String> ktypes;
    private ArrayList<String> tokenTypes;
    private ArrayList<Certificate> certificates;

    //Input challenge data
    private TPSBuffer wrappedChallenge;
    private TPSBuffer plaintextChallenge;
    private TPSBuffer keyCheck;

    private int numCertsToEnroll;
    private int currentCertIndex;

    static final private int startProgress = 15;
    static final private int endProgress = 90;

    public int getCurrentCertIndex() {
        return currentCertIndex;
    }

    public void setCurrentCertIndex(int index) {
        currentCertIndex = index;
    }

    public void setNumCertsToEnroll(int num) {
        numCertsToEnroll = num;
    }

    public int getNumCertsToEnroll() {
        return numCertsToEnroll;
    }

    int getStartProgressValue() {
        return startProgress;
    }

    int getEndProgressValue() {
        return endProgress;
    }

    public void setKeyCheck(TPSBuffer keyCheck) {
        this.keyCheck = keyCheck;
    }

    public TPSBuffer getKeyCheck() {
        return keyCheck;
    }

    //PKCS11Object that will have values added to it during processing
    private PKCS11Obj pkcs11objx;

    public void setWrappedChallenge(TPSBuffer wrappedChallenge) {
        this.wrappedChallenge = wrappedChallenge;
    }

    public TPSBuffer getWrappedChallenge() {
        return wrappedChallenge;
    }

    public void setPlaintextChallenge(TPSBuffer plaintextChallenge) {
        this.plaintextChallenge = plaintextChallenge;
    }

    public TPSBuffer getPlaintextChallenge() {
        return plaintextChallenge;
    }

    public void setPKCS11Obj(PKCS11Obj pkcs11obj) {
        pkcs11objx = pkcs11obj;
    }

    public PKCS11Obj getPKCS11Obj() {
        return pkcs11objx;
    }

    public void addOrigin(String origin) {
        origins.add(origin);
    }

    public void addKType(String ktype) {
        ktypes.add(ktype);
    }

    public void addTokenType(String tokenType) {
        tokenTypes.add(tokenType);
    }

    public void addCertificate(Certificate cert) {
        certificates.add(cert);
    }

}
