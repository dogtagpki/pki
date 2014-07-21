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

import java.util.ArrayList;

import netscape.security.x509.X509CertImpl;

import org.dogtagpki.server.tps.main.PKCS11Obj;
import org.dogtagpki.tps.main.TPSBuffer;

public class EnrolledCertsInfo {

    EnrolledCertsInfo() {
        certificates = new ArrayList<X509CertImpl>();
        ktypes = new ArrayList<String>();
        origins = new ArrayList<String>();
        tokenTypes = new ArrayList<String>();
    }

    EnrolledCertsInfo(PKCS11Obj obj, TPSBuffer wrappedChallenge, TPSBuffer plainChallenge, int keyTypeNum,
            int startProgress, int endProgress) {
        this();
        this.wrappedChallenge = wrappedChallenge;
        plaintextChallenge = plainChallenge;
        pkcs11objx = obj;
        numCertsToEnroll = keyTypeNum;
        this.startProgress = startProgress;
        this.endProgress = endProgress;
    }

    //Tables that will get set during processing
    private ArrayList<String> origins;
    private ArrayList<String> ktypes;
    private ArrayList<String> tokenTypes;
    private ArrayList<X509CertImpl> certificates;

    //Input challenge data
    private TPSBuffer wrappedChallenge;
    private TPSBuffer plaintextChallenge;
    private TPSBuffer keyCheck;

    private int numCertsToEnroll;
    private int currentCertIndex;

    private int startProgress;
    private int endProgress;

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

    public void addCertificate(X509CertImpl x509Cert) {
        certificates.add(x509Cert);
    }

    public void setStartProgress(int startP) {
        startProgress = startP;

    }

    public void setEndProgress(int endP) {
        endProgress = endP;

    }

}
