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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;

import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenCertStatus;
import org.dogtagpki.server.tps.main.PKCS11Obj;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;

public class EnrolledCertsInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(EnrolledCertsInfo.class);

    EnrolledCertsInfo() {
        certificates = new ArrayList<X509CertImpl>();
        certStatuses = new ArrayList<TokenCertStatus>();
        ktypes = new ArrayList<String>();
        origins = new ArrayList<String>();
        tokenTypes = new ArrayList<String>();
        externalRegRecoveryEnrollList = new ArrayList<CertEnrollInfo>();
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
    private ArrayList<TokenCertStatus> certStatuses;

    private ArrayList<CertEnrollInfo> externalRegRecoveryEnrollList;

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

    public ArrayList<CertEnrollInfo> getExternalRegRecoveryEnrollList() {
        return externalRegRecoveryEnrollList;
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

        logger.debug("EnrolledCertsInfo.addOrigin: " + origin);
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

    public void removeCertificate(X509CertImpl x509Cert) {
        certificates.remove(x509Cert);
    }

    public void addCertStatus(TokenCertStatus status) {
        certStatuses.add(status);
    }

    public void setCertStatus(int index, TokenCertStatus status) {
        certStatuses.set(index, status);
    }

    public void setStartProgress(int startP) {
        startProgress = startP;

    }

    public void setEndProgress(int endP) {
        endProgress = endP;

    }

    public ArrayList<TPSCertRecord> toTPSCertRecords(String cuid, String uid) {
        ArrayList<TPSCertRecord> certs = new ArrayList<TPSCertRecord>();
        logger.debug("EnrolledCertsInfo.toTPSCertRecords: starts");
        int index = 0;
        for (X509CertImpl cert: certificates) {
            TPSCertRecord certRecord = new TPSCertRecord();

            //serial number
            BigInteger serial_BigInt = cert.getSerialNumber();

            String hexSerial = serial_BigInt.toString(16);
            String serialNumber = "0x" + hexSerial;
            certRecord.setSerialNumber(serialNumber);

            String uniqueString = Util.getTimeStampString(false);
            String id = hexSerial + "." + uniqueString;

            certRecord.setId(id);
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: converting cert:"+ certRecord.getId());

            //token id
            certRecord.setTokenID(cuid);
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: cuid =" + cuid);

            //origin
            if ((!origins.isEmpty()) && index <origins.size() && origins.get(index)!= null) {
                certRecord.setOrigin(origins.get(index));
                logger.debug("EnrolledCertsInfo.toTPSCertRecords: origin =" + origins.get(index));
            } else {
                logger.warn("EnrolledCertsInfo.toTPSCertRecords: origin not found for index:"+ index);
            }

            //user id
            certRecord.setUserID(uid);
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: uid =" + uid);

            //KeyType
            if ((!ktypes.isEmpty()) && index <ktypes.size() && ktypes.get(index)!= null) {
                certRecord.setKeyType(ktypes.get(index));
                logger.debug("EnrolledCertsInfo.toTPSCertRecords: keyType =" + ktypes.get(index));
            } else {
                logger.warn("EnrolledCertsInfo.toTPSCertRecords: keyType not found for index:"+ index);
            }

            //token type
            if ((!tokenTypes.isEmpty()) && index <tokenTypes.size() && tokenTypes.get(index)!= null) {
                logger.debug("EnrolledCertsInfo.toTPSCertRecords: tokenType=" + tokenTypes.get(index));
                certRecord.setType(tokenTypes.get(index));
                logger.debug("EnrolledCertsInfo.toTPSCertRecords: tokenType set");
            } else {
                logger.warn("EnrolledCertsInfo.toTPSCertRecords: tokenType not found for index:"+ index);
                //certRecord.setType("");
            }

            //cert status
            if ((!certStatuses.isEmpty()) && index < certStatuses.size() && certStatuses.get(index) != null) {
                logger.debug("EnrolledCertsInfo.toTPSCertRecords: cert status=" + certStatuses.get(index));
                certRecord.setStatus(certStatuses.get(index).toString());
            } else {
                logger.warn("EnrolledCertsInfo.toTPSCertRecords: certStatus not found for index:" + index
                        + "; set to default active");
                certRecord.setStatus(TokenCertStatus.ACTIVE.toString());
            }

            //Issuer
            String issuedBy = cert.getIssuerDN().toString();
            certRecord.setIssuedBy(issuedBy);
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: issuer ="+ issuedBy);

            //Subject
            String subject = cert.getSubjectDN().toString();
            certRecord.setSubject(subject);
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: subject ="+ subject);

            //NotBefore
            certRecord.setValidNotBefore(cert.getNotBefore());
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: notBefore ="+ cert.getNotBefore().toString());

            //NotAfter
            certRecord.setValidNotAfter(cert.getNotAfter());
            logger.debug("EnrolledCertsInfo.toTPSCertRecords: notAfter ="+ cert.getNotAfter().toString());

            /* certificate
            byte[] certBytes = null;
            try {
                certBytes = cert.getEncoded();
                //logger.debug("EnrolledCertsInfo.toTPSCertRecords: certBytes ="+ CMS.BtoA(certBytes));
                logger.debug("EnrolledCertsInfo.toTPSCertRecords: cert encoded");
            } catch (CertificateEncodingException e) {
                logger.warn("EnrolledCertsInfo.toTPSCertRecord: "+ e.getMessage(), e);
                //TODO: throw

            }
            certRecord.setCertificate(CMS.BtoA(certBytes));
            */
            // Alternative to the actual certificate -- certificate AKI
            try {
                String aki = Util.getCertAkiString(cert);
                certRecord.setCertificate(aki);
            } catch (EBaseException | IOException e) {
                logger.warn("EnrolledCertsInfo: " + e.getMessage(), e);
            }

            certs.add(certRecord);

            index++;
        }
        logger.debug("EnrolledCertsInfo.toTPSCertRecords: ends");
        return certs;
    }

}
