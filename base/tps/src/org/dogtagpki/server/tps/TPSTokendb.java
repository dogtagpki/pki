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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.dogtagpki.server.tps.cms.CARemoteRequestHandler;
import org.dogtagpki.server.tps.cms.CARevokeCertResponse;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.main.ExternalRegAttrs;
import org.dogtagpki.server.tps.main.ExternalRegCertToRecover;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.tps.token.TokenStatus;

import netscape.security.x509.RevocationReason;

/*
 * TPSTokendb class offers a collection of tokendb management convenience routines
 */
public class TPSTokendb {

    private TPSSubsystem tps;

    public TPSTokendb(TPSSubsystem tps) throws EBaseException {
        if (tps == null) {
            String msg = "TPStokendb.TPSTokendb: tps cannot be null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        this.tps = tps;
    }

    public boolean isTransitionAllowed(TokenRecord tokenRecord, TokenStatus newState) throws Exception {
        boolean result = false;
        TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();

        CMS.debug("TokenRecord.isTransitionAllowed(): current status: " + currentTokenStatus);
        Collection<TokenStatus> nextStatuses = tps.getNextTokenStates(tokenRecord);

        CMS.debug("TokenRecord.isTransitionAllowed(): allowed next statuses: " + nextStatuses);
        if (!nextStatuses.contains(newState)) {
            CMS.debug("TokenRecord.isTransitionAllowed(): next status not allowed: " + newState);

            result = false;
        } else {
            //status change allowed
            result = true;
        }
        return result;
    }

    /*
     * tdbActivity logs token activities; This version is called by non-administrative functions
     */
    public void tdbActivity(
            String op, TokenRecord tokenRecord, String ip, String msg, String result) {
        try {
            tps.activityDatabase.log(
                    ip,
                    (tokenRecord != null)? tokenRecord.getId():null,
                    op,
                    result,
                    msg,
                    (tokenRecord != null)? tokenRecord.getUserID():null,
                    (tokenRecord != null)? tokenRecord.getType():null);
        } catch (Exception e) {
            msg = msg + ";" + " tokendb activity logging failure: " + e;
        }
    }

    /*
     * tdbActivity logs token activities; This version is called by administrative functions
     */
    public void tdbActivity(
            String op, TokenRecord tokenRecord, String ip, String msg, String result, String uid) {
        try {
            tps.activityDatabase.log(
                    ip,
                    (tokenRecord != null)? tokenRecord.getId():null,
                    op,
                    result,
                    msg,
                    uid,
                    (tokenRecord != null)? tokenRecord.getType():null);
        } catch (Exception e) {
            msg = msg + ";" + " tokendb activity logging failure: " + e;
        }
    }

    public boolean isTokenPresent(String cuid) {
        boolean present = false;
        try {
            tps.tokenDatabase.getRecord(cuid);
            present = true;
        } catch (Exception e) {
            CMS.debug("TPSTokendb.isTokenPresent: token entry not found");
            present = false;
        }
        return present;
    }

    public TokenRecord tdbGetTokenEntry(String cuid)
            throws Exception {
        return tps.tokenDatabase.getRecord(cuid);
    }

    /*
     * tdbFindTokenRecordsByUID finds and returns token records belong to one user
     * @param uid the uid of the owner to the token
     * @return ArrayList of the token records
     */
    public ArrayList<TokenRecord> tdbFindTokenRecordsByUID(String uid)
            throws Exception {
        ArrayList<TokenRecord> tokenRecords = new ArrayList<TokenRecord>();
        String filter = uid;
        Iterator<TokenRecord> records = null;
        records = tps.tokenDatabase.findRecords(filter).iterator();

       while (records.hasNext()) {
           TokenRecord tokenRecord = records.next();
           tokenRecords.add(tokenRecord);
       }

       return tokenRecords;
    }

    public void tdbHasActiveToken(String userid)
           throws Exception {
        if (userid == null)
            throw new Exception("TPSTokendb.tdbhasActiveToken: uerid null");

        ArrayList<TokenRecord> tokens =
                tdbFindTokenRecordsByUID(userid);
        boolean foundActive = false;
        for (TokenRecord tokenRecord:tokens) {
            if (tokenRecord.getTokenStatus().equals(TokenStatus.ACTIVE)) {
                foundActive = true;
            }
        }
        if (!foundActive) {
            throw new Exception("TPSTokendb.tdbhasActiveToken: active token not found");
        }
    }

    public void tdbAddTokenEntry(TokenRecord tokenRecord, TokenStatus status)
            throws Exception {
        tokenRecord.setTokenStatus(status);

        tps.tokenDatabase.addRecord(tokenRecord.getId(), tokenRecord);
    }

    public void tdbUpdateTokenEntry(TokenRecord tokenRecord)
            throws Exception {
        String id = tokenRecord.getId();
        TokenRecord existingTokenRecord;
        try {
            existingTokenRecord = tps.tokenDatabase.getRecord(id);
        } catch (EDBRecordNotFoundException e) {
            CMS.debug("TPSTokendb.tdbUpdateTokenEntry: " + e);
            CMS.debug("TPSTokendb.tdbUpdateTokenEntry: Adding token " + id);
            // add and exit
            tdbAddTokenEntry(tokenRecord, TokenStatus.FORMATTED);
            return;
        }
        // token found; modify
        CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry found; Modifying with status: " + tokenRecord.getTokenStatus());
        // don't change the create time of an existing token record; put it back
        tokenRecord.setCreateTimestamp(existingTokenRecord.getCreateTimestamp());
        tps.tokenDatabase.updateRecord(id, tokenRecord);
    }

    /*
     * tdbAddCertificatesForCUID adds certificates issued for the token CUID
     * - this instance pre-process the cert records to update the cert statuses
     * @param cuid the cuid of the token
     * @param certs an ArrayList of TPSCertRecord
     * @param erAttrs the ExternalRegAttrs collection
     */
    public void tdbAddCertificatesForCUID(String cuid, ArrayList<TPSCertRecord> certs, ExternalRegAttrs erAttrs)
            throws TPSException {
        String method = "TPSTokendb.tdbAddCertificatesForCUID (with erAttrs): ";
        String logMsg = "";
        CMS.debug(method + "begins");
        if (cuid == null || certs== null || certs.isEmpty() || erAttrs == null) {
            logMsg =  "params cuid, certs and erAttrs cannot be null or empty";
            CMS.debug(method + logMsg);
            throw new TPSException(method + logMsg, TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }
        CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: number of certs to update:"+ certs.size());

        // update cert status first
        for (TPSCertRecord cert : certs) {
            ExternalRegCertToRecover.CertStatus status = ExternalRegCertToRecover.CertStatus.UNINITIALIZED;
            status = erAttrs.getCertStatus(cert.getSerialNumber());
            if (status == ExternalRegCertToRecover.CertStatus.UNINITIALIZED) {
                //cert not found in ExternalReg; don't reset status; don't report
                continue;
            }

            //cert is one of the ExternalReg recovered certs, update the status
            CMS.debug(method + "found and set status for:" + cert.getSerialNumber());
            cert.setStatus(status.toString());

        }

        tdbAddCertificatesForCUID(cuid, certs);
        CMS.debug(method + "ends");


    }

    public void tdbAddCertificatesForCUID(String cuid, ArrayList<TPSCertRecord> certs)
            throws TPSException {
        String method = "TPSTokendb.tdbAddCertificatesForCUID: ";
        CMS.debug(method + "begins");
        boolean tokenExist = isTokenPresent(cuid);
        if (!tokenExist){
            CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: token not found: "+ cuid);
            throw new TPSException("TPSTokendb:tdbUpdateCertificates: token "+ cuid + " does not exist");
        }

        CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: found token "+ cuid);
        CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: number of certs to update:"+ certs.size());
        try {
            for (TPSCertRecord cert: certs) {
               // cert.setOrigin(cuid);

                try {
                tps.certDatabase.addRecord(cert.getId(), cert);
                } catch (Exception e) {

                    //If this is due to a dup, try to update the record.
                    tps.certDatabase.updateRecord(cert.getId(), cert);
                }
            }
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbAddCertificatesForCUID: "+ e);
            // TODO: what if it throws in the middle of the cert list -- some cert records already updated?
            throw new TPSException(e.getMessage());
        }
    }

    /*
     * tdbGetCertificatesByCUID finds and returns certificate records belong to a token cuid
     * @param cuid the cuid of the token
     * @return Collection of the cert records
     */
    public Collection<TPSCertRecord> tdbGetCertRecordsByCUID(String cuid)
            throws TPSException {

        if (cuid == null)
            throw new TPSException("TPSTokendb.tdbGetCertificatesByCUID: cuid null");

        Map<String, String> attributes = new HashMap<String, String>();
        attributes.put("tokenID",  cuid);

        try {
             return tps.certDatabase.findRecords(null, attributes);
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbGetCertificatesByCUID:" + e);
            throw new TPSException(e);
        }
    }

    public ArrayList<TPSCertRecord> tdbGetCertRecordsByCert(String serial, String issuer)
            throws TPSException {
        if (serial == null)
            throw new TPSException("TPSTokendb.tdbGetCertificatesBySerial: serial null");

        if (issuer == null) {
            throw new TPSException("TPSTokendb.tdbGetCertificatesBySerial: issuer null");
        }

        Map<String, String> attributes = new HashMap<String, String>();
        attributes.put("serialNumber", serial);
        attributes.put("issuedBy", issuer);

        ArrayList<TPSCertRecord> certRecords = new ArrayList<TPSCertRecord>();
        Iterator<TPSCertRecord> records;
        try {
            records = tps.certDatabase.findRecords(null, attributes).iterator();
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbGetCertificatesByCUID:" + e);
            throw new TPSException(e.getMessage());
        }

        while (records.hasNext()) {
            TPSCertRecord certRecord = records.next();
            certRecords.add(certRecord);
        }

        return certRecords;
    }

    public void tdbRemoveCertificatesByCUID(String cuid)
        throws Exception {
        String method = "TPSTokendb.tdbRemoveCertificatesByCUID";
        if (cuid == null)
            throw new Exception(method + ": cuid null");

        CMS.debug(method + ":" + " begins for cuid=" + cuid);
        String filter = cuid;
        Iterator<TPSCertRecord> records;
        try {
             records = tps.certDatabase.findRecords(filter).iterator();
        } catch (Exception e) {
            CMS.debug(method + ":" + e);
            throw new Exception(method + ":" + e);
        }

        while (records.hasNext()) {
            TPSCertRecord certRecord = records.next();
            // make sure the cuid matches the tokenID instead of the origin !
            if (certRecord.getTokenID().equalsIgnoreCase(cuid)) {
                tps.certDatabase.removeRecord(certRecord.getId());
                CMS.debug(method + ":" + "cert removed:" + certRecord.getId());
            } else {
                CMS.debug(method + ":" + " next record not matched:" + certRecord.getTokenID());
            }
        }
        CMS.debug(method + ":" + " done");
    }

    public void revokeCertsByCUID(String cuid, String tokenReason, String ipAddress, String remoteUser)
            throws Exception {
        String method = "TPStokendb.revokeCertsByCUID";
        CMS.debug(method + ": called");
        if (cuid == null)
            throw new TPSException(method + ": cuid null");
        revokeCertsByCUID(true, cuid, tokenReason, ipAddress, remoteUser);
    }

    public void unRevokeCertsByCUID(String cuid, String ipAddress, String remoteUser) throws Exception {
        String method = "TPStokendb.unRevokeCertsByCUID";
        CMS.debug(method + ": called");
        if (cuid == null)
            throw new TPSException(method + ": cuid null");
        revokeCertsByCUID(false, cuid, null /* null for unrevoke*/, ipAddress, remoteUser);
    }

    private boolean isLastActiveSharedCert(String serial, String issuer, String cuid) throws TPSException {
        ArrayList<TPSCertRecord> certRecords = tps.getTokendb().tdbGetCertRecordsByCert(serial, issuer);
        for (TPSCertRecord cert : certRecords) {
            // exclude current token
            if (cert.getTokenID().equals(cuid))
                continue;

            if (cert.getStatus().equals("active"))
                return false;
        }

        return true;
    }

    private void revokeCert(TokenRecord tokenRecord, TPSCertRecord cert, String tokenReason,
            String ipAddress, String remoteUser) {

        String method = "TPSTokendb.revokeCert";
        String logMsg;

        try {

            IConfigStore configStore = CMS.getConfigStore();

            // get conn ID
            String config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() + ".ca.conn";
            CMS.debug(method + ": " + " getting config: " + config);
            String connID = configStore.getString(config);

            RevocationReason revokeReason = RevocationReason.UNSPECIFIED;

            logMsg = "called to revoke";
            CMS.debug(method + ": " + logMsg);

            checkShouldRevoke(tokenRecord, cert, tokenReason, ipAddress, remoteUser);

            logMsg = "certificate to be revoked:" + cert.getSerialNumber();
            CMS.debug(method + ": " + logMsg);

            // get revoke reason
            config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() +
                    ".recovery." + tokenReason + ".revokeCert.reason";
            CMS.debug(method + ": " + " getting config: " + config);
            int reasonInt = configStore.getInteger(config, 0);
            revokeReason = RevocationReason.fromInt(reasonInt);

            CARemoteRequestHandler caRH = new CARemoteRequestHandler(connID);
            BigInteger bInt = cert.getSerialNumberInBigInteger();
            String serialStr = bInt.toString();
            CMS.debug(method + ": found cert hex serial: " + cert.getSerialNumber() +
                    " dec serial: " + serialStr);
            CARevokeCertResponse response =
                    caRH.revokeCertificate(true, serialStr, cert.getCertificate(),
                            revokeReason);
            CMS.debug(method + ": response status: " + response.getStatus());

            // update certificate status
            if (revokeReason == RevocationReason.CERTIFICATE_HOLD) {
                updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(), "revoked_on_hold");
            } else {
                updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(), "revoked");
            }

            logMsg = "certificate revoked: " + cert.getSerialNumber();
            CMS.debug(method + ": " + logMsg);

            tdbActivity(ActivityDatabase.OP_CERT_REVOCATION, tokenRecord,
                    ipAddress, logMsg, "success", remoteUser);

        } catch (Exception e) {
            logMsg = "certificate not revoked: " + cert.getSerialNumber() + ": " + e;
            CMS.debug(method + ": " + logMsg);

            tdbActivity(ActivityDatabase.OP_CERT_REVOCATION, tokenRecord,
                    ipAddress, e.getMessage(), "failure", remoteUser);

            // continue revoking the next certificate
        }
    }

    private void unrevokeCert(TokenRecord tokenRecord, TPSCertRecord cert, String tokenReason,
            String ipAddress, String remoteUser) {

        String method = "TPSTokendb.unrevokeCert";
        String logMsg;

        try {
            IConfigStore configStore = CMS.getConfigStore();

            // get conn ID
            String config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() + ".ca.conn";
            String connID = configStore.getString(config);

            RevocationReason revokeReason = RevocationReason.UNSPECIFIED;

            logMsg = "called to unrevoke";
            CMS.debug(method + ": " + logMsg);

            if (!cert.getStatus().equalsIgnoreCase("revoked_on_hold")) {
                logMsg = "certificate record current status is not revoked_on_hold; cannot unrevoke";
                CMS.debug(method + ": " + logMsg);
                return; // TODO: continue or bail?
            }

            CARemoteRequestHandler caRH = new CARemoteRequestHandler(connID);
            BigInteger bInt = cert.getSerialNumberInBigInteger();
            String serialStr = bInt.toString();
            CMS.debug(method + ": found cert hex serial: " + cert.getSerialNumber() +
                    " dec serial: " + serialStr);
            CARevokeCertResponse response =
                    caRH.revokeCertificate(false, serialStr, cert.getCertificate(),
                            revokeReason);
            CMS.debug(method + ": response status: " + response.getStatus());

            // update certificate status
            updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(), "active");

            logMsg = "certificate unrevoked: " + cert.getSerialNumber();
            CMS.debug(method + ": " + logMsg);

            tdbActivity(ActivityDatabase.OP_CERT_UNREVOCATION, tokenRecord,
                    ipAddress, logMsg, "success", remoteUser);

        } catch (Exception e) {
            logMsg = "certificate not unrevoked: " + cert.getSerialNumber() + " : " + e;
            CMS.debug(method + ": " + logMsg);

            tdbActivity(ActivityDatabase.OP_CERT_UNREVOCATION, tokenRecord,
                    ipAddress, e.getMessage(), "failure", remoteUser);

            // continue unrevoking the next certificate
        }
    }

    private void checkShouldRevoke(TokenRecord tokenRecord, TPSCertRecord cert, String tokenReason,
            String ipAddress, String remoteUser) throws Exception {

        IConfigStore configStore = CMS.getConfigStore();

        if (cert == null) {
            throw new TPSException("Missing token certificate");
        }

        String tokenType = cert.getType();
        String keyType = cert.getKeyType();

        // check if certificate revocation is enabled
        String config = "op.enroll." + tokenType + ".keyGen." + keyType +
                ".recovery." + tokenReason + ".revokeCert";
        boolean revokeCerts = configStore.getBoolean(config, true);
        if (!revokeCerts) {
            throw new TPSException(
                    "certificate revocation (serial " + cert.getSerialNumber() +
                    ") not enabled for tokenType: " + tokenType +
                    ", keyType: " + keyType +
                    ", state: " + tokenReason);
        }

        // check if expired certificates should be revoked.
        config = "op.enroll." + tokenType + ".keyGen." + keyType + ".recovery." +
                tokenReason + ".revokeExpiredCerts";
        boolean revokeExpiredCerts = configStore.getBoolean(config, true);
        if (!revokeExpiredCerts) {
            Date notBefore = cert.getValidNotBefore();
            Date notAfter = cert.getValidNotAfter();
            Date now = new Date();
            if (now.after(notAfter)) {
                throw new TPSException(
                        "revocation not enabled for expired cert: " + cert.getSerialNumber());
            }
            if (now.before(notBefore)) {
                throw new TPSException(
                        "revocation not enabled for cert that is not yet valid: " + cert.getSerialNumber());
            }
        }

        // check if certs on multiple tokens should be revoked
        config = "op.enroll." + tokenType + ".keyGen." + keyType + ".recovery." +
                tokenReason + ".holdRevocationUntilLastCredential";
        boolean holdRevocation = configStore.getBoolean(config, false);
        if (holdRevocation) {
            if (!isLastActiveSharedCert(cert.getSerialNumber(), cert.getIssuedBy(), tokenRecord.getId())) {
                throw new TPSException(
                        "revocation not permitted as certificate " + cert.getSerialNumber() +
                        " is shared by another active token");
            }
        }
    }

    /*
     * revokeCertsByCUID
     * @param isRevoke true if to revoke; false to unrevoke
     * @param cuid cuid of token to revoke/unrevoke
     * @param onHold true if revocation is to put onHold; false if to really revoke
     */
    private void revokeCertsByCUID(boolean isRevoke, String cuid, String tokenReason,
            String ipAddress, String remoteUser) throws Exception {
        String method = "TPSTokendb.revokeCertsByCUID";
        String logMsg;

        if (cuid == null) {
            logMsg = "Missing token CUID";
            CMS.debug(method + ": " + logMsg);
            throw new TPSException(logMsg);
        }

        TokenRecord tokenRecord = tdbGetTokenEntry(cuid);

        Collection<TPSCertRecord> certRecords = tps.getTokendb().tdbGetCertRecordsByCUID(cuid);
        if (tokenReason != null) {
            if (!tokenReason.equalsIgnoreCase("onHold") &&
                    !tokenReason.equalsIgnoreCase("destroyed") &&
                    !tokenReason.equalsIgnoreCase("keyCompromise") &&
                    !tokenReason.equalsIgnoreCase("terminated")) {
                logMsg = "unknown tokenRecord lost reason:" + tokenReason;
                CMS.debug(method + ":" + logMsg);
                throw new Exception(method + ":" + logMsg);
            }
        }

        IConfigStore configStore = CMS.getConfigStore();

        for (TPSCertRecord cert : certRecords) {
            if (isRevoke) {
                revokeCert(tokenRecord, cert, tokenReason, ipAddress, remoteUser);
            } else {
                unrevokeCert(tokenRecord, cert, tokenReason, ipAddress, remoteUser);
            }
        }
    }

    public void updateCertsStatus(String serial, String issuer, String status) throws Exception {
        ArrayList<TPSCertRecord> certRecords = tps.getTokendb().tdbGetCertRecordsByCert(serial, issuer);

        for (TPSCertRecord certRecord : certRecords) {
            certRecord.setStatus(status);
            tps.certDatabase.updateRecord(certRecord.getId(), certRecord);
        }
    }

    public void tdbAddCertEntry(TPSCertRecord certRecord, String status)
            throws Exception {
        certRecord.setStatus(status);

        tps.certDatabase.addRecord(certRecord.getId(), certRecord);
    }

    public void tdbUpdateCertEntry(TPSCertRecord certRecord)
            throws Exception {
        String method = "TPSTokendb.tdbUpdateCertEntry";
        String id = certRecord.getId();
        TPSCertRecord existingCertRecord;
        try {
            existingCertRecord = tps.certDatabase.getRecord(id);
        } catch (Exception e) {
            CMS.debug(method + ": token entry not found; Adding");
            // add and exit
            tdbAddCertEntry(certRecord, certRecord.getStatus());
            return;
        }
        // cert found; modify
        CMS.debug(method + ": cert entry found; Modifying with status: "+ certRecord.getStatus());
        // don't change the create time of an existing token record; put it back
        certRecord.setCreateTime(existingCertRecord.getCreateTime());
        tps.certDatabase.updateRecord(id, certRecord);
    }
}
