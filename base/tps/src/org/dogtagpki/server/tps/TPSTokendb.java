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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import org.dogtagpki.server.tps.cms.CARemoteRequestHandler;
import org.dogtagpki.server.tps.cms.CARevokeCertResponse;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.main.ExternalRegAttrs;
import org.dogtagpki.server.tps.main.ExternalRegCertToRecover;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.tps.token.TokenStatus;

import netscape.security.x509.RevocationReason;

/*
 * TPSTokendb class offers a collection of tokendb management convenience routines
 */
public class TPSTokendb {
    private TPSSubsystem tps;
    private Map<TokenStatus, Collection<TokenStatus>> allowedTransitions = new HashMap<TokenStatus, Collection<TokenStatus>>();

    public TPSTokendb(TPSSubsystem tps) throws EBaseException {
        if (tps == null) {
            String msg = "TPStokendb.TPSTokendb: tps cannot be null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        this.tps = tps;
        try {
            initAllowedTransitions();
        } catch (Exception e) {
            CMS.debug("TPSTokendb: initAllowedTransitions() failed:" + e);
            throw new EBaseException(e.toString());
        }
    }

    void initAllowedTransitions()
            throws Exception {
        CMS.debug("TPSTokendb.initAllowedTransitions()");
        IConfigStore configStore = CMS.getConfigStore();

        // load allowed token state transitions
        CMS.debug("TPSTokendbs: allowed transitions:");

        for (String transition : configStore.getString(TPSEngine.CFG_TOKENDB_ALLOWED_TRANSITIONS).split(",")) {
            String states[] = transition.split(":");
            TokenStatus fromState = TokenStatus.fromInt(Integer.valueOf(states[0]));
            TokenStatus toState = TokenStatus.fromInt(Integer.valueOf(states[1]));
            CMS.debug("TPSTokendb:  - " + fromState + " to " + toState);

            Collection<TokenStatus> nextStates = allowedTransitions.get(fromState);
            if (nextStates == null) {
                nextStates = new HashSet<TokenStatus>();
                allowedTransitions.put(fromState, nextStates);
            }
            nextStates.add(toState);
        }
    }

    public boolean isTransitionAllowed(TokenRecord tokenRecord, TokenStatus newState) {
        boolean result = false;
        TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();
        CMS.debug("TokenRecord.isTransitionAllowed(): current status: " + currentTokenStatus);
        Collection<TokenStatus> nextStatuses = allowedTransitions.get(currentTokenStatus);
        CMS.debug("TokenRecord.isTransitionAllowed(): allowed next statuses: " + nextStatuses);
        if (nextStatuses == null || !nextStatuses.contains(newState)) {
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
            if (tokenRecord.getStatus().equals("active")) {
                foundActive = true;
            }
        }
        if (!foundActive) {
            throw new Exception("TPSTokendb.tdbhasActiveToken: active token not found");
        }
    }

    public void tdbAddTokenEntry(TokenRecord tokenRecord, String status)
            throws Exception {
        tokenRecord.setStatus(status);

        tps.tokenDatabase.addRecord(tokenRecord.getId(), tokenRecord);
    }

    public void tdbUpdateTokenEntry(TokenRecord tokenRecord)
            throws Exception {
        String id = tokenRecord.getId();
        TokenRecord existingTokenRecord;
        try {
            existingTokenRecord = tps.tokenDatabase.getRecord(id);
        } catch (Exception e) {
            CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry not found; Adding");
            // add and exit
            tdbAddTokenEntry(tokenRecord, "uninitialized");
            return;
        }
        // token found; modify
        CMS.debug("TPSTokendb.tdbUpdateTokenEntry: token entry found; Modifying with status: "+ tokenRecord.getStatus());
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
            }
        }
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

    private boolean shouldRevoke(TPSCertRecord cert, String cuid, String tokenReason,
            String ipAddress, String remoteUser) throws Exception {
        IConfigStore configStore = CMS.getConfigStore();
        String method = "TPStokendb.shouldRevoke";
        String activityMsg;

        if (cert == null) {
            throw new TPSException(method + ": cert null");
        }

        String tokenType = cert.getType();
        String keyType = cert.getKeyType();

        // check if certificate revocation is enabled
        String config = "op.enroll." + tokenType + ".keyGen." + keyType +
                ".recovery." + tokenReason + ".revokeCert";
        boolean revokeCerts = configStore.getBoolean(config, true);
        if (!revokeCerts) {
            activityMsg = "certificate revocation (serial " + cert.getSerialNumber() +
                    ") not enabled for tokenType: " + tokenType +
                    ", keyType: " + keyType +
                    ", state: " + tokenReason;

            tdbActivity(ActivityDatabase.OP_DO_TOKEN, tdbGetTokenEntry(cuid),
                    ipAddress, activityMsg, "success", remoteUser);

            return false;
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
                activityMsg = "revocation not enabled for expired cert: " + cert.getSerialNumber();
                tdbActivity(ActivityDatabase.OP_DO_TOKEN, tdbGetTokenEntry(cuid),
                        ipAddress, activityMsg, "success", remoteUser);
                return false;
            }
            if (now.before(notBefore)) {
                activityMsg = "revocation not enabled for cert that is not yet valid: " + cert.getSerialNumber();
                tdbActivity(ActivityDatabase.OP_DO_TOKEN, tdbGetTokenEntry(cuid),
                        ipAddress, activityMsg, "success", remoteUser);
                return false;
            }
        }

        // check if certs on multiple tokens should be revoked
        config = "op.enroll." + tokenType + ".keyGen." + keyType + ".recovery." +
                tokenReason + ".holdRevocationUntilLastCredential";
        boolean holdRevocation = configStore.getBoolean(config, false);
        if (holdRevocation) {
            if (!isLastActiveSharedCert(cert.getSerialNumber(), cert.getIssuedBy(), cuid)) {
                activityMsg = "revocation not permitted as certificate " + cert.getSerialNumber() +
                        " is shared by anothr active token";

                tdbActivity(ActivityDatabase.OP_DO_TOKEN, tdbGetTokenEntry(cuid),
                        ipAddress, activityMsg, "success", remoteUser);

                return false;
            }
        }

        return true;
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
        if (cuid == null)
            throw new TPSException(method + ": cuid null");
        String logMsg;
        IConfigStore configStore = CMS.getConfigStore();
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
        for (TPSCertRecord cert : certRecords) {
            // get conn id
            String config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() + ".ca.conn";
            String connID = configStore.getString(config);

            RevocationReason revokeReason = RevocationReason.UNSPECIFIED;

            if (isRevoke) {
                logMsg = "called to revoke";
                CMS.debug(method + ":" + logMsg);
                boolean revokeCert = shouldRevoke(cert, cuid, tokenReason, ipAddress, remoteUser);

                if (!revokeCert) {
                    logMsg = "cert not to be revoked:" + cert.getSerialNumber();
                    CMS.debug(method + ":" + logMsg);
                    continue;
                }
                logMsg = "cert to be revoked:" + cert.getSerialNumber();
                CMS.debug(method + ":" + logMsg);

                // get revoke reason
                config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() +
                        ".recovery." + tokenReason + ".revokeCert.reason";
                int reasonInt = configStore.getInteger(config, 0);
                revokeReason = RevocationReason.fromInt(reasonInt);
            } else { // is unrevoke
                logMsg = "called to unrevoke";
                CMS.debug(method + ":" + logMsg);
                if (!cert.getStatus().equalsIgnoreCase("revoked_on_hold")) {
                    logMsg = "cert record current status is not revoked_on_hold; cannot unrevoke";
                    CMS.debug(method + ":" + logMsg);
                    continue;// TODO: continue or bail?
                }
            }

            CARemoteRequestHandler caRH = null;
            caRH = new CARemoteRequestHandler(connID);
            String hexSerial = cert.getSerialNumber();
            if (hexSerial.length() >= 3 && hexSerial.startsWith("0x")) {
                String serial = hexSerial.substring(2); // skip over the '0x'
                BigInteger bInt = new BigInteger(serial, 16);
                String serialStr = bInt.toString();
                CMS.debug(method + ": found cert hex serial: " + serial +
                        " dec serial:" + serialStr);
                CARevokeCertResponse response =
                        caRH.revokeCertificate(isRevoke, serialStr, cert.getCertificate(),
                                revokeReason);
                CMS.debug(method + ": response status =" + response.getStatus());
            } else {
                logMsg = "mulformed hex serial number :" + hexSerial;
                CMS.debug(method + ": " + logMsg);
                throw new Exception(logMsg);
            }

            // update certificate status
            if (isRevoke) {
                if (revokeReason == RevocationReason.CERTIFICATE_HOLD) {
                    updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(), "revoked_on_hold");
                } else {
                    updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(), "revoked");
                }
            } else {
                updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(), "active");
            }

            logMsg = "cert (un)revoked:" + cert.getSerialNumber();
            CMS.debug(method + ":" + logMsg);
            //TODO: tdbActivity
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
