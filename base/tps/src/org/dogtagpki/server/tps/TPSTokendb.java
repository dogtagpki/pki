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
import java.util.LinkedHashMap;
import java.util.Map;

import org.dogtagpki.server.tps.cms.CARemoteRequestHandler;
import org.dogtagpki.server.tps.cms.CARevokeCertResponse;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenCertStatus;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.main.ExternalRegCertToRecover;
import org.dogtagpki.tps.main.TPSException;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/*
 * TPSTokendb class offers a collection of tokendb management convenience routines
 */
public class TPSTokendb {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSTokendb.class);

    private TPSSubsystem tps;

    public TPSTokendb(TPSSubsystem tps) throws EBaseException {
        if (tps == null) {
            String msg = "TPStokendb.TPSTokendb: tps cannot be null";
            logger.error(msg);
            throw new EBaseException(msg);
        }
        this.tps = tps;
    }

    public boolean isTransitionAllowed(TokenRecord tokenRecord, TokenStatus newState) throws Exception {
        boolean result = false;
        TokenStatus currentTokenStatus = tokenRecord.getTokenStatus();

        logger.debug("TokenRecord.isTransitionAllowed(): current status: " + currentTokenStatus);
        Collection<TokenStatus> nextStatuses = tps.getUINextTokenStates(tokenRecord);

        logger.debug("TokenRecord.isTransitionAllowed(): allowed next statuses: " + nextStatuses);
        if (!nextStatuses.contains(newState)) {
            logger.debug("TokenRecord.isTransitionAllowed(): next status not allowed: " + newState);

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
            logger.warn(msg + ";" + " tokendb activity logging failure: " + e.getMessage(), e);
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
            logger.warn(msg + ";" + " tokendb activity logging failure: " + e.getMessage(), e);
        }
    }

    public boolean isTokenPresent(String cuid) {
        boolean present = false;
        try {
            tps.tokenDatabase.getRecord(cuid);
            present = true;
        } catch (Exception e) {
            logger.warn("TPSTokendb.isTokenPresent: token entry not found: " + e.getMessage(), e);
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

        // search for tokens with (userID=<UID>) filter which will be
        // translated into (tokenUserID=<UID>) LDAP filter as defined
        // in TokenRecord
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("userID", uid);

        Iterator<TokenRecord> records = tps.tokenDatabase.findRecords(null, attributes).iterator();

        ArrayList<TokenRecord> tokenRecords = new ArrayList<TokenRecord>();
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

    public void tdbHasOtherActiveToken(String userid,String cuid)
            throws Exception {
         if (userid == null || cuid == null)
             throw new Exception("TPSTokendb.tdbhasOtherActiveToken: uerid null, or cuid is null");

         ArrayList<TokenRecord> tokens =
                 tdbFindTokenRecordsByUID(userid);
         boolean foundActive = false;
         for (TokenRecord tokenRecord:tokens) {
             if (tokenRecord.getTokenStatus().equals(TokenStatus.ACTIVE)) {

                 if(!tokenRecord.getId().equalsIgnoreCase(cuid))
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
        String method = "TPSTokendb.tdbUpdateTokenEntry:";
        String id = tokenRecord.getId();
        TokenRecord existingTokenRecord;
        try {
            existingTokenRecord = tps.tokenDatabase.getRecord(id);
        } catch (EDBRecordNotFoundException e) {
            String logMsg = method + e.getMessage();
            logger.error(logMsg, e);
            throw new TPSException(logMsg);
        }
        // token found; modify
        logger.debug(method + " token entry found; Modifying with status: " + tokenRecord.getTokenStatus());
        // don't change the create time of an existing token record; put it back
        tokenRecord.setCreateTimestamp(existingTokenRecord.getCreateTimestamp());
        tps.tokenDatabase.updateRecord(id, tokenRecord);
    }

    /**
     * tdbAddCertificatesForCUID -
     *   adds ccerts in the array of TPSCertRecord onto the token, except
     *   the ones already present
     */
    public void tdbAddCertificatesForCUID(String cuid, ArrayList<TPSCertRecord> certs)
            throws TPSException {
        String method = "TPSTokendb.tdbAddCertificatesForCUID: ";
        logger.debug(method + "begins");
        boolean tokenExist = isTokenPresent(cuid);
        if (!tokenExist) {
            logger.error(method + " token not found: " + cuid);
            throw new TPSException(method + " token " + cuid + " does not exist");
        }

        logger.debug(method + " found token " + cuid);
        logger.debug(method + " number of certs to update:" + certs.size());
        try {
            for (TPSCertRecord cert : certs) {
                try {
                    if (!isCertOnToken(cert, cuid)) {
                        logger.debug(method + " adding cert with serial: " + cert.getSerialNumber());
                        tps.certDatabase.addRecord(cert.getId(), cert);
                    } else {
                        // cert already on token
                        logger.debug(method + "retain and skip adding with serial:" + cert.getSerialNumber());
                    }
                } catch (Exception e) {
                    logger.warn(method + "Exception after isCertOnToken call: "+ e.getMessage(), e);
                    // ignore; go to next;
                }
            }
        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            // TODO: what if it throws in the middle of the cert list -- some cert records already updated?
            throw new TPSException(e.getMessage(), e);
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
            logger.error("TPSTokendb.tdbGetCertificatesByCUID:" + e.getMessage(), e);
            throw new TPSException(e);
        }
    }

    public ArrayList<TPSCertRecord> tdbGetCertRecordsByCert(String serial, String issuer)
            throws TPSException {
        String method = "TPSTokendb.tdbGetCertRecordsByCert:";
        if (serial == null)
            throw new TPSException(method + " serial null");

        if (issuer == null) {
            throw new TPSException(method + " issuer null");
        }

        Map<String, String> attributes = new HashMap<String, String>();
        attributes.put("serialNumber", serial);
        attributes.put("issuedBy", issuer);

        ArrayList<TPSCertRecord> certRecords = new ArrayList<TPSCertRecord>();
        Iterator<TPSCertRecord> records;
        try {
            records = tps.certDatabase.findRecords(null, attributes).iterator();
        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            throw new TPSException(e.getMessage(), e);
        }

        while (records.hasNext()) {
            TPSCertRecord certRecord = records.next();
            certRecords.add(certRecord);
        }

        return certRecords;
    }

    /**
     * tdbGetOrigCertRecord
     * Finds and returns the original cert record --
     *   tokenID must match tokenOrigin in the cert record;
     * Returns null if cert not found;
     */
    public TPSCertRecord tdbGetOrigCertRecord(X509CertImpl cert) {
        String method = "TPSTokendb.tdbGetCertTokenOrigin: ";
        TPSCertRecord result = null;

        String serialNumber = null;
        String issuedBy = null;

        if (cert == null) {
            logger.warn(method + "input param cert null");
            return null;
        }
        try {
            BigInteger serial_BigInt = cert.getSerialNumber();
            String hexSerial = serial_BigInt.toString(16);
            serialNumber = "0x" + hexSerial;
            issuedBy = cert.getIssuerDN().toString();
        } catch (Exception e) {
            logger.error(method + ":" + e.getMessage(), e);
            return null;
        }

        ArrayList<TPSCertRecord> certRecords = null;
        try {
            certRecords = tdbGetCertRecordsByCert(serialNumber, issuedBy);
        } catch (TPSException e) {
            logger.warn(method + e.getMessage(), e);
            return null;
        }

        for (TPSCertRecord certRec : certRecords) {
            String tokenID = certRec.getTokenID();
            String origin = certRec.getOrigin();
            if ((tokenID != null) && (origin != null) &&
                    (tokenID.equalsIgnoreCase(origin))) {
                logger.debug(method + "found original cert record");
                result = certRec;
            }
        }
        return result;
    }

    /**
     * isCertOnToken -
     *   returns true if cert is currently on token; false otherwise
     */
    private boolean isCertOnToken(TPSCertRecord cert, String cuid) {
        String method = "TPSTokendb: isCertOnToken: ";
        boolean result = false;
        String filter = cuid;
        Iterator<TPSCertRecord> records;
        if (cert == null) {
            logger.warn(method + "input param cert null");
            return false;
        }
        if (cuid == null) {
            logger.warn(method + "input param cuid null");
            return false;
        }

        logger.debug(method + "begins - " +
                "cert serial = " + cert.getSerialNumber() +
                "; token cuid = " + cuid);
        try {
            records = tps.certDatabase.findRecords(filter).iterator();
        } catch (Exception e) {
            logger.warn(method + ":" + e.getMessage(), e);
            return false;
        }
        if (!records.hasNext()) {
            logger.warn(method + "no cert records currently exist on token");
            return false;
        }

        while (records.hasNext()) {
            TPSCertRecord certRecord = records.next();
            // logger.debug(method + "found cert serial: " + certRecord.getSerialNumber());
            // make sure the cuid matches the tokenID instead of the origin !
            if (certRecord.getTokenID().equalsIgnoreCase(cuid)) {
                if (certRecord.getSerialNumber().equalsIgnoreCase(cert.getSerialNumber())) {
                    logger.debug(method + "cert exists on token; serial: " + cert.getSerialNumber());
                    result = true;
                    break;
                }
            }
        }

        return result;
    }

    public void tdbRemoveCertificatesByCUID(String cuid)
            throws Exception {
        tdbRemoveCertificatesByCUID(cuid, null);
    }

    /**
     * tdbRemoveCertificatesByCUID removes all certs on the token
     * record except for the ones in the erCertsToRecover;
     * If erCertsToRecover is null, all certs will be removed on
     * the token;
     */
    public void tdbRemoveCertificatesByCUID(String cuid,
            ArrayList<ExternalRegCertToRecover> erCertsToRecover)
            throws Exception {
        String method = "TPSTokendb.tdbRemoveCertificatesByCUID";
        if (cuid == null)
            throw new Exception(method + ": cuid null");

        logger.debug(method + ":" + " begins for cuid =" + cuid);
        String filter = cuid;
        Iterator<TPSCertRecord> records;
        try {
            records = tps.certDatabase.findRecords(filter).iterator();
        } catch (Exception e) {
            logger.error(method + ":" + e.getMessage(), e);
            throw new Exception(method + ":" + e);
        }

        while (records.hasNext()) {
            TPSCertRecord certRecord = records.next();
            // make sure the cuid matches the tokenID instead of the origin !
            if (certRecord.getTokenID().equalsIgnoreCase(cuid)) {
                boolean isCertRetained = false;
                if (erCertsToRecover != null) {
                    isCertRetained = isCertRetained(certRecord.getSerialNumberInBigInteger(), erCertsToRecover);
                }

                if (!isCertRetained) {
                    tps.certDatabase.removeRecord(certRecord.getId());
                    logger.debug(method + ":" + "cert removed:" + certRecord.getId());
                } else {
                    logger.debug(method + ":" + "cert retained:" + certRecord.getId());
                }
            } else {
                logger.debug(method + ":" + " record not matched:" + certRecord.getTokenID());
            }
        }
        logger.debug(method + ":" + " done");
    }

    /**
     * isCertRetained returns true if cert is retainable, false otherwise
     */
    private boolean isCertRetained(BigInteger certSerial,
            ArrayList<ExternalRegCertToRecover> erCertsToRecover) {
        String method = "TPSTokendb.isCertRetained: ";
        boolean result = false;
        if (erCertsToRecover == null) {
            logger.warn(method + "input param erCertsToRecover null");
            return false;
        }
        if (certSerial == null) {
            logger.warn(method + "input param certSerial null");
            return false;
        }

        for (ExternalRegCertToRecover certToRecover : erCertsToRecover) {
            if (certToRecover == null) {
                continue;
            }
            // TODO: could enhance the comparison to include more than serials
            if (certSerial.compareTo(certToRecover.getSerial()) == 0) {
                if (certToRecover.getIsRetainable()) {
                    result = true;
                    break;
                }
            }
        }
        return result;
    }

    public void revokeCertsByCUID(String cuid, String tokenReason, String ipAddress, String remoteUser)
            throws Exception {
        String method = "TPStokendb.revokeCertsByCUID";
        logger.debug(method + ": called");
        if (cuid == null)
            throw new TPSException(method + ": cuid null");
        revokeCertsByCUID(true, cuid, tokenReason, ipAddress, remoteUser);
    }

    public void unRevokeCertsByCUID(String cuid, String ipAddress, String remoteUser) throws Exception {
        String method = "TPStokendb.unRevokeCertsByCUID";
        logger.debug(method + ": called");
        if (cuid == null)
            throw new TPSException(method + ": cuid null");
        revokeCertsByCUID(false, cuid, null /* null for unrevoke*/, ipAddress, remoteUser);
    }

    private boolean isLastActiveSharedCert(String serial, String issuer, String cuid) throws TPSException {
        String method = "TPSTokendb.isLastActiveSharedCert";
        String msg = "";
        if (serial == null) {
            msg = "input param serial null";
            throw new TPSException(method + msg);
        }
        if (issuer == null) {
            msg = "input param issuer null";
            throw new TPSException(method + msg);
        }
        if (cuid == null) {
            msg = "input param cuid null";
            throw new TPSException(method + msg);
        }

        logger.debug(method + "begins for cuid = " + cuid);
        ArrayList<TPSCertRecord> certRecords = tps.getTokendb().tdbGetCertRecordsByCert(serial, issuer);
        for (TPSCertRecord cert : certRecords) {
            logger.debug(method + "found cert record for cuid = " + cert.getTokenID() + ", cert status = "
                    + cert.getStatus());
            // exclude current token
            if (cert.getTokenID().equals(cuid))
                continue;

            TokenRecord tokenRecord = null;
            try {
                tokenRecord = tdbGetTokenEntry(cert.getTokenID());
            } catch (Exception e) {
                throw new TPSException("error getting token entry for: " + cert.getTokenID() + ": " + e.getMessage(), e);
            }

            if (tokenRecord.getTokenStatus() == TokenStatus.ACTIVE) {
                logger.warn(method + "token " + cert.getTokenID() + " contains the cert and has status: "
                        + tokenRecord.getTokenStatus() + "... returning false");
                return false;
            } else {
                logger.debug(method + "token " + cert.getTokenID() + " status: " + tokenRecord.getTokenStatus());
            }

        }

        logger.debug(method + "returning true");
        return true;
    }

    private void revokeCert(TokenRecord tokenRecord, TPSCertRecord cert, String tokenReason,
            String ipAddress, String remoteUser) {

        String method = "TPSTokendb.revokeCert";
        String logMsg;

        logger.debug(method + "begins: tokenReason=" + tokenReason);

        CMSEngine engine = CMS.getCMSEngine();
        try {

            EngineConfig configStore = engine.getConfig();

            // get conn ID
            String config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() + ".ca.conn";
            logger.debug(method + ": " + " getting config: " + config);
            String connID = configStore.getString(config);

            RevocationReason revokeReason = RevocationReason.UNSPECIFIED;

            checkShouldRevoke(tokenRecord, cert, tokenReason, ipAddress, remoteUser);

            logMsg = "certificate to be revoked:" + cert.getSerialNumber();
            logger.debug(method + ": " + logMsg);

            // get revoke reason
            config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() +
                    ".recovery." + tokenReason + ".revokeCert.reason";
            logger.debug(method + ": " + " getting config: " + config);
            int reasonInt = configStore.getInteger(config, 0);
            revokeReason = RevocationReason.fromInt(reasonInt);

            CARemoteRequestHandler caRH = new CARemoteRequestHandler(connID);
            BigInteger bInt = cert.getSerialNumberInBigInteger();
            String serialStr = bInt.toString();
            logger.debug(method + ": found cert hex serial: " + cert.getSerialNumber() +
                    " dec serial: " + serialStr);
            CARevokeCertResponse response =
                    caRH.revokeCertificate(true, serialStr, cert.getCertificate(),
                            revokeReason);
            logger.debug(method + ": response status: " + response.getStatus());

            // update certificate status
            if (revokeReason == RevocationReason.CERTIFICATE_HOLD) {
                updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(),
                        TokenCertStatus.ONHOLD.toString());
            } else {
                updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(),
                        TokenCertStatus.REVOKED.toString());
            }

            logMsg = "certificate revoked: " + cert.getSerialNumber();
            logger.debug(method + ": " + logMsg);

            tdbActivity(ActivityDatabase.OP_CERT_REVOCATION, tokenRecord,
                    ipAddress, logMsg, "success", remoteUser);

        } catch (Exception e) {
            logMsg = "certificate not revoked: " + cert.getSerialNumber() + ": " + e.getMessage();
            logger.warn(method + ": " + logMsg, e);

            tdbActivity(ActivityDatabase.OP_CERT_REVOCATION, tokenRecord,
                    ipAddress, e.getMessage(), "failure", remoteUser);

            // continue revoking the next certificate
        }
    }

    private void unrevokeCert(TokenRecord tokenRecord, TPSCertRecord cert, String tokenReason,
            String ipAddress, String remoteUser) {

        String method = "TPSTokendb.unrevokeCert";
        String logMsg;

        CMSEngine engine = CMS.getCMSEngine();
        try {
            EngineConfig configStore = engine.getConfig();

            // get conn ID
            String config = "op.enroll." + cert.getType() + ".keyGen." + cert.getKeyType() + ".ca.conn";
            String connID = configStore.getString(config);

            RevocationReason revokeReason = RevocationReason.UNSPECIFIED;

            logMsg = "called to unrevoke";
            logger.debug(method + ": " + logMsg);

            if (!cert.getStatus().equalsIgnoreCase(TokenCertStatus.ONHOLD.toString())) {
                logMsg = "certificate record current status is not revoked_on_hold; cannot unrevoke";
                logger.warn(method + ": " + logMsg);
                return; // TODO: continue or bail?
            }

            CARemoteRequestHandler caRH = new CARemoteRequestHandler(connID);
            BigInteger bInt = cert.getSerialNumberInBigInteger();
            String serialStr = bInt.toString();
            logger.debug(method + ": found cert hex serial: " + cert.getSerialNumber() +
                    " dec serial: " + serialStr);
            CARevokeCertResponse response =
                    caRH.revokeCertificate(false, serialStr, cert.getCertificate(),
                            revokeReason);
            logger.debug(method + ": response status: " + response.getStatus());

            // update certificate status
            updateCertsStatus(cert.getSerialNumber(), cert.getIssuedBy(),
                    TokenCertStatus.ACTIVE.toString());

            logMsg = "certificate unrevoked: " + cert.getSerialNumber();
            logger.debug(method + ": " + logMsg);

            tdbActivity(ActivityDatabase.OP_CERT_RESTORATION, tokenRecord,
                    ipAddress, logMsg, "success", remoteUser);

        } catch (Exception e) {
            logMsg = "certificate not unrevoked: " + cert.getSerialNumber() + " : " + e.getMessage();
            logger.warn(method + ": " + logMsg, e);

            tdbActivity(ActivityDatabase.OP_CERT_RESTORATION, tokenRecord,
                    ipAddress, e.getMessage(), "failure", remoteUser);

            // continue unrevoking the next certificate
        }
    }

    private void checkShouldRevoke(TokenRecord tokenRecord, TPSCertRecord cert, String tokenReason,
            String ipAddress, String remoteUser) throws Exception {

        String method = "TPSTokendb.checkShouldRevoke:";
        String msg = "";
        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig configStore = engine.getConfig();

        if (cert == null) {
            throw new TPSException("Missing token certificate");
        }
        if (cert.getStatus().equalsIgnoreCase(TokenCertStatus.REVOKED.toString())) {
            String existingTokenReason = tokenRecord.getReason();
            if( (existingTokenReason != null && existingTokenReason.equals(tokenReason)) ||
                (existingTokenReason == null && tokenReason == null) )
            {
                throw new TPSException(
                        method + "certificate " + cert.getSerialNumber() +
                                " already revoked and reason has not changed.");
            }
            else {
                logger.debug(method + "Cert " + cert.getSerialNumber() +
                        " already revoked, but reason has changed, so revoking again.");
                logger.debug(method + "Previous reason was: " +
                        ((existingTokenReason == null) ? "(null)" : existingTokenReason));
                logger.debug(method + "New reason is: " +
                        ((tokenReason == null) ? "(null)" : tokenReason));
            }
        }
        logger.debug(method + "begins: ");

        String tokenType = cert.getType();
        String keyType = cert.getKeyType();

        // check if certificate revocation is enabled
        String config = "op.enroll." + tokenType + ".keyGen." + keyType +
                ".recovery." + tokenReason + ".revokeCert";
        logger.debug(method + "getting config:" + config);
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
        logger.debug(method + "getting config:" + config);
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
        logger.debug(method + "getting config:" + config);
        boolean holdRevocation = configStore.getBoolean(config, false);
        if (holdRevocation) {
            if (!isLastActiveSharedCert(cert.getSerialNumber(), cert.getIssuedBy(), tokenRecord.getId())) {
                msg = "revocation not permitted as certificate " + cert.getSerialNumber() +
                        " is shared by another active token";
                logger.error(method + " holdRevocation true; " + msg);
                throw new TPSException(msg);
            }
        }
        logger.debug(method + "revocation allowed.");
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
            logger.error(method + ": " + logMsg);
            throw new TPSException(logMsg);
        }

        logger.debug(method + "begins: with tokenReason=" + tokenReason);

        TokenRecord tokenRecord = tdbGetTokenEntry(cuid);

        Collection<TPSCertRecord> certRecords = tps.getTokendb().tdbGetCertRecordsByCUID(cuid);
        if (tokenReason != null) {
            if (!tokenReason.equalsIgnoreCase("onHold") &&
                    !tokenReason.equalsIgnoreCase("destroyed") &&
                    !tokenReason.equalsIgnoreCase("keyCompromise") &&
                    !tokenReason.equalsIgnoreCase("terminated")) {
                logMsg = "unknown tokenRecord lost reason:" + tokenReason;
                logger.error(method + ":" + logMsg);
                throw new Exception(method + ":" + logMsg);
            }
        }

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
            logger.warn(method + ": token entry not found; Adding: " + e.getMessage(), e);
            // add and exit
            tdbAddCertEntry(certRecord, certRecord.getStatus());
            return;
        }
        // cert found; modify
        logger.debug(method + ": cert entry found; Modifying with status: "+ certRecord.getStatus());
        // don't change the create time of an existing token record; put it back
        certRecord.setCreateTime(existingCertRecord.getCreateTime());
        tps.certDatabase.updateRecord(id, certRecord);
    }
}
