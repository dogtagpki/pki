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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.kra;

import java.math.BigInteger;

import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.servlet.request.KeyRequestService;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmsutil.util.Utils;

/**
 * This implementation implements SecurityData archival operations.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class SecurityDataService implements IService {

    private final static String DEFAULT_OWNER = "IPA Agent";
    public final static String ATTR_KEY_RECORD = "keyRecord";
    private final static String STATUS_ACTIVE = "active";

    private IKeyRecoveryAuthority mKRA = null;
    private ITransportKeyUnit mTransportUnit = null;
    private IStorageKeyUnit mStorageUnit = null;
    private ILogger signedAuditLogger = CMS.getSignedAuditLogger();

    private final static String LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED_6";


    public SecurityDataService(IKeyRecoveryAuthority kra) {
        mKRA = kra;
        mTransportUnit = kra.getTransportKeyUnit();
        mStorageUnit = kra.getStorageKeyUnit();
    }

    /**
     * Performs the service of archiving Security Data.
     * represented by this request.
     * <p>
     *
     * @param request
     *            The request that needs service. The service may use
     *            attributes stored in the request, and may update the
     *            values, or store new ones.
     * @return
     *         an indication of whether this request is still pending.
     *         'false' means the request will wait for further notification.
     * @exception EBaseException indicates major processing failure.
     */
    public boolean serviceRequest(IRequest request)
            throws EBaseException {
        String id = request.getRequestId().toString();
        String clientKeyId = request.getExtDataInString(IRequest.SECURITY_DATA_CLIENT_KEY_ID);

        // one way to get data - unexploded pkiArchiveOptions
        String pkiArchiveOptions = request.getExtDataInString(IEnrollProfile.REQUEST_ARCHIVE_OPTIONS);

        // another way - exploded pkiArchiveOptions
        String transWrappedSessionKey = request.getExtDataInString(IEnrollProfile.REQUEST_SESSION_KEY);
        String wrappedSecurityData = request.getExtDataInString(IEnrollProfile.REQUEST_SECURITY_DATA);
        String algParams = request.getExtDataInString(IEnrollProfile.REQUEST_ALGORITHM_PARAMS);
        String algStr = request.getExtDataInString(IEnrollProfile.REQUEST_ALGORITHM_OID);

        // prameters if the secret is a symkey
        String dataType = request.getExtDataInString(IRequest.SECURITY_DATA_TYPE);
        String algorithm = request.getExtDataInString(IRequest.SECURITY_DATA_ALGORITHM);
        int strength = request.getExtDataInInteger(IRequest.SECURITY_DATA_STRENGTH);

        CMS.debug("SecurityDataService.serviceRequest. Request id: " + id);
        CMS.debug("SecurityDataService.serviceRequest wrappedSecurityData: " + wrappedSecurityData);

        String owner = getOwnerName(request);
        String subjectID = auditSubjectID();

        //Check here even though restful layer checks for this.
        if (clientKeyId == null || dataType == null) {
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Bad data in request");
            throw new EBaseException("Bad data in SecurityDataService.serviceRequest");
        }

        if (wrappedSecurityData != null) {
            if (transWrappedSessionKey == null || algStr == null || algParams == null) {
                throw new EBaseException(
                        "Bad data in SecurityDataService.serviceRequest, no session key");

            }
        } else if (pkiArchiveOptions == null) {
            throw new EBaseException("No data to archive in SecurityDataService.serviceRequest");
        }

        byte[] wrappedSessionKey = null;
        byte[] secdata = null;
        byte[] sparams = null;

        if (wrappedSecurityData == null) {
            // We have PKIArchiveOptions data

            //We need some info from the PKIArchiveOptions wrapped security data
            byte[] encoded = Utils.base64decode(pkiArchiveOptions);

            ArchiveOptions options = ArchiveOptions.toArchiveOptions(encoded);
            algStr = options.getSymmAlgOID();
            wrappedSessionKey = options.getEncSymmKey();
            secdata = options.getEncValue();
            sparams = options.getSymmAlgParams();

        } else {
            wrappedSessionKey = Utils.base64decode(transWrappedSessionKey);
            secdata = Utils.base64decode(wrappedSecurityData);
            sparams = Utils.base64decode(algParams);
        }

        SymmetricKey securitySymKey = null;
        byte[] securityData = null;

        String keyType = null;
        if (dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE)) {
            // Symmetric Key
            keyType = KeyRequestResource.SYMMETRIC_KEY_TYPE;
            securitySymKey = mTransportUnit.unwrap_symmetric(
                    wrappedSessionKey,
                    algStr,
                    sparams,
                    secdata,
                    KeyRequestService.SYMKEY_TYPES.get(algorithm),
                    strength);

        } else if (dataType.equals(KeyRequestResource.PASS_PHRASE_TYPE)) {
            keyType = KeyRequestResource.PASS_PHRASE_TYPE;
            securityData = mTransportUnit.decryptExternalPrivate(
                    wrappedSessionKey,
                    algStr,
                    sparams,
                    secdata);

        }

        byte[] publicKey = null;
        byte privateSecurityData[] = null;

        if (securitySymKey != null) {
            privateSecurityData = mStorageUnit.wrap(securitySymKey);
        } else if (securityData != null) {
            privateSecurityData = mStorageUnit.encryptInternalPrivate(securityData);
        } else { // We have no data.
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to create security data to archive");
            throw new EBaseException("Failed to create security data to archive!");
        }
        // create key record
        KeyRecord rec = new KeyRecord(null, publicKey,
                privateSecurityData, owner,
                algStr, owner);

        rec.set(IKeyRecord.ATTR_CLIENT_ID, clientKeyId);

        //Now we need a serial number for our new key.

        if (rec.getSerialNumber() != null) {
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        IKeyRepository storage = mKRA.getKeyRepository();
        BigInteger serialNo = storage.getNextSerialNumber();

        if (serialNo == null) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_GET_NEXT_SERIAL"));
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to get  next Key ID");
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        rec.set(KeyRecord.ATTR_ID, serialNo);
        rec.set(KeyRecord.ATTR_DATA_TYPE, keyType);
        rec.set(KeyRecord.ATTR_STATUS, STATUS_ACTIVE);

        if (dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE)) {
            rec.set(KeyRecord.ATTR_ALGORITHM, algorithm);
            rec.set(KeyRecord.ATTR_KEY_SIZE, strength);
        }

        request.setExtData(ATTR_KEY_RECORD, serialNo);

        CMS.debug("KRA adding Security Data key record " + serialNo);

        storage.addKeyRecord(rec);

        auditArchivalRequestProcessed(subjectID, ILogger.SUCCESS, request.getRequestId(),
                clientKeyId, serialNo.toString(), "None");
        request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        mKRA.getRequestQueue().updateRequest(request);

        return true;

    }
    //ToDo: return real owner with auth
    private String getOwnerName(IRequest request) {
        return DEFAULT_OWNER;
    }

    private void audit(String msg) {
        if (signedAuditLogger == null)
            return;

        signedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    private String auditSubjectID() {
        if (signedAuditLogger == null) {
            return null;
        }

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String) auditContext.get(SessionContext.USER_ID);
            subjectID = (subjectID != null) ? subjectID.trim() : ILogger.NONROLEUSER;
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    private void auditArchivalRequestProcessed(String subjectID, String status, RequestId requestID, String clientKeyID,
            String keyID, String reason) {
        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED,
                subjectID,
                status,
                requestID.toString(),
                clientKeyID,
                keyID != null ? keyID : "None",
                reason);
        audit(auditMessage);
    }
}