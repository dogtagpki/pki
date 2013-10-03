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
        String clientId = request.getExtDataInString(IRequest.SECURITY_DATA_CLIENT_ID);
        String wrappedSecurityData = request.getExtDataInString(IEnrollProfile.REQUEST_ARCHIVE_OPTIONS);
        String dataType = request.getExtDataInString(IRequest.SECURITY_DATA_TYPE);

        CMS.debug("SecurityDataService.serviceRequest. Request id: " + id);
        CMS.debug("SecurityDataService.serviceRequest wrappedSecurityData: " + wrappedSecurityData);

        String owner = getOwnerName(request);
        String subjectID = auditSubjectID();

        //Check here even though restful layer checks for this.
        if(wrappedSecurityData == null || clientId == null || dataType == null) {
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientId, null, "Bad data in request");
            throw new EBaseException("Bad data in SecurityDataService.serviceRequest");
        }
        //We need some info from the PKIArchiveOptions wrapped security data

        byte[] encoded = Utils.base64decode(wrappedSecurityData);

        ArchiveOptions options = ArchiveOptions.toArchiveOptions(encoded);

        //Check here just in case a null ArchiveOptions makes it this far
        if(options == null) {
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientId, null, "Problem decoding PKIArchiveOptions");
            throw new EBaseException("Problem decoding PKIArchiveOptions.");
        }

        String algStr = options.getSymmAlgOID();

        SymmetricKey securitySymKey = null;
        byte[] securityData = null;

        String keyType = null;
        if (dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE)) {
            // Symmetric Key
            keyType = KeyRequestResource.SYMMETRIC_KEY_TYPE;
            securitySymKey = mTransportUnit.unwrap_symmetric(options.getEncSymmKey(),
                      options.getSymmAlgOID(),
                      options.getSymmAlgParams(),
                      options.getEncValue());

        } else if (dataType.equals(KeyRequestResource.PASS_PHRASE_TYPE)) {
            keyType = KeyRequestResource.PASS_PHRASE_TYPE;
            securityData = mTransportUnit.decryptExternalPrivate(options.getEncSymmKey(),
                      options.getSymmAlgOID(),
                      options.getSymmAlgParams(),
                      options.getEncValue());

        }

        byte[] publicKey = null;
        byte privateSecurityData[] = null;

        if (securitySymKey != null) {
            privateSecurityData = mStorageUnit.wrap(securitySymKey);
        } else if (securityData != null) {
            privateSecurityData = mStorageUnit.encryptInternalPrivate(securityData);
        } else { // We have no data.
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientId, null, "Failed to create security data to archive");
            throw new EBaseException("Failed to create security data to archive!");
        }
        // create key record
        KeyRecord rec = new KeyRecord(null, publicKey,
                privateSecurityData, owner,
                algStr, owner);

        rec.set(IKeyRecord.ATTR_CLIENT_ID, clientId);

        //Now we need a serial number for our new key.

        if (rec.getSerialNumber() != null) {
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientId, null, CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        IKeyRepository storage = mKRA.getKeyRepository();
        BigInteger serialNo = storage.getNextSerialNumber();

        if (serialNo == null) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_GET_NEXT_SERIAL"));
            auditArchivalRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientId, null, "Failed to get  next Key ID");
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        rec.set(KeyRecord.ATTR_ID, serialNo);
        rec.set(KeyRecord.ATTR_DATA_TYPE, keyType);
        rec.set(KeyRecord.ATTR_STATUS, STATUS_ACTIVE);
        request.setExtData(ATTR_KEY_RECORD, serialNo);

        CMS.debug("KRA adding Security Data key record " + serialNo);

        storage.addKeyRecord(rec);

        auditArchivalRequestProcessed(subjectID, ILogger.SUCCESS, request.getRequestId(),
                clientId, serialNo.toString(), "None");

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

    private void auditArchivalRequestProcessed(String subjectID, String status, RequestId requestID, String clientID,
            String keyID, String reason) {
        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED,
                subjectID,
                status,
                requestID.toString(),
                clientID,
                keyID != null ? keyID : "None",
                reason);
        audit(auditMessage);
    }
}