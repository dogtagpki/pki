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
package com.netscape.cms.profile.common;


import java.security.cert.*;
import java.math.*;
import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.connector.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.logging.*;

import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;

import java.security.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;


/**
 * This class implements a Certificate Manager enrollment
 * profile.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class CAEnrollProfile extends EnrollProfile {

    private final static String
        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST =
        "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_4";


    public CAEnrollProfile() {
        super();
    }

    public IAuthority getAuthority() {
        IAuthority authority = (IAuthority) 
            CMS.getSubsystem(CMS.SUBSYSTEM_CA);

        if (authority == null)
            return null;
        return authority;
    }

    public X500Name getIssuerName() {
        ICertificateAuthority ca = (ICertificateAuthority)
            CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        X500Name issuerName = ca.getX500Name();

        return issuerName;
    }

    public void execute(IRequest request)
        throws EProfileException {

        long startTime = CMS.getCurrentDate().getTime();
         
        if (!isEnable()) {
            CMS.debug("CAEnrollProfile: Profile Not Enabled");
            throw new EProfileException("Profile Not Enabled");
        }

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(request);
        String auditArchiveID = ILogger.UNIDENTIFIED;


        String id = request.getRequestId().toString();
        if (id != null) {
            auditArchiveID = id.trim();
        }

        CMS.debug("CAEnrollProfile: execute reqId=" + 
            request.getRequestId().toString());
        ICertificateAuthority ca = (ICertificateAuthority) getAuthority();
        ICAService caService = (ICAService) ca.getCAService();

        if (caService == null) {
            throw new EProfileException("No CA Service");
        }

        // if PKI Archive Option present, send this request
        // to DRM
        byte optionsData[] = request.getExtDataInByteArray(REQUEST_ARCHIVE_OPTIONS);

        // do not archive keys for renewal requests
        if ((optionsData != null) && (!request.getRequestType().equals(IRequest.RENEWAL_REQUEST))) {
            PKIArchiveOptions options = (PKIArchiveOptions)
                toPKIArchiveOptions(optionsData);

            if (options != null) {
                CMS.debug("CAEnrollProfile: execute found " +
                    "PKIArchiveOptions");
                try {
                    IConnector kraConnector = caService.getKRAConnector();

                    if (kraConnector == null) {
                        CMS.debug("CAEnrollProfile: KRA connector " +
                            "not configured");

                        auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditArchiveID);

                        audit(auditMessage);
                   
                    } else {
                        CMS.debug("CAEnrollProfile: execute send request");
                        kraConnector.send(request);


                        
                        // check response
                        if (!request.isSuccess()) {
                            auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditArchiveID);

                            audit(auditMessage);
                            throw new ERejectException(
                                    request.getError(getLocale(request)));
                        }

                        auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRequesterID,
                            auditArchiveID);

                        audit(auditMessage);
                    }
                } catch (Exception e) {


                    if (e instanceof ERejectException) {
                        throw (ERejectException) e;
                    }
                    CMS.debug("CAEnrollProfile: " + e.toString());
                    CMS.debug(e);

                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditArchiveID);

                    audit(auditMessage);
                    throw new EProfileException(e.toString());
                }
            }
        }

        // process certificate issuance
        X509CertInfo info = request.getExtDataInCertInfo(REQUEST_CERTINFO);
        X509CertImpl theCert = null;

        // #615460 - added audit log (transaction) 
        SessionContext sc = SessionContext.getExistingContext();
        sc.put("profileId", getId());
        String setId = request.getExtDataInString("profileSetId");
        if (setId != null) {
          sc.put("profileSetId", setId);
        }

        try {
            theCert = caService.issueX509Cert(info, getId() /* profileId */,
              id /* requestId */);
        } catch (EBaseException e) {
            CMS.debug(e.toString());

            throw new EProfileException(e.toString());
        }
        request.setExtData(REQUEST_ISSUED_CERT, theCert);

        long endTime = CMS.getCurrentDate().getTime();

        String initiative = AuditFormat.FROMAGENT
                          + " userID: "
                          + (String)sc.get(SessionContext.USER_ID);
        String authMgr = (String)sc.get(SessionContext.AUTH_MANAGER_ID);

        ILogger logger = CMS.getLogger();
        if( logger != null ) {
            logger.log( ILogger.EV_AUDIT, 
                        ILogger.S_OTHER, AuditFormat.LEVEL, AuditFormat.FORMAT, 
                        new Object[] { 
                            request.getRequestType(), 
                            request.getRequestId(), 
                            initiative, 
                            authMgr, 
                            "completed", 
                            theCert.getSubjectDN(), 
                            "cert issued serial number: 0x" + 
                            theCert.getSerialNumber().toString(16) + 
                            " time: " + (endTime - startTime) }
            );
        }

        request.setRequestStatus(RequestStatus.COMPLETE);

        // notifies updater plugins
        Enumeration updaterIds = getProfileUpdaterIds();
        while (updaterIds.hasMoreElements()) {
           String updaterId = (String)updaterIds.nextElement();
           IProfileUpdater updater = getProfileUpdater(updaterId);
           updater.update(request, RequestStatus.COMPLETE); 
        }

        // set value for predicate value - checking in getRule
        if (CMS.isEncryptionCert(theCert))
            request.setExtData("isEncryptionCert", "true");
        else
            request.setExtData("isEncryptionCert", "false");

        // Need to update request record to prevent issue 325612 and bug 516632
        IRequestQueue queue = ((IAuthority)ca).getRequestQueue();
        if (queue == null) {
            CMS.debug("CAEnrollProfile: Cannot access CA's request queue");
        } else {
            try {
                queue.updateRequest(request);
                CMS.debug("CAEnrollProfile: request "+request.getRequestId().toString()+" updated");
            } catch (EBaseException e) {
                CMS.debug("CAEnrollProfile: Request commit error " +
                        e.toString());
            }
        }
        // End of fix for issue 325612 and bug 516632

        IRequestNotifier notifier = ca.getRequestNotifier();
        if (notifier != null && notifier.isPublishingQueueEnabled()) {
            CMS.debug("about to addToNotify");
            notifier.addToNotify(request);
            CMS.debug("addToNotify done");
        } else {
            Enumeration names = ca.getRequestListenerNames();
            if (names != null) {
                while (names.hasMoreElements()) {
                    String name = (String) names.nextElement();
                    CMS.debug("CAEnrollProfile: listener " + name);
                    IRequestListener listener = ca.getRequestListener(name);
                    if (listener != null) { 
                        listener.accept(request); 
                    }
                }
            }
        }
    }
}

