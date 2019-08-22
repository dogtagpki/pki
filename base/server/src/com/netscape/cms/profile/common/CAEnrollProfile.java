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

import java.util.Date;
import java.util.Enumeration;

import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.ICAService;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IProfileUpdater;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.cert.CertUtils;

/**
 * This class implements a Certificate Manager enrollment
 * profile.
 *
 * @version $Revision$, $Date$
 */
public class CAEnrollProfile extends EnrollProfile {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAEnrollProfile.class);

    public CAEnrollProfile() {
    }

    public IAuthority getAuthority() {
        CMSEngine engine = CMS.getCMSEngine();
        IAuthority authority = (IAuthority) engine.getSubsystem(ICertificateAuthority.ID);

        if (authority == null)
            return null;
        return authority;
    }

    public X500Name getIssuerName() {
        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        X500Name issuerName = ca.getX500Name();

        return issuerName;
    }

    public void execute(IRequest request)
            throws EProfileException, ERejectException {

        long startTime = new Date().getTime();

        if (!isEnable()) {
            logger.error("CAEnrollProfile: Profile Not Enabled");
            throw new EProfileException("Profile Not Enabled");
        }

        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(request);
        RequestId requestId = request.getRequestId();


        logger.debug("CAEnrollProfile: execute request ID " + requestId.toString());

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
            PKIArchiveOptions options = toPKIArchiveOptions(optionsData);

            if (options != null) {
                logger.debug("CAEnrollProfile: execute found " +
                        "PKIArchiveOptions");
                try {
                    IConnector kraConnector = caService.getKRAConnector();

                    if (kraConnector == null) {
                        String message = "KRA connector not configured";
                        logger.error("CAEnrollProfile: " + message);

                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null,
                                message));

                        throw new EProfileException(message);

                    } else {
                        logger.debug("CAEnrollProfile: execute send request");
                        kraConnector.send(request);

                        // check response
                        if (!request.isSuccess()) {
                            String message = "archival request failed";
                            logger.error("CAEnrollProfile: " + message);

                            signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                    auditSubjectID,
                                    auditRequesterID,
                                    requestId,
                                    null,
                                    message));

                            if (getLocale(request) != null &&
                                request.getError(getLocale(request)) != null) {

                                if ((request.getError(getLocale(request))).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) {
                                    logger.error("CAEnrollProfile: execute set request status: REJECTED");
                                    request.setRequestStatus(RequestStatus.REJECTED);
                                    ca.getRequestQueue().updateRequest(request);
                                }
                                throw new ERejectException(
                                    request.getError(getLocale(request)));
                            } else {
                                throw new ERejectException(CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST")+ " check KRA log for detail");
                            }
                        }

                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null));
                    }
                } catch (Exception e) {

                    logger.error("CAEnrollProfile: " + e.getMessage(), e);

                    signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                            auditSubjectID,
                            auditRequesterID,
                            requestId,
                            null,
                            e));

                    if (e instanceof ERejectException) {
                        throw (ERejectException) e;
                    }
                    throw new EProfileException(e);
                }
            }
        }

        // process certificate issuance
        X509CertInfo info = request.getExtDataInCertInfo(REQUEST_CERTINFO);
        // #615460 - added audit log (transaction)
        SessionContext sc = SessionContext.getExistingContext();
        sc.put("profileId", getId());

        String setId = request.getExtDataInString("profileSetId");
        if (setId != null) {
            sc.put("profileSetId", setId);
        }

        AuthorityID aid = null;
        String aidString = request.getExtDataInString(IRequest.AUTHORITY_ID);
        if (aidString != null)
            aid = new AuthorityID(aidString);

        X509CertImpl theCert;
        try {
            theCert = caService.issueX509Cert(
                aid, info, getId() /* profileId */, requestId.toString());
        } catch (EBaseException e) {
            logger.error("CAEnrollProfile: " + e.getMessage(), e);
            throw new EProfileException(e);
        }

        request.setExtData(REQUEST_ISSUED_CERT, theCert);

        long endTime = new Date().getTime();

        String initiative = AuditFormat.FROMAGENT
                          + " userID: "
                          + (String) sc.get(SessionContext.USER_ID);
        String authMgr = (String) sc.get(SessionContext.AUTH_MANAGER_ID);

        logger.info(
                AuditFormat.FORMAT,
                request.getRequestType(),
                request.getRequestId(),
                initiative,
                authMgr,
                "completed",
                theCert.getSubjectDN(),
                "cert issued serial number: 0x" +
                        theCert.getSerialNumber().toString(16) +
                        " time: " + (endTime - startTime)
        );

        request.setRequestStatus(RequestStatus.COMPLETE);

        // notifies updater plugins
        Enumeration<String> updaterIds = getProfileUpdaterIds();
        while (updaterIds.hasMoreElements()) {
            String updaterId = updaterIds.nextElement();
            IProfileUpdater updater = getProfileUpdater(updaterId);
            updater.update(request, RequestStatus.COMPLETE);
        }

        // set value for predicate value - checking in getRule
        if (CertUtils.isEncryptionCert(theCert))
            request.setExtData("isEncryptionCert", "true");
        else
            request.setExtData("isEncryptionCert", "false");
    }

}
