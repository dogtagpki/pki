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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.ICAService;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IProfileUpdater;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

/**
 * This class implements a Certificate Manager enrollment
 * profile.
 *
 * @author cfu - Server-Side Keygen Enrollment implementation
 */
public class CAEnrollProfile extends EnrollProfile {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public CAEnrollProfile() {
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
            throws EProfileException, ERejectException {
        String method = "CAEnrollProfile: execute: ";
        long startTime = CMS.getCurrentDate().getTime();

        if (!isEnable()) {
            CMS.debug("CAEnrollProfile: Profile Not Enabled");
            throw new EProfileException("Profile Not Enabled");
        }

        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(request);
        RequestId requestId = request.getRequestId();


        CMS.debug("CAEnrollProfile: execute request ID " + requestId.toString());

        ICertificateAuthority ca = (ICertificateAuthority) getAuthority();

        ICAService caService = (ICAService) ca.getCAService();
        if (caService == null) {
            throw new EProfileException("No CA Service");
        }

        //cfu: if isServerSideKeygen, send keygen request to KRA
        boolean isSSKeygen = false;
        String isSSKeygenStr = request.getExtDataInString("isServerSideKeygen");
        if (isSSKeygenStr != null && isSSKeygenStr.equalsIgnoreCase("true")) {
            CMS.debug(method + "isServerSideKeygen = true");
            isSSKeygen = true;
        } else {
            CMS.debug(method + "isServerSideKeygen = false");
        }

        // if PKI Archive Option present, send this request
        // to DRM
        byte optionsData[] = request.getExtDataInByteArray(REQUEST_ARCHIVE_OPTIONS);
        if (isSSKeygen) { // cfu
            request.setExtData(IRequest.SSK_STAGE, IRequest.SSK_STAGE_KEYGEN);
            try {
                IConnector kraConnector = caService.getKRAConnector();

                if (kraConnector == null) {
                    String message = "KRA connector not configured";
                    CMS.debug(method + message);
                } else {
                    CMS.debug(method + "request");
                    kraConnector.send(request);

                    // check response
                    if (!request.isSuccess()) {
                        String message = "serverSide Keygen request failed";
                        CMS.debug(method + message);

                        if (getLocale(request) != null &&
                                request.getError(getLocale(request)) != null) {

                            if ((request.getError(getLocale(request))).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) { //Todo
                                CMS.debug(method + "set request status: REJECTED");
                                request.setRequestStatus(RequestStatus.REJECTED);
                                ca.getRequestQueue().updateRequest(request);
                            }
                            throw new ERejectException(
                                    request.getError(getLocale(request)));
                        } else {
                            throw new ERejectException(CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST")+ " check KRA log for detail");
                        }
                    }
/*
                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null));
*/
                }
            } catch (Exception e) {

                CMS.debug(method + e);

/*
                    signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                            auditSubjectID,
                            auditRequesterID,
                            requestId,
                            null,
                            e));
*/

                if (e instanceof ERejectException) {
                    throw (ERejectException) e;
                }
                throw new EProfileException(e);
            }
        } else if ((optionsData != null) && (!request.getRequestType().equals(IRequest.RENEWAL_REQUEST))) {
            // do not archive keys for renewal requests
            PKIArchiveOptions options = toPKIArchiveOptions(optionsData);

            if (options != null) {
                CMS.debug("CAEnrollProfile: execute found " +
                        "PKIArchiveOptions");
                try {
                    IConnector kraConnector = caService.getKRAConnector();

                    if (kraConnector == null) {
                        String message = "KRA connector not configured";
                        CMS.debug("CAEnrollProfile: " + message);

                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null,
                                message));

                        throw new EProfileException(message);

                    } else {
                        CMS.debug("CAEnrollProfile: execute send request");
                        kraConnector.send(request);

                        // check response
                        if (!request.isSuccess()) {
                            String message = "archival request failed";
                            CMS.debug("CAEnrollProfile: " + message);

                            signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                    auditSubjectID,
                                    auditRequesterID,
                                    requestId,
                                    null,
                                    message));

                            if (getLocale(request) != null &&
                                request.getError(getLocale(request)) != null) {

                                if ((request.getError(getLocale(request))).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) {
                                    CMS.debug("CAEnrollProfile: execute set request status: REJECTED");
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

                    CMS.debug("CAEnrollProfile: " + e);

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

        if (isSSKeygen) { // cfu
            try {
                String pubKeyStr = request.getExtDataInString("public_key");
                CMS.debug(method + "pubKeyStr = " + pubKeyStr);
                byte[] pubKeyB = CryptoUtil.base64Decode(pubKeyStr);
                CertificateX509Key certKey = new CertificateX509Key(
                    new ByteArrayInputStream(pubKeyB));
                Object oj = info.get(X509CertInfo.KEY);
                if (oj != null) {
                    info.delete(X509CertInfo.KEY);
                    CMS.debug(method + " fake key deleted");
                }
                info.set(X509CertInfo.KEY, certKey);
            } catch (IOException e) {
                CMS.debug(method + e);
                throw new EProfileException(e);
            } catch (CertificateException e) {
                CMS.debug(method + e);
                throw new EProfileException(e);
            }
        }

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
            CMS.debug(e);
            throw new EProfileException(e);
        }

        request.setExtData(REQUEST_ISSUED_CERT, theCert);

        //cfu: cert issued, now retrieve p12
        if (isSSKeygen) {
            CMS.debug(method + "onto SSK_STAGE_KEY_RETRIEVE");
            request.setExtData(IRequest.SSK_STAGE, IRequest.SSK_STAGE_KEY_RETRIEVE);
            request.setExtData("requestType", "recovery");
            request.setExtData("cert", theCert); //recognized by kra
            try {
                IConnector kraConnector = caService.getKRAConnector();

                if (kraConnector == null) {
                    String message = "KRA connector not configured";
                    CMS.debug(method + message);
                } else {
                    CMS.debug(method + "request");
                    kraConnector.send(request);

                    // check response
                    if (!request.isSuccess()) {
                        String message = "serverSide Keygen request failed";
                        CMS.debug(method + message);

                        if (getLocale(request) != null &&
                                request.getError(getLocale(request)) != null) {

                            if ((request.getError(getLocale(request))).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) { //Todo
                                CMS.debug(method + "set request status: REJECTED");
                                request.setRequestStatus(RequestStatus.REJECTED);
                                ca.getRequestQueue().updateRequest(request);
                            }
                            throw new ERejectException(
                                    request.getError(getLocale(request)));
                        } else {
                            throw new ERejectException(CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST")+ " check KRA log for detail");
                        }
                    }
/*
                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null));
*/
                }
            } catch (Exception e) {

                CMS.debug(method + e);
/*
                    signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                            auditSubjectID,
                            auditRequesterID,
                            requestId,
                            null,
                            e));
*/

                if (e instanceof ERejectException) {
                    throw (ERejectException) e;
                }
                throw new EProfileException(e);
            }
            CMS.debug(method + "isSSKeygen: response received from KRA");
            byte p12bytes[] = request.getExtDataInByteArray("pkcs12");
            if (p12bytes != null) {
                CMS.debug(method + "p12bytes not null");
            } else {
                CMS.debug(method + "p12bytes null");
            }
        }

        long endTime = CMS.getCurrentDate().getTime();

        String initiative = AuditFormat.FROMAGENT
                          + " userID: "
                          + (String) sc.get(SessionContext.USER_ID);
        String authMgr = (String) sc.get(SessionContext.AUTH_MANAGER_ID);

        ILogger logger = CMS.getLogger();
        if (logger != null) {
            logger.log(ILogger.EV_AUDIT,
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
        Enumeration<String> updaterIds = getProfileUpdaterIds();
        while (updaterIds.hasMoreElements()) {
            String updaterId = updaterIds.nextElement();
            IProfileUpdater updater = getProfileUpdater(updaterId);
            updater.update(request, RequestStatus.COMPLETE);
        }

        // set value for predicate value - checking in getRule
        if (CMS.isEncryptionCert(theCert))
            request.setExtData("isEncryptionCert", "true");
        else
            request.setExtData("isEncryptionCert", "false");
    }

}
