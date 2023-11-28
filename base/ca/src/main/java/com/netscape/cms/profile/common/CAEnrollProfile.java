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
import java.util.Date;
import java.util.Enumeration;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICAService;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.logging.event.ServerSideKeygenEnrollKeyRetrievalEvent;
import com.netscape.certsrv.logging.event.ServerSideKeygenEnrollKeygenEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.updater.IProfileUpdater;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements a Certificate Manager enrollment
 * profile.
 *
 * @author cfu - Server-Side Keygen Enrollment implementation
 * @version $Revision$, $Date$
 */
public class CAEnrollProfile extends EnrollProfile {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAEnrollProfile.class);

    public CAEnrollProfile() {
    }

    @Override
    public IAuthority getAuthority() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getCA();
    }

    @Override
    public X500Name getIssuerName() {
        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        return ca.getX500Name();
    }

    /**
     * Called after initialization. It populates default
     * policies, inputs, and outputs.
     */
    public void populate() throws EBaseException {
    }

    @Override
    public void execute(IRequest request)
            throws EProfileException, ERejectException {

        String method = "CAEnrollProfile: execute: ";
        long startTime = new Date().getTime();

        if (!isEnable()) {
            logger.error("CAEnrollProfile: Profile Not Enabled");
            throw new EProfileException("Profile Not Enabled");
        }

        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(request);
        RequestId requestId = request.getRequestId();


        logger.debug("CAEnrollProfile: execute request ID " + requestId.toString());

        CAEngine engine = CAEngine.getInstance();
        ICertificateAuthority ca = (ICertificateAuthority) getAuthority();

        ICAService caService = (ICAService) ca.getCAService();
        if (caService == null) {
            throw new EProfileException("No CA Service");
        }

        // if isServerSideKeygen, send keygen request to KRA
        boolean isSSKeygen = false;
        String isSSKeygenStr = request.getExtDataInString("isServerSideKeygen");
        if (isSSKeygenStr != null && isSSKeygenStr.equalsIgnoreCase("true")) {
            logger.debug(method + "isServerSideKeygen = true");
            isSSKeygen = true;
        } else {
            logger.debug(method + "isServerSideKeygen = false");
        }

        // prepare for auditing
        CertificateSubjectName reqSubj =
                request.getExtDataInCertSubjectName(IRequest.REQUEST_SUBJECT_NAME);
        String clientId = "unknown serverKeyGenUser";
        if (reqSubj != null) {
            X500Name xN = reqSubj.getX500Name();
            clientId = xN.toString();
            logger.debug(method + "clientId = " + clientId);
        }

        // if PKI Archive Option present, send this request
        // to DRM
        byte optionsData[] = request.getExtDataInByteArray(IRequest.REQUEST_ARCHIVE_OPTIONS);

        byte[] transWrappedSessionKey = null;
        byte[] sessionWrappedPassphrase = null;
        if (isSSKeygen) { // Server-Side Keygen enrollment
            request.setExtData(IRequest.SSK_STAGE, IRequest.SSK_STAGE_KEYGEN);

            /*
             * temporarily remove the items not needed for SSK_STAGE_KEYGEN
             * so not to pass them to KRA.
             * They will be put back at SSK_STAGE_KEY_RETRIEVE below
             */
            transWrappedSessionKey = request.getExtDataInByteArray("serverSideKeygenP12PasswdTransSession");

            sessionWrappedPassphrase = request.getExtDataInByteArray("serverSideKeygenP12PasswdEnc");

            request.setExtData("serverSideKeygenP12PasswdTransSession", "");
            request.deleteExtData("serverSideKeygenP12PasswdTransSession");
            request.setExtData("serverSideKeygenP12PasswdEnc", "");
            request.deleteExtData("serverSideKeygenP12PasswdEnc");

            try {
                IConnector kraConnector = caService.getKRAConnector();

                if (kraConnector == null) {
                    String message = "KRA connector not configured";
                    logger.debug(method + message);

                    throw new EProfileException(message);
                } else {
                    logger.debug(method + "request");
                    kraConnector.send(request);

                    // check response
                    if (!request.isSuccess()) {
                        String message = "serverSide Keygen request failed";
                        logger.debug(method + message);

                        if (getLocale(request) != null &&
                                request.getError(getLocale(request)) != null) {

                            if ((request.getError(getLocale(request))).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) { //Todo
                                logger.debug(method + "set request status: REJECTED");
                                request.setRequestStatus(RequestStatus.REJECTED);
                                engine.getRequestQueue().updateRequest(request);
                            }
                            throw new ERejectException(
                                    request.getError(getLocale(request)));
                        } else {
                            throw new ERejectException(CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST")+ " check KRA log for detail");
                        }
                    }
                    // TODO: perhaps have Server-Side Keygen enrollment audit
                    // event, or expand AsymKeyGenerationEvent
                    signedAuditLogger.log(new ServerSideKeygenEnrollKeygenEvent(
                            auditSubjectID,
                            "Success",
                            requestId,
                            clientId));
                }
            } catch (Exception e) {

                logger.debug(method + e);

                signedAuditLogger.log(new ServerSideKeygenEnrollKeygenEvent(
                            auditSubjectID,
                            "Failure",
                            requestId,
                            clientId));

                if (e instanceof ERejectException) {
                    throw (ERejectException) e;
                }
                throw new EProfileException(e);
            }
        } else if ((optionsData != null) && (!request.getRequestType().equals(IRequest.RENEWAL_REQUEST))) {
            // do not archive keys for renewal requests
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
                                    engine.getRequestQueue().updateRequest(request);
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
        // logger.debug(method + " before: X509CertInfo info = " + info.toString());

        if (isSSKeygen) {
            try {
                String pubKeyStr = request.getExtDataInString("public_key");
                if (pubKeyStr == null) {
                    throw new EProfileException("Server-Side Keygen enrollment failed to retrieve public_key from KRA");
                }
                // logger.debug(method + "pubKeyStr = " + pubKeyStr);
                byte[] pubKeyB = CryptoUtil.base64Decode(pubKeyStr);
                CertificateX509Key certKey = new CertificateX509Key(
                    new ByteArrayInputStream(pubKeyB));

                // replace fake key in info
                CertificateX509Key infokey = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
                if (infokey != null) {
                    X509Key key = (X509Key)
                            infokey.get(CertificateX509Key.KEY);
                    // logger.debug(method + "key = " + key.toString());
                    // a placeholder temporary fake key was put in
                    // ServerKeygenUserKeyDefault
                    info.delete(X509CertInfo.KEY);
                    // logger.debug(method + "fake key deleted");
                }

                // adding real key
                info.set(X509CertInfo.KEY, certKey);

                // fake key replaced;
                // need to compute/replace SKI as well if present

                SubjectKeyIdentifierExtension ext = (SubjectKeyIdentifierExtension) CertUtils.getExtension(PKIXExtensions.SubjectKey_Id.toString(), info);
                if (ext != null) {
                    logger.debug(method + "found SubjectKey_Id extension");
                    /*
                     * determine message digest algorithm:
                     * the "old_ski" was generated based on the profile
                     * from the "fake key",
                     * so we could use it's length to determine the size
                     * of the new hash.
                     *
                     * Message digest can be controlled by the messageDigest
                     * parameter in the subjectKeyIdentifier extension in a
                     * profile. e.g.
                     * policyset.caCertSet.8.default.params.messageDigest=SHA-256
                     */
                    String messageDigest = "SHA-1"; // default; len==20
                    KeyIdentifier old_ski = null;
                    try {
                        old_ski = (KeyIdentifier) ext.get(SubjectKeyIdentifierExtension.KEY_ID);
                    } catch (IOException e) {
                        old_ski = null;
                    }
                    if (old_ski != null) { 
                        byte[] old_ski_val = old_ski.getIdentifier();
                        if (old_ski_val != null) {
                            int old_ski_len = old_ski_val.length;

                            if (old_ski_len == 32) {
                                messageDigest = "SHA-256";
                            } else if (old_ski_len == 48) {
                                messageDigest = "SHA-384";
                            } else if (old_ski_len == 64) {
                                messageDigest = "SHA-512";
                            }
                        }
                    }
                    logger.debug(method + "ServerSideKeygen message digest alg == " + messageDigest);
                    // compute keyId
                    X509Key realkey = (X509Key)
                            certKey.get(CertificateX509Key.KEY);
                    byte[] hash = CryptoUtil.generateKeyIdentifier(realkey.getKey(), messageDigest);
                    int new_ski_len = hash.length;
                    logger.debug(method + "ServerSideKeygen hash len = " + new_ski_len);
                    KeyIdentifier id = new KeyIdentifier(hash);
                    SubjectKeyIdentifierExtension skiExt =
                            new SubjectKeyIdentifierExtension(id.getIdentifier());

                    // replace it
                    CertUtils.replaceExtension(PKIXExtensions.SubjectKey_Id.toString(), skiExt, info);
                    logger.debug(method + " SubjectKey_Id replaced");

                    // logger.debug(method + " after replacement: X509CertInfo info = " + info.toString());
                }/* else
                    Not every cert needs an SKI
                    logger.debug(method + "did not find SubjectKey_Id");
                  */

            } catch (IOException e) {
                logger.debug(method + e);
                throw new EProfileException(e);
            } catch (CertificateException e) {
                logger.debug(method + e);
                throw new EProfileException(e);
            } catch (Exception e) {
                logger.debug(method + e);
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
            logger.error("CAEnrollProfile: " + e.getMessage(), e);
            throw new EProfileException(e);
        }

        request.setExtData(REQUEST_ISSUED_CERT, theCert);

        // cert issued, now retrieve p12
        if (isSSKeygen) {
            logger.debug(method + "onto SSK_STAGE_KEY_RETRIEVE");
            request.setExtData(IRequest.SSK_STAGE, IRequest.SSK_STAGE_KEY_RETRIEVE);
            request.setExtData(IRequest.REQ_STATUS, "begin");
            request.setExtData("requestType", "recovery");

            // putting them back
            request.setExtData("serverSideKeygenP12PasswdEnc", sessionWrappedPassphrase);
            request.setExtData("serverSideKeygenP12PasswdTransSession", transWrappedSessionKey);

            // debug
            // CertUtils.printRequestContent(request);

            try {
                IConnector kraConnector = caService.getKRAConnector();

                if (kraConnector == null) {
                    String message = "KRA connector not configured";
                    logger.debug(method + message);
                } else {
                    logger.debug(method + "request");
                    kraConnector.send(request);

                    // check response
                    if (!request.isSuccess()) {
                        String message = "serverSide Keygen request failed";
                        logger.debug(method + message);

                        if (getLocale(request) != null &&
                                request.getError(getLocale(request)) != null) {

                            if ((request.getError(getLocale(request))).equals(CMS.getUserMessage("CMS_KRA_INVALID_TRANSPORT_CERT"))) { //Todo
                                logger.debug(method + "set request status: REJECTED");
                                request.setRequestStatus(RequestStatus.REJECTED);
                                engine.getRequestQueue().updateRequest(request);
                            }
                            throw new ERejectException(
                                    request.getError(getLocale(request)));
                        } else {
                            throw new ERejectException(CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST")+ " check KRA log for detail");
                        }
                    }

                    signedAuditLogger.log(new ServerSideKeygenEnrollKeyRetrievalEvent(
                                auditSubjectID,
                                "Success",
                                requestId,
                                clientId));
                }
            } catch (Exception e) {

                logger.debug(method + e);

                signedAuditLogger.log(new ServerSideKeygenEnrollKeyRetrievalEvent(
                            auditSubjectID,
                            "Failure",
                            requestId,
                            clientId));

                if (e instanceof ERejectException) {
                    throw (ERejectException) e;
                }
                throw new EProfileException(e);
            } finally {
                // cfu TODO: clean them
                    request.setExtData("serverSideKeygenP12PasswdTransSession", "");
                    request.deleteExtData("serverSideKeygenP12PasswdTransSession");
                    request.setExtData("serverSideKeygenP12PasswdEnc", "");
                    request.deleteExtData("serverSideKeygenP12PasswdEnc");
            }
            logger.debug(method + "isSSKeygen: response received from KRA");
        }
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
