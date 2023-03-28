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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.cert;

import java.math.BigInteger;
import java.security.Principal;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CertRequestProcessedEvent;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cms.tomcat.ExternalPrincipal;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmsutil.ldap.LDAPUtil;

public class CertProcessor extends CAProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertProcessor.class);

    public CertProcessor(String id, Locale locale) {
        super(id, locale);
    }

    protected void setCredentialsIntoContext(
            HttpServletRequest request,
            AuthCredentials creds,
            AuthManager authenticator,
            Map<String, String> ctx) {

        Enumeration<String> names = authenticator.getValueNames();
        if (names == null) {
            logger.warn("CertProcessor: No authenticator credentials required");
            return;
        }

        logger.debug("CertProcessor: Authentication credentials:");
        while (names.hasMoreElements()) {
            String name = names.nextElement();

            Object value;
            if (creds == null) {
                value = request.getParameter(name);
            } else {
                value = creds.get(name);
            }

            if (value == null) continue;
            ctx.put(name, value.toString());
        }
    }

    private void setInputsIntoRequest(CertEnrollmentRequest data, Profile profile, Request req) {
        // put profile inputs into a local map
        HashMap<String, String> dataInputs = new HashMap<>();
        for (ProfileInput input : data.getInputs()) {
            for (ProfileAttribute attr : input.getAttributes()) {
                dataInputs.put(attr.getName(), attr.getValue());
            }
        }

        // iterate over inputs in profile
        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                if (inputNames != null) {
                    while (inputNames.hasMoreElements()) {
                        String inputName = inputNames.nextElement();
                        if (dataInputs.containsKey(inputName)) {
                            // special characters in subject names parameters must be escaped
                            if (inputName.matches("^sn_.*")) {
                                req.setExtData(inputName,
                                        LDAPUtil.escapeRDNValue(dataInputs.get(inputName)));
                            } else {
                                req.setExtData(inputName, dataInputs.get(inputName));
                            }
                        }
                    }
                }
            }
        }
    }

    private static void setAuthTokenIntoRequest(
            Request req, AuthToken authToken) {
        Enumeration<String> tokenNames = authToken.getElements();
        while (tokenNames.hasMoreElements()) {
            String tokenName = tokenNames.nextElement();
            String[] tokenVals = authToken.getInStringArray(tokenName);
            if (tokenVals != null) {
                for (int i = 0; i < tokenVals.length; i++) {
                    req.setExtData(
                        Request.AUTH_TOKEN_PREFIX
                            + "." + tokenName + "[" + i + "]"
                        , tokenVals[i]);
                }
            } else {
                String tokenVal = authToken.getInString(tokenName);
                if (tokenVal != null) {
                    req.setExtData(
                        Request.AUTH_TOKEN_PREFIX + "." + tokenName,
                        tokenVal);
                }
            }
        }

        // special processing of ExternalAuthToken / ExternalPrincipal
        if (authToken instanceof ExternalAuthToken) {
            Principal principal =
                ((ExternalAuthToken) authToken).getPrincipal();
            if (principal instanceof ExternalPrincipal) {
                HashMap<String, Object> m =
                    ((ExternalPrincipal) principal).getAttributes();
                for (String k : m.keySet()) {
                    req.setExtData(
                        Request.AUTH_TOKEN_PREFIX
                            + "." + "PRINCIPAL"
                            + "." + k
                        , m.get(k).toString()
                    );
                }
            }
        }
    }

    /*
     * fill input info from orig request to the renew request.
     * This is expected to be used by renewal where the request
     * is retrieved from request record
     */
    private void setInputsIntoRequest(Request request, Profile profile, Request req, Locale locale) {
        logger.debug("CertProcessor: setInputsIntoRequest()");
        // passing inputs into request
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();
                    String inputValue = "";
                    //logger.debug("CertProcessor: setInputsIntoRequest() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        logger.warn("CertProcessor: setInputsIntoRequest() getvalue() failed: " + e.toString());
                    }

                    if (inputValue != null) {
                        //logger.debug("CertProcessor: setInputsIntoRequest() setting value in ctx:" + inputValue);
                        req.setExtData(inputName, inputValue);
                    }/* else {
                        logger.warn("CertProcessor: setInputsIntoRequest() value null");
                    }*/
                }
            }
        }

    }

    protected String codeToReason(Locale locale, String errorCode, String errorString, RequestId requestId) {
        if (errorCode == null)
            return null;
        if (errorCode.equals("1")) {
            return CMS.getUserMessage(locale, "CMS_PROFILE_INTERNAL_ERROR", requestId.toString());
        } else if (errorCode.equals("2")) {
            return CMS.getUserMessage(locale, "CMS_PROFILE_DEFERRED", errorString);
        } else if (errorCode.equals("3")) {
            return CMS.getUserMessage(locale, "CMS_PROFILE_REJECTED", requestId.toString(), errorString);
        }
        return null;
    }

    protected String submitRequests(Locale locale, Profile profile, AuthToken authToken, Request[] reqs) {
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = ILogger.UNIDENTIFIED;
        String errorCode = null;
        String errorReason = null;

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

        for (Request req : reqs) {
            try {
                ConfigStore profileConf = profile.getConfigStore().getSubStore("auth", ConfigStore.class);
                boolean explicitApprovalRequired = profileConf.getBoolean("explicitApprovalRequired", false);

                // reset the "auditRequesterID"
                auditRequesterID = auditRequesterID(req);

                logger.info("CertProcessor: Processing certificate request:");

                if (req != null) {
                    Enumeration<String> reqKeys = req.getExtDataKeys();
                    while (reqKeys.hasMoreElements()) {
                        String reqKey = reqKeys.nextElement();
                        String reqVal = req.getExtDataInString(reqKey);
                        if (reqVal != null) {
                            logger.info("CertProcessor: - " + reqKey + ": " + reqVal);
                        }
                    }
                }

                logger.info("CertProcessor: Submitting certificate request to " + profile.getId() + " profile");

                profile.submit(authToken, req, explicitApprovalRequired);

                req.setRequestStatus(RequestStatus.COMPLETE);

                X509CertImpl x509cert = req.getExtDataInCert(Request.REQUEST_ISSUED_CERT);

                if (x509cert != null) {

                    auditor.log(CertRequestProcessedEvent.createSuccessEvent(
                            auditSubjectID,
                            auditRequesterID,
                            ILogger.SIGNED_AUDIT_ACCEPTANCE,
                            x509cert));
                }

            } catch (EDeferException e) {

                logger.warn("Certificate request deferred: " + e.getMessage());

                req.setRequestStatus(RequestStatus.PENDING);
                // need to notify
                RequestNotifier notify = engine.getRequestQueue().getPendingNotify();
                if (notify != null) {
                    notify.notify(req);
                }

                errorCode = "2";
                req.setExtData(Request.ERROR_CODE, errorCode);

                // do NOT store a message in the signed audit log file
                // as this errorCode indicates that a process has been
                // deferred for manual acceptance/cancellation/rejection

            } catch (ERejectException e) {

                logger.warn("Certificate request rejected: " + e.getMessage(), e);

                req.setRequestStatus(RequestStatus.REJECTED);

                errorCode = "3";
                req.setExtData(Request.ERROR, e.toString());
                req.setExtData(Request.ERROR_CODE, errorCode);

                auditor.log(CertRequestProcessedEvent.createFailureEvent(
                        auditSubjectID,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        codeToReason(locale, errorCode, e.toString(), req.getRequestId())));

            } catch (Throwable e) {

                logger.warn("Certificate request failed: " + e.getMessage(), e);

                errorCode = "1";
                errorReason = codeToReason(locale, errorCode, null, req.getRequestId());
                req.setExtData(Request.ERROR, errorReason);
                req.setExtData(Request.ERROR_CODE, errorCode);

                auditor.log(CertRequestProcessedEvent.createFailureEvent(
                        auditSubjectID,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        errorReason));
            }

            try {
                logger.info("Updating certificate request");

                if (errorCode == null) {
                    engine.getRequestQueue().markAsServiced(req);
                } else {
                    engine.getRequestRepository().updateRequest(req);
                }

            } catch (EBaseException e) {
                logger.warn("Unable to update certificate request: " + e.getMessage(), e);
            }
        }

        return errorCode;
    }

    protected void populateRequests(CertEnrollmentRequest data, boolean isRenewal,
            Locale locale, Date origNotAfter, String origSubjectDN, Request origReq, String profileId,
            Profile profile, Map<String, String> ctx, AuthManager authenticator, AuthToken authToken,
            Request[] reqs) throws Exception {

        for (Request req : reqs) {
            // adding parameters to request
            if (isRenewal) {
                setInputsIntoRequest(origReq, profile, req, locale);
                req.setExtData("origNotAfter", BigInteger.valueOf(origNotAfter.getTime()));
                req.setExtData(AuthManager.AUTHENTICATED_NAME, origSubjectDN);
                req.setRequestType("renewal");
            } else {
                setInputsIntoRequest(data, profile, req);
            }

            if (authToken != null) {
                setAuthTokenIntoRequest(req, authToken);

                // if RA agent, auto-assign the request
                String raGroupName = "Registration Manager Agents";
                if (raGroupName.equals(authToken.getInString(AuthToken.GROUP))) {
                    String uid = authToken.getInString(AuthToken.UID);
                    if (uid == null)
                        uid = "";
                    logger.debug("CertProcessor: request from RA: " + uid);
                    req.setExtData(ARG_REQUEST_OWNER, uid);
                }
            }

            // put profile framework parameters into the request
            req.setExtData(ARG_PROFILE, "true");
            req.setExtData(Request.PROFILE_ID, profileId);
            if (isRenewal)
                req.setExtData(ARG_RENEWAL_PROFILE_ID, data.getProfileId());
            req.setExtData(ARG_PROFILE_APPROVED_BY, profile.getApprovedBy());
            String setId = profile.getPolicySetId(req);

            if (setId == null) {
                // no profile set found
                logger.error("CertProcessor: no profile policy set found");
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_PROFILE_NO_POLICY_SET_FOUND"));
            }

            logger.debug("CertProcessor: profileSetid=" + setId);
            req.setExtData(ARG_PROFILE_SET_ID, setId);
            req.setExtData(ARG_PROFILE_REMOTE_HOST, data.getRemoteHost());
            req.setExtData(ARG_PROFILE_REMOTE_ADDR, data.getRemoteAddr());

            logger.debug("CertProcessor: request " + req.getRequestId());

            logger.debug("CertProcessor: populating request inputs");
            // give authenticator a chance to populate the request
            if (authenticator != null) {
                authenticator.populate(authToken, req);
            }
            profile.populateInput(ctx, req);
            profile.populate(req);
        }
    }

}
