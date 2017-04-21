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

import javax.servlet.http.HttpServletRequest;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CertRequestProcessedEvent;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cms.tomcat.ExternalPrincipal;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.security.x509.X509CertImpl;

public class CertProcessor extends CAProcessor {

    public CertProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    protected void setCredentialsIntoContext(
            HttpServletRequest request,
            AuthCredentials creds,
            IProfileAuthenticator authenticator,
            IProfileContext ctx) {

        Enumeration<String> names = authenticator.getValueNames();
        if (names == null) {
            CMS.debug("CertProcessor: No authenticator credentials required");
            return;
        }

        CMS.debug("CertProcessor: Authentication credentials:");
        while (names.hasMoreElements()) {
            String name = names.nextElement();

            Object value;
            if (creds == null) {
                value = request.getParameter(name);
            } else {
                value = creds.get(name);
            }

            if (value == null) continue;
            ctx.set(name, value.toString());
        }
    }

    private void setInputsIntoRequest(CertEnrollmentRequest data, IProfile profile, IRequest req) {
        // put profile inputs into a local map
        HashMap<String, String> dataInputs = new HashMap<String, String>();
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
                IProfileInput profileInput = profile.getProfileInput(inputId);
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
            IRequest req, IAuthToken authToken) {
        Enumeration<String> tokenNames = authToken.getElements();
        while (tokenNames.hasMoreElements()) {
            String tokenName = tokenNames.nextElement();
            String[] tokenVals = authToken.getInStringArray(tokenName);
            if (tokenVals != null) {
                for (int i = 0; i < tokenVals.length; i++) {
                    req.setExtData(
                        IRequest.AUTH_TOKEN_PREFIX
                            + "." + tokenName + "[" + i + "]"
                        , tokenVals[i]);
                }
            } else {
                String tokenVal = authToken.getInString(tokenName);
                if (tokenVal != null) {
                    req.setExtData(
                        IRequest.AUTH_TOKEN_PREFIX + "." + tokenName,
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
                        IRequest.AUTH_TOKEN_PREFIX
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
    private void setInputsIntoRequest(IRequest request, IProfile profile, IRequest req, Locale locale) {
        CMS.debug("CertProcessor: setInputsIntoRequest()");
        // passing inputs into request
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();
                    String inputValue = "";
                    //CMS.debug("CertProcessor: setInputsIntoRequest() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        CMS.debug("CertProcessor: setInputsIntoRequest() getvalue() failed: " + e.toString());
                    }

                    if (inputValue != null) {
                        //CMS.debug("CertProcessor: setInputsIntoRequest() setting value in ctx:" + inputValue);
                        req.setExtData(inputName, inputValue);
                    }/* else {
                        CMS.debug("CertProcessor: setInputsIntoRequest() value null");
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

    protected String submitRequests(Locale locale, IProfile profile, IAuthToken authToken, IRequest[] reqs) {
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = ILogger.UNIDENTIFIED;
        String errorCode = null;
        String errorReason = null;

        for (IRequest req : reqs) {
            try {
                // reset the "auditRequesterID"
                auditRequesterID = auditRequesterID(req);

                /* print request debug
                CMS.debug("CertProcessor: Request:");
                if (req != null) {
                    Enumeration<String> reqKeys = req.getExtDataKeys();
                    while (reqKeys.hasMoreElements()) {
                        String reqKey = reqKeys.nextElement();
                        String reqVal = req.getExtDataInString(reqKey);
                        if (reqVal != null) {
                            CMS.debug("CertProcessor: - " + reqKey + ": " + reqVal);
                        }
                    }
                }
                */

                CMS.debug("CertProcessor.submitRequest: calling profile submit");
                profile.submit(authToken, req);
                req.setRequestStatus(RequestStatus.COMPLETE);

                X509CertImpl x509cert = req.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
                String auditInfoCertValue = auditInfoCertValue(x509cert);

                if (auditInfoCertValue != null) {
                    if (!(auditInfoCertValue.equals(
                            ILogger.SIGNED_AUDIT_EMPTY_VALUE))) {

                        audit(new CertRequestProcessedEvent(
                                auditSubjectID,
                                ILogger.SUCCESS,
                                auditRequesterID,
                                ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                auditInfoCertValue));
                    }
                }
            } catch (EDeferException e) {
                // return defer message to the user
                req.setRequestStatus(RequestStatus.PENDING);
                // need to notify
                INotify notify = profile.getRequestQueue().getPendingNotify();
                if (notify != null) {
                    notify.notify(req);
                }

                CMS.debug("CertProcessor: submit " + e);
                errorCode = "2";
                req.setExtData(IRequest.ERROR_CODE, errorCode);

                // do NOT store a message in the signed audit log file
                // as this errorCode indicates that a process has been
                // deferred for manual acceptance/cancellation/rejection
            } catch (ERejectException e) {
                // return error to the user
                req.setRequestStatus(RequestStatus.REJECTED);
                CMS.debug("CertProcessor: submit " + e);
                errorCode = "3";
                req.setExtData(IRequest.ERROR, e.toString());
                req.setExtData(IRequest.ERROR_CODE, errorCode);

                audit(new CertRequestProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        codeToReason(locale, errorCode, e.toString(), req.getRequestId())));

            } catch (Throwable e) {
                // return error to the user
                CMS.debug(e);
                CMS.debug("CertProcessor: submit " + e);
                errorCode = "1";
                errorReason = codeToReason(locale, errorCode, null, req.getRequestId());
                req.setExtData(IRequest.ERROR, errorReason);
                req.setExtData(IRequest.ERROR_CODE, errorCode);

                audit(new CertRequestProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        errorReason));
            }

            try {
                if (errorCode == null) {
                    profile.getRequestQueue().markAsServiced(req);
                } else {
                    profile.getRequestQueue().updateRequest(req);
                }
            } catch (EBaseException e) {
                CMS.debug(e);
                CMS.debug("CertProcessor: updateRequest " + e);
            }
        }
        return errorCode;
    }

    protected void populateRequests(CertEnrollmentRequest data, boolean isRenewal,
            Locale locale, Date origNotAfter, String origSubjectDN, IRequest origReq, String profileId,
            IProfile profile, IProfileContext ctx, IProfileAuthenticator authenticator, IAuthToken authToken,
            IRequest[] reqs) throws EBaseException {
        for (IRequest req : reqs) {
            // adding parameters to request
            if (isRenewal) {
                setInputsIntoRequest(origReq, profile, req, locale);
                req.setExtData("origNotAfter", BigInteger.valueOf(origNotAfter.getTime()));
                req.setExtData(IProfileAuthenticator.AUTHENTICATED_NAME, origSubjectDN);
                req.setRequestType("renewal");
            } else {
                setInputsIntoRequest(data, profile, req);
            }

            if (authToken != null) {
                setAuthTokenIntoRequest(req, authToken);

                // if RA agent, auto-assign the request
                String raGroupName = "Registration Manager Agents";
                if (raGroupName.equals(authToken.getInString(IAuthToken.GROUP))) {
                    String uid = authToken.getInString(IAuthToken.UID);
                    if (uid == null)
                        uid = "";
                    CMS.debug("CertProcessor: request from RA: " + uid);
                    req.setExtData(ARG_REQUEST_OWNER, uid);
                }
            }

            // put profile framework parameters into the request
            req.setExtData(ARG_PROFILE, "true");
            req.setExtData(IRequest.PROFILE_ID, profileId);
            if (isRenewal)
                req.setExtData(ARG_RENEWAL_PROFILE_ID, data.getProfileId());
            req.setExtData(ARG_PROFILE_APPROVED_BY, profile.getApprovedBy());
            String setId = profile.getPolicySetId(req);

            if (setId == null) {
                // no profile set found
                CMS.debug("CertProcessor: no profile policy set found");
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_PROFILE_NO_POLICY_SET_FOUND"));
            }

            CMS.debug("CertProcessor: profileSetid=" + setId);
            req.setExtData(ARG_PROFILE_SET_ID, setId);
            req.setExtData(ARG_PROFILE_REMOTE_HOST, data.getRemoteHost());
            req.setExtData(ARG_PROFILE_REMOTE_ADDR, data.getRemoteAddr());

            CMS.debug("CertProcessor: request " + req.getRequestId());

            CMS.debug("CertProcessor: populating request inputs");
            // give authenticator a chance to populate the request
            if (authenticator != null) {
                authenticator.populate(authToken, req);
            }
            profile.populateInput(ctx, req);
            profile.populate(req);
        }
    }

}
