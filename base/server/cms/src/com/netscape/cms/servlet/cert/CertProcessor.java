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
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmsutil.ldap.LDAPUtil;

public class CertProcessor extends CAProcessor {

    public CertProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    protected void setCredentialsIntoContext(HttpServletRequest request, IProfileAuthenticator authenticator,
            IProfileContext ctx) {
        Enumeration<String> authIds = authenticator.getValueNames();

        if (authIds != null) {
            CMS.debug("CertRequestSubmitter:setCredentialsIntoContext() authNames not null");
            while (authIds.hasMoreElements()) {
                String authName = authIds.nextElement();

                CMS.debug("CertRequestSubmitter:setCredentialsIntoContext() authName:" +
                        authName);
                if (request.getParameter(authName) != null) {
                    CMS.debug("CertRequestSubmitter:setCredentialsIntoContext() authName found in request");
                    ctx.set(authName, request.getParameter(authName));
                } else {
                    CMS.debug("CertRequestSubmitter:setCredentialsIntoContext() authName not found in request");
                }
            }
        } else {
            CMS.debug("CertRequestSubmitter:setCredentialsIntoContext() authIds` null");
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

    /*
     * fill input info from orig request to the renew request.
     * This is expected to be used by renewal where the request
     * is retrieved from request record
     */
    private void setInputsIntoRequest(IRequest request, IProfile profile, IRequest req, Locale locale) {
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
                    CMS.debug("CertRequestSubmitter: setInputsIntoRequest() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        CMS.debug("CertRequestSubmitter: setInputsIntoRequest() getvalue() failed: " + e.toString());
                    }

                    if (inputValue != null) {
                        CMS.debug("CertRequestSubmitter: setInputsIntoRequest() setting value in ctx:" + inputValue);
                        req.setExtData(inputName, inputValue);
                    } else {
                        CMS.debug("CertRequestSubmitter: setInputsIntoRequest() value null");
                    }
                }
            }
        }

    }

    protected String codeToReason(Locale locale, String errorCode) {
        if (errorCode == null) return null;
        if (errorCode.equals("1")) {
            return CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR");
        } else if (errorCode.equals("2")) {
            return CMS.getUserMessage(locale, "CMS_PROFILE_DEFERRED");
        } else if (errorCode.equals("3")) {
            return CMS.getUserMessage(locale, "CMS_PROFILE_REJECTED");
        }
        return null;
    }

    protected String submitRequests(Locale locale, IProfile profile, IAuthToken authToken, IRequest[] reqs) {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = ILogger.UNIDENTIFIED;
        String auditInfoCertValue = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String errorCode = null;
        String errorReason = null;

        for (IRequest req : reqs) {
            try {
                // reset the "auditRequesterID"
                auditRequesterID = auditRequesterID(req);

                // print request debug
                if (req != null) {
                    Enumeration<String> reqKeys = req.getExtDataKeys();
                    while (reqKeys.hasMoreElements()) {
                        String reqKey = reqKeys.nextElement();
                        String reqVal = req.getExtDataInString(reqKey);
                        if (reqVal != null) {
                            CMS.debug("CertRequestSubmitter: key=$request." + reqKey + "$ value=" + reqVal);
                        }
                    }
                }

                profile.submit(authToken, req);
                req.setRequestStatus(RequestStatus.COMPLETE);

                // reset the "auditInfoCertValue"
                auditInfoCertValue = auditInfoCertValue(req);

                if (auditInfoCertValue != null) {
                    if (!(auditInfoCertValue.equals(
                            ILogger.SIGNED_AUDIT_EMPTY_VALUE))) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.SUCCESS,
                                auditRequesterID,
                                ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                auditInfoCertValue);

                        audit(auditMessage);
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

                CMS.debug("CertRequestSubmitter: submit " + e.toString());
                errorCode = "2";
                errorReason = CMS.getUserMessage(locale, "CMS_PROFILE_DEFERRED", e.toString());

                // do NOT store a message in the signed audit log file
                // as this errorCode indicates that a process has been
                // deferred for manual acceptance/cancellation/rejection
            } catch (ERejectException e) {
                // return error to the user
                req.setRequestStatus(RequestStatus.REJECTED);
                CMS.debug("CertRequestSubmitter: submit " + e.toString());
                errorCode = "3";
                errorReason = CMS.getUserMessage(locale, "CMS_PROFILE_REJECTED", e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        errorReason);

                audit(auditMessage);
            } catch (Throwable e) {
                // return error to the user
                e.printStackTrace();
                CMS.debug("CertRequestSubmitter: submit " + e.toString());
                errorCode = "1";
                errorReason = CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR");
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        errorReason);

                audit(auditMessage);
            }

            try {
                if (errorCode == null) {
                    profile.getRequestQueue().markAsServiced(req);
                } else {
                    profile.getRequestQueue().updateRequest(req);
                }
            } catch (EBaseException e) {
                e.printStackTrace();
                CMS.debug("CertRequestSubmitter: updateRequest " + e.toString());
            }
        }
        return errorCode;
    }

    protected void populateRequests(CertEnrollmentRequest data, boolean isRenewal,
            Locale locale, Date origNotAfter, String origSubjectDN, IRequest origReq, String profileId,
            IProfile profile, IProfileContext ctx, IProfileAuthenticator authenticator, IAuthToken authToken,
            IRequest[] reqs) throws EBaseException {
        for (IRequest req : reqs) {
            boolean fromRA = false;
            String uid = "";

            // adding parameters to request
            if (isRenewal) {
                setInputsIntoRequest(origReq, profile, req, locale);
                req.setExtData("origNotAfter", BigInteger.valueOf(origNotAfter.getTime()));
                req.setExtData(IProfileAuthenticator.AUTHENTICATED_NAME, origSubjectDN);
                req.setRequestType("renewal");
            } else {
                setInputsIntoRequest(data, profile, req);
            }

            // serial auth token into request
            if (authToken != null) {
                Enumeration<String> tokenNames = authToken.getElements();
                while (tokenNames.hasMoreElements()) {
                    String tokenName = tokenNames.nextElement();
                    String[] tokenVals = authToken.getInStringArray(tokenName);
                    if (tokenVals != null) {
                        for (int i = 0; i < tokenVals.length; i++) {
                            req.setExtData(ARG_AUTH_TOKEN + "." + tokenName + "[" + i + "]", tokenVals[i]);
                        }
                    } else {
                        String tokenVal = authToken.getInString(tokenName);
                        if (tokenVal != null) {
                            req.setExtData(ARG_AUTH_TOKEN + "." + tokenName, tokenVal);
                            // if RA agent, auto assign the request
                            if (tokenName.equals("uid"))
                                uid = tokenVal;
                            if (tokenName.equals("group") && tokenVal.equals("Registration Manager Agents")) {
                                fromRA = true;
                            }
                        }
                    }
                }
            }

            if (fromRA) {
                CMS.debug("CertRequestSubmitter: request from RA: " + uid);
                req.setExtData(ARG_REQUEST_OWNER, uid);
            }

            // put profile framework parameters into the request
            req.setExtData(ARG_PROFILE, "true");
            req.setExtData(ARG_PROFILE_ID, profileId);
            if (isRenewal)
                req.setExtData(ARG_RENEWAL_PROFILE_ID, data.getProfileId());
            req.setExtData(ARG_PROFILE_APPROVED_BY, profile.getApprovedBy());
            String setId = profile.getPolicySetId(req);

            if (setId == null) {
                // no profile set found
                CMS.debug("CertRequestSubmitter: no profile policy set found");
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_PROFILE_NO_POLICY_SET_FOUND"));
            }

            CMS.debug("CertRequestSubmitter profileSetid=" + setId);
            req.setExtData(ARG_PROFILE_SET_ID, setId);
            req.setExtData(ARG_PROFILE_REMOTE_HOST, data.getRemoteHost());
            req.setExtData(ARG_PROFILE_REMOTE_ADDR, data.getRemoteAddr());

            CMS.debug("CertRequestSubmitter: request " + req.getRequestId().toString());

            CMS.debug("CertRequestSubmitter: populating request inputs");
            // give authenticator a chance to populate the request
            if (authenticator != null) {
                authenticator.populate(authToken, req);
            }
            profile.populateInput(ctx, req);
            profile.populate(req);
        }
    }

}
