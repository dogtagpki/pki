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
package com.netscape.cms.servlet.profile;


import java.util.*;
import java.security.cert.*;
import javax.servlet.*;
import javax.servlet.http.*;

import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.template.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.certsrv.logging.*;
import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cmsutil.xml.*;
import com.netscape.cmsutil.util.*;
import org.w3c.dom.*;
import netscape.security.x509.*;


/**
 * This servlet submits end-user request into the profile framework.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ProfileSubmitServlet extends ProfileServlet {

    private static final String ARG_AUTH_TOKEN = "auth_token";
    private static final String ARG_REQUEST_OWNER = "requestOwner";
    private static final String PROP_PROFILE_ID = "profileId";
    private static final String PROP_AUTHORITY_ID = "authorityId";
    private final static String SUCCESS = "0";
    private final static String FAILED = "1";

    private String mProfileId = null;
    private String mProfileSubId = null;
    private String mReqType = null;
    private String mAuthorityId = null;

    private final static byte EOL[] = { Character.LINE_SEPARATOR };
    private final static String[]
        SIGNED_AUDIT_AUTOMATED_REJECTION_REASON = new String[] {
            
            /* 0 */ "automated profile cert request rejection:  "
            + "indeterminate reason for inability to process "
            + "cert request due to an EBaseException"
        };
    private final static String LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED =
        "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";

    public ProfileSubmitServlet() {
    }

    /**
     * initialize the servlet. And instance of this servlet can 
     * be set up to always issue certificates against a certain profile
     * by setting the 'profileId' configuration in the servletConfig
     * If not, the user must specify the profileID when submitting the request
     * 
     * "ImportCert.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mAuthorityId = sc.getInitParameter(PROP_AUTHORITY_ID);
        mProfileId = sc.getInitParameter(PROP_PROFILE_ID);
    }

    private void setInputsIntoContext(HttpServletRequest request, IProfile profile, IProfileContext ctx) {
        // passing inputs into context
        Enumeration inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = (String) inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = (String) inputNames.nextElement();

                    if (request.getParameter(inputName) != null) {
                        ctx.set(inputName, request.getParameter(inputName));
                    }
                }
            }
        }

    }

    private void setCredentialsIntoContext(HttpServletRequest request, IProfileAuthenticator authenticator, IProfileContext ctx) {
        Enumeration authIds = authenticator.getValueNames();

        if (authIds != null) {
            while (authIds.hasMoreElements()) {
                String authName = (String) authIds.nextElement();

                if (request.getParameter(authName) != null) {
                    ctx.set(authName, request.getParameter(authName));
                }
            }
        }
    }

    public IAuthToken authenticate(IProfileAuthenticator authenticator,
        HttpServletRequest request)  throws EBaseException {
        AuthCredentials credentials = new AuthCredentials();

        // build credential
        Enumeration authNames = authenticator.getValueNames();

        if (authNames != null) {
            while (authNames.hasMoreElements()) {
                String authName = (String) authNames.nextElement();

                credentials.set(authName, request.getParameter(authName));
            }
        }

        credentials.set("clientHost", request.getRemoteHost());
        IAuthToken authToken = authenticator.authenticate(credentials);

        SessionContext sc = SessionContext.getContext();
        if (sc != null) { 
          sc.put(SessionContext.AUTH_MANAGER_ID, authenticator.getName()); 
          String userid = authToken.getInString(IAuthToken.USER_ID);
          if (userid != null) { 
            sc.put(SessionContext.USER_ID, userid); 
          }
        }

        return authToken;
    }

    private void setInputsIntoRequest(HttpServletRequest request, IProfile profile, IRequest req) {
        Enumeration inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = (String) inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration inputNames = profileInput.getValueNames();

                if (inputNames != null) {
                    while (inputNames.hasMoreElements()) {
                        String inputName = (String) inputNames.nextElement();

                        if (request.getParameter(inputName) != null) {
                            req.setExtData(inputName, request.getParameter(inputName));
                        }
                    }
                }
            }
        }
    }

    private void setOutputIntoArgs(IProfile profile, ArgList outputlist, Locale locale, IRequest req) {
        Enumeration outputIds = profile.getProfileOutputIds();

        if (outputIds != null) {
            while (outputIds.hasMoreElements()) {
                String outputId = (String) outputIds.nextElement();
                IProfileOutput profileOutput = profile.getProfileOutput(outputId);

                Enumeration outputNames = profileOutput.getValueNames();

                if (outputNames != null) {
                    while (outputNames.hasMoreElements()) {
                        ArgSet outputset = new ArgSet();
                        String outputName = (String) outputNames.nextElement();
                        IDescriptor outputDesc = 
                            profileOutput.getValueDescriptor(locale, outputName);

                        if (outputDesc == null)
                            continue;
                        String outputSyntax = outputDesc.getSyntax();
                        String outputConstraint = outputDesc.getConstraint();
                        String outputValueName = outputDesc.getDescription(locale);
                        String outputValue = null;

                        try {
                            outputValue = profileOutput.getValue(outputName, 
                                        locale, req);
                        } catch (EProfileException e) {
                            CMS.debug("ProfileSubmitServlet: " + e.toString());
                        }

                        outputset.set(ARG_OUTPUT_ID, outputName);
                        outputset.set(ARG_OUTPUT_SYNTAX, outputSyntax);
                        outputset.set(ARG_OUTPUT_CONSTRAINT, outputConstraint);
                        outputset.set(ARG_OUTPUT_NAME, outputValueName);
                        outputset.set(ARG_OUTPUT_VAL, outputValue);
                        outputlist.add(outputset);
                    }
                }
            }
        }
    }

    /**
     * Process the HTTP request
     * <P>
     * 
     * (Certificate Request Processed - either an automated "EE" profile based
     *  cert acceptance, or an automated "EE" profile based cert rejection)
     * <P>
     * 
     * <ul>
     * <li>http.param profileId ID of profile to use to process request
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a
     * certificate request has just been through the approval process
     * </ul>
     * @param cmsReq the object holding the request and response information
     * @exception EBaseException an error has occurred
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();
        boolean xmlOutput = false;

        String v = request.getParameter("xmlOutput");
        if (v != null && v.equals("true"))
            xmlOutput = true;

        IStatsSubsystem statsSub = (IStatsSubsystem)CMS.getSubsystem("stats");
        if (statsSub != null) {
          statsSub.startTiming("enrollment", true /* main action */);
        }

        long startTime = CMS.getCurrentDate().getTime();
        Locale locale = getLocale(request);
        ArgSet args = new ArgSet();

        if (CMS.debugOn()) {
            CMS.debug("Start of Input Parameters");
            Enumeration paramNames = request.getParameterNames();

            while (paramNames.hasMoreElements()) {
                String paramName = (String) paramNames.nextElement();

                CMS.debug("Input Parameter " + paramName + "='" + 
                    request.getParameter(paramName) + "'");
            }
            CMS.debug("End of Input Parameters");
        }

        CMS.debug("ProfileSubmitServlet: start serving");

        if (mProfileSubId == null || mProfileSubId.equals("")) {
            mProfileSubId = IProfileSubsystem.ID;
        }
        CMS.debug("ProfileSubmitServlet: SubId=" + mProfileSubId);
        IProfileSubsystem ps = (IProfileSubsystem) 
            CMS.getSubsystem(mProfileSubId); 

        if (ps == null) {
            CMS.debug("ProfileSubmitServlet: ProfileSubsystem not found");
            if (xmlOutput) {
                outputError(response, CMS.getUserMessage(locale,
                  "CMS_INTERNAL_ERROR"));
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);
            }
            if (statsSub != null) {
              statsSub.endTiming("enrollment");
            }
            return;
        }

        // if we did not configure profileId in xml file,
        // then accept the user-provided one
        String profileId = null;

        if (mProfileId == null) {
            profileId = request.getParameter("profileId");
        } else {
            profileId = mProfileId;
        }

        IProfile profile = null; 

        try { 
            CMS.debug("ProfileSubmitServlet: profileId " + profileId);
            profile = ps.getProfile(profileId); 
        } catch (EProfileException e) { 
            CMS.debug("ProfileSubmitServlet: profile not found profileId " + 
                profileId + " " + e.toString());
        }
        if (profile == null) {
            if (xmlOutput) {
                outputError(response, CMS.getUserMessage(locale,"CMS_PROFILE_NOT_FOUND", profileId));
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
                outputTemplate(request, response, args);
            }
            return;
        }

        if (!ps.isProfileEnable(profileId)) {
            CMS.debug("ProfileSubmitServlet: Profile " + profileId + 
                " not enabled");
            if (xmlOutput) {
                outputError(response, CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
                outputTemplate(request, response, args);
            }
            if (statsSub != null) {
              statsSub.endTiming("enrollment");
            }
            return;
        }

        IProfileContext ctx = profile.createContext();
        // passing auths into context
        IProfileAuthenticator authenticator = null;

        try {
            authenticator = profile.getAuthenticator();
        } catch (EProfileException e) {
            // authenticator not installed correctly
        }
        if (authenticator == null) {
            CMS.debug("ProfileSubmitServlet: authenticator not found");
        } else {
            CMS.debug("ProfileSubmitServlet: authenticator " + 
                authenticator.getName() + " found");
            setCredentialsIntoContext(request, authenticator, ctx);
        }

        setInputsIntoContext(request, profile, ctx);
        CMS.debug("ProfileSubmistServlet: set Inputs into Context");

        // before creating the request, authenticate the request

        IAuthToken authToken = null;

        // for ssl authentication; pass in servlet for retrieving
        // ssl client certificates
        SessionContext context = SessionContext.getContext();

        // insert profile context so that input parameter can be retrieved
        context.put("profileContext", ctx); 
        context.put("sslClientCertProvider", 
            new SSLClientCertProvider(request));
        CMS.debug("ProfileSubmitServlet: set sslClientCertProvider");
        if (statsSub != null) {
          statsSub.startTiming("profile_authentication");
        }
        if (authenticator != null) { 
            try {
                authToken = authenticate(authenticator, request);
                // authentication success
            } catch (EBaseException e) {
                CMS.debug("ProfileSubmitServlet: authentication error " + 
                    e.toString());
                // authentication error
                if (xmlOutput) {
                    outputError(response, AUTH_FAILURE, CMS.getUserMessage(locale, "CMS_AUTHENTICATION_ERROR"));
                } else {
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_AUTHENTICATION_ERROR"));
                    outputTemplate(request, response, args);
                }
                if (statsSub != null) {
                  statsSub.endTiming("authentication");
                }
                if (statsSub != null) {
                  statsSub.endTiming("enrollment");
                }
                return;
            }
        }
        if (statsSub != null) {
          statsSub.endTiming("profile_authentication");
        }

        if (authToken != null) {
            // do profile authorization
            String acl = profile.getAuthzAcl();
            if (acl != null && acl.length() > 0) {
                try {
                    AuthzToken authzToken = authorize(mAclMethod, authToken, acl);
                } catch (Exception e) {
                    CMS.debug("ProfileSubmitServlet authorize: "+e.toString());
                    if (xmlOutput) {
                        outputError(response, CMS.getUserMessage(locale, 
                          "CMS_AUTHORIZATION_ERROR"));
                    } else {
                        args.set(ARG_ERROR_CODE, "1");
                        args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                            "CMS_AUTHORIZATION_ERROR"));
                        outputTemplate(request, response, args);
                    }

                    return;
                }
            }
        }

        IRequest reqs[] = null;

        if (statsSub != null) {
          statsSub.startTiming("request_population");
        }
        ///////////////////////////////////////////////
        // create request
        ///////////////////////////////////////////////
        try {
            reqs = profile.createRequests(ctx, locale);
        } catch (EProfileException e) {
            CMS.debug(e);
            CMS.debug("ProfileSubmitServlet: 1 createRequests " + e.toString());
            if (xmlOutput) {
                outputError(response, e.toString());
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, e.toString());
                outputTemplate(request, response, args);
            }
            if (statsSub != null) {
              statsSub.endTiming("request_population");
              statsSub.endTiming("enrollment");
            }
            return;
        } catch (Throwable e) {
            CMS.debug(e);
            CMS.debug("ProfileSubmitServlet: createRequests " + e.toString());
            if (xmlOutput) {
                outputError(response, CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);
            }
            if (statsSub != null) {
              statsSub.endTiming("request_population");
              statsSub.endTiming("enrollment");
            }
            return;
        }

        String errorCode = null;
        String errorReason = null; 

        ///////////////////////////////////////////////
        // populate request
        ///////////////////////////////////////////////
        for (int k = 0; k < reqs.length; k++) {
            boolean fromRA = false;
            String uid = "";

            // adding parameters to request
            setInputsIntoRequest(request, profile, reqs[k]);

            // serial auth token into request
            if (authToken != null) {
                Enumeration tokenNames = authToken.getElements();
                while (tokenNames.hasMoreElements()) {
                    String tokenName = (String) tokenNames.nextElement();
                    String[] tokenVals = authToken.getInStringArray(tokenName);
                    if (tokenVals != null) {
                        for (int i = 0; i < tokenVals.length; i++) {
                            reqs[k].setExtData(ARG_AUTH_TOKEN + "." +
                                    tokenName + "[" + i + "]", tokenVals[i]);
                        }
                    } else {
                        String tokenVal = authToken.getInString(tokenName);
                        if (tokenVal != null) {
                            reqs[k].setExtData(ARG_AUTH_TOKEN + "." + tokenName,
                                    tokenVal);
                            // if RA agent, auto assign the request
                            if (tokenName.equals("uid"))
                                uid = tokenVal;
                            if (tokenName.equals("group") &&
                                    tokenVal.equals("Registration Manager Agents")) {
                                fromRA = true;
                            }
                        }
                    }
                }
            }

            if (fromRA) {
                CMS.debug("ProfileSubmitServlet: request from RA: "+ uid);
                reqs[k].setExtData(ARG_REQUEST_OWNER, uid);
            }

            // put profile framework parameters into the request
            reqs[k].setExtData(ARG_PROFILE, "true");
            reqs[k].setExtData(ARG_PROFILE_ID, profileId);
            reqs[k].setExtData(ARG_PROFILE_APPROVED_BY, profile.getApprovedBy());
            String setId = profile.getPolicySetId(reqs[k]);

            if (setId == null) {
                // no profile set found
                CMS.debug("ProfileSubmitServlet: no profile policy set found");
                if (xmlOutput) {
                    outputError(response, CMS.getUserMessage("CMS_PROFILE_NO_POLICY_SET_FOUND"));
                } else {
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, 
                      CMS.getUserMessage("CMS_PROFILE_NO_POLICY_SET_FOUND"));
                    outputTemplate(request, response, args);
                }
                if (statsSub != null) {
                  statsSub.endTiming("request_population");
                  statsSub.endTiming("enrollment");
                }
                return;
            }

            CMS.debug("ProfileSubmitServlet profileSetid=" + setId);
            reqs[k].setExtData(ARG_PROFILE_SET_ID, setId);
            reqs[k].setExtData(ARG_PROFILE_REMOTE_HOST, request.getRemoteHost());
            reqs[k].setExtData(ARG_PROFILE_REMOTE_ADDR, request.getRemoteAddr());

            CMS.debug("ProfileSubmitServlet: request " + 
                reqs[k].getRequestId().toString());

            try {
                CMS.debug("ProfileSubmitServlet: populating request inputs");
                // give authenticator a chance to populate the request
                if (authenticator != null) { 
                    authenticator.populate(authToken, reqs[k]);
                }
                profile.populateInput(ctx, reqs[k]);
                profile.populate(reqs[k]);
            } catch (EProfileException e) {
                CMS.debug("ProfileSubmitServlet: populate " + e.toString());
                if (xmlOutput) {
                    outputError(response, e.toString());
                } else {
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, e.toString());
                    outputTemplate(request, response, args);
                }
                if (statsSub != null) {
                  statsSub.endTiming("request_population");
                  statsSub.endTiming("enrollment");
                }
                return;
            } catch (Throwable e) {
                CMS.debug("ProfileSubmitServlet: populate " + e.toString());
                //  throw new IOException("Profile " + profileId + 
                //          " cannot populate");
                if (xmlOutput) {
                    outputError(response, CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
                } else {
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                    outputTemplate(request, response, args);
                }
                if (statsSub != null) {
                  statsSub.endTiming("request_population");
                  statsSub.endTiming("enrollment");
                }
                return;
            }
        }
        if (statsSub != null) {
          statsSub.endTiming("request_population");
        }

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = ILogger.UNIDENTIFIED;
        String auditInfoCertValue = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        try {
            ///////////////////////////////////////////////
            // submit request
            ///////////////////////////////////////////////
            for (int k = 0; k < reqs.length; k++) {
                try {
                    // reset the "auditRequesterID"
                    auditRequesterID = auditRequesterID(reqs[k]);


                    // print request debug
                    if (reqs[k] != null) {
                      Enumeration reqKeys = reqs[k].getExtDataKeys();
                      while (reqKeys.hasMoreElements()) {
                        String reqKey = (String)reqKeys.nextElement();
                        String reqVal = reqs[k].getExtDataInString(reqKey);
                        if (reqVal != null) {
                           CMS.debug("ProfileSubmitServlet: key=$request." + reqKey + "$ value=" + reqVal);
                        }
                      }
                    }

                    profile.submit(authToken, reqs[k]);
                    reqs[k].setRequestStatus(RequestStatus.COMPLETE);

                    // reset the "auditInfoCertValue"
                    auditInfoCertValue = auditInfoCertValue(reqs[k]);

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
                    reqs[k].setRequestStatus(RequestStatus.PENDING);
                    // need to notify
                    INotify notify = profile.getRequestQueue().getPendingNotify();
                    if (notify != null) {
                       notify.notify(reqs[k]);
                    }
                
                    CMS.debug("ProfileSubmitServlet: submit " + e.toString());
                    errorCode = "2";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_PROFILE_DEFERRED",
                                e.toString());
                } catch (ERejectException e) {
                    // return error to the user 
                    reqs[k].setRequestStatus(RequestStatus.REJECTED);
                    CMS.debug("ProfileSubmitServlet: submit " + e.toString());
                    errorCode = "3";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_PROFILE_REJECTED",
                                e.toString());
                } catch (Throwable e) {
                    // return error to the user
                    CMS.debug("ProfileSubmitServlet: submit " + e.toString());
                    errorCode = "1";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_INTERNAL_ERROR");
                }

                try { 
                    profile.getRequestQueue().updateRequest(reqs[k]);
                } catch (EBaseException e) {
                    CMS.debug("ProfileSubmitServlet: updateRequest " +
                        e.toString());
                }

                if (errorCode != null) {
                    if (errorCode.equals("1")) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_REJECTION,
                                    errorReason);

                        audit(auditMessage);
                    } else if (errorCode.equals("2")) {
                        // do NOT store a message in the signed audit log file
                        // as this errorCode indicates that a process has been
                        // deferred for manual acceptance/cancellation/rejection
                    } else if (errorCode.equals("3")) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_REJECTION,
                                    errorReason);

                        audit(auditMessage);
                    }
                }
            }

            if (errorCode != null) {
                if (xmlOutput) {
                    outputError(response, errorReason);
                } else {
                    ArgList requestlist = new ArgList();

                    for (int k = 0; k < reqs.length; k++) {
                        ArgSet requestset = new ArgSet();

                        requestset.set(ARG_REQUEST_ID,
                            reqs[k].getRequestId().toString());
                        requestlist.add(requestset);
                    }
                    args.set(ARG_REQUEST_LIST, requestlist);
                    args.set(ARG_ERROR_CODE, errorCode);
                    args.set(ARG_ERROR_REASON, errorReason);
                    outputTemplate(request, response, args);
                }
                if (statsSub != null) {
                  statsSub.endTiming("enrollment");
                }
                return;
            }

            ///////////////////////////////////////////////
            // output output list 
            ///////////////////////////////////////////////
            if (xmlOutput) {
                xmlOutput(response, profile, locale, reqs);
            } else {
                ArgList outputlist = new ArgList();
                for (int k = 0; k < reqs.length; k++) {

                    setOutputIntoArgs(profile, outputlist, locale, reqs[k]);
                    args.set(ARG_OUTPUT_LIST, outputlist);
                }

                CMS.debug("ProfileSubmitServlet: done serving");

                ArgList requestlist = new ArgList();

                for (int k = 0; k < reqs.length; k++) {
                    ArgSet requestset = new ArgSet();

                    requestset.set(ARG_REQUEST_ID,
                        reqs[k].getRequestId().toString());
                    requestlist.add(requestset);
                }
                args.set(ARG_REQUEST_LIST, requestlist);
                args.set(ARG_ERROR_CODE, "0");
                args.set(ARG_ERROR_REASON, "");

                outputTemplate(request, response, args);
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            // (automated cert request processed - "rejected")
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        ILogger.SIGNED_AUDIT_REJECTION,
                        SIGNED_AUDIT_AUTOMATED_REJECTION_REASON[0]);

            audit(auditMessage);

            if (statsSub != null) {
              statsSub.endTiming("enrollment");
            }
            throw eAudit1;
        } finally {
            context.releaseContext();
        }
        if (statsSub != null) {
          statsSub.endTiming("enrollment");
        }
    }

    private void xmlOutput(HttpServletResponse httpResp, IProfile profile, Locale locale, IRequest[] reqs) {
        try {
            XMLObject xmlObj = null;
            xmlObj = new XMLObject();

            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            Node n = xmlObj.createContainer(root, "Requests");
            CMS.debug("ProfileSubmitServlet xmlOutput: req len = " +reqs.length);

            for (int i=0; i<reqs.length; i++) {
                Node subnode = xmlObj.createContainer(n, "Request");
                xmlObj.addItemToContainer(subnode, "Id", reqs[i].getRequestId().toString());
                X509CertInfo certInfo =
                    reqs[i].getExtDataInCertInfo(IEnrollProfile.REQUEST_CERTINFO);
                if (certInfo != null) {
                  String subject = "";
                  subject = (String) certInfo.get(X509CertInfo.SUBJECT).toString();
                  xmlObj.addItemToContainer(subnode, "SubjectDN", subject);
                } else {
                  CMS.debug("ProfileSubmitServlet xmlOutput: no certInfo found in request");
                }
                Enumeration outputIds = profile.getProfileOutputIds();
                if (outputIds != null) {
                    while (outputIds.hasMoreElements()) {
                        String outputId = (String) outputIds.nextElement();
                        IProfileOutput profileOutput = profile.getProfileOutput(outputId);
                        Enumeration outputNames = profileOutput.getValueNames();
                        if (outputNames != null) {
                            while (outputNames.hasMoreElements()) {
                                String outputName = (String) outputNames.nextElement();
                                if (!outputName.equals("b64_cert") && !outputName.equals("pkcs7"))
                                    continue;
                                try {
                                    String outputValue = profileOutput.getValue(outputName, locale, reqs[i]);
                                    if (outputName.equals("b64_cert")) {
                                      String ss = Cert.normalizeCertStrAndReq(outputValue);
                                      outputValue = Cert.stripBrackets(ss);
                                      byte[] bcode = CMS.AtoB(outputValue);
                                      X509CertImpl impl = new X509CertImpl(bcode);
                                      xmlObj.addItemToContainer(subnode,
                                        "serialno", impl.getSerialNumber().toString(16));
                                      xmlObj.addItemToContainer(subnode, "b64", outputValue);
                                    }// if b64_cert
                                    else if (outputName.equals("pkcs7")) {
                                      String ss = Cert.normalizeCertStrAndReq(outputValue);
                                      xmlObj.addItemToContainer(subnode, "pkcs7", ss);
                                    }
 
                                } catch (EProfileException e) {
                                    CMS.debug("ProfileSubmitServlet xmlOutput: "+e.toString());
                                } catch (Exception e) {
                                    CMS.debug("ProfileSubmitServlet xmlOutput: "+e.toString());
                                }
                            }
                        }
                    }
                }
            }

            byte[] cb = xmlObj.toByteArray();
            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("Failed to send the XML output");
        }
    }

    /**
     * Signed Audit Log Requester ID
     *
     * This method is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return id string containing the signed audit log message RequesterID
     */
    private String auditRequesterID(IRequest request) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String requesterID = ILogger.UNIDENTIFIED;

        if (request != null) {
            // overwrite "requesterID" if and only if "id" != null
            String id = request.getRequestId().toString();

            if (id != null) {
                requesterID = id.trim();
            }
        }

        return requesterID;
    }

    /**
     * Signed Audit Log Info Certificate Value
     *
     * This method is called to obtain the certificate from the passed in
     * "X509CertImpl" for a signed audit log message.
     * <P>
     *
     * @param request request containing an X509CertImpl
     * @return cert string containing the certificate
     */
    private String auditInfoCertValue(IRequest request) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        X509CertImpl x509cert = request.getExtDataInCert(
                IEnrollProfile.REQUEST_ISSUED_CERT);

        if (x509cert == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        try {
            rawData = x509cert.getEncoded();
        } catch (CertificateEncodingException e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        String cert = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = com.netscape.osutil.OSUtil.BtoA(rawData).trim();

            // extract all line separators from the "base64Data"
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < base64Data.length(); i++) {
                if (base64Data.substring(i, i).getBytes() != EOL) {
                    sb.append(base64Data.substring(i, i));
                }
            }
            cert = sb.toString();
        }

        if (cert != null) {
            cert = cert.trim();

            if (cert.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return cert;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
    }
}
