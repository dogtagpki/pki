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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.pkix.cmc.LraPopWitness;
import org.mozilla.jss.pkix.cmc.OtherInfo;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.common.CMCOutputTemplate;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.util.Utils;

/**
 * This servlet submits end-user request into the profile framework.
 *
 * @version $Revision$, $Date$
 */
public class ProfileSubmitCMCServlet extends ProfileServlet {

    /**
     *
     */
    private static final long serialVersionUID = -8017841111435988197L;
    private static final String ARG_AUTH_TOKEN = "auth_token";
    private static final String PROP_PROFILE_ID = "profileId";

    private String mProfileId = null;
    private String mProfileSubId = null;
    private String requestB64 = null;

    private final static String LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";

    public ProfileSubmitCMCServlet() {
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
        mProfileId = sc.getInitParameter(PROP_PROFILE_ID);
        mRenderResult = false;
    }

    private void setInputsIntoContext(HttpServletRequest request, IProfile profile, IProfileContext ctx) {

        // passing inputs into context
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();

                    if (request.getParameter(inputName) != null) {
                        ctx.set(inputName, request.getParameter(inputName));
                    }
                }
            }
        }

    }

    private void setCredentialsIntoContext(HttpServletRequest request, IProfileAuthenticator authenticator,
            IProfileContext ctx) {
        Enumeration<String> authIds = authenticator.getValueNames();

        if (authIds != null) {
            while (authIds.hasMoreElements()) {
                String authName = authIds.nextElement();

                if (request.getParameter(authName) != null) {
                    ctx.set(authName, request.getParameter(authName));
                }
            }
        }
    }

    public IAuthToken authenticate(IProfileAuthenticator authenticator,
            HttpServletRequest request) throws EBaseException {
        AuthCredentials credentials = new AuthCredentials();

        // build credential
        Enumeration<String> authNames = authenticator.getValueNames();

        if (authNames != null) {
            while (authNames.hasMoreElements()) {
                String authName = authNames.nextElement();

                if (authName.equals("cert_request"))
                    credentials.set(authName, requestB64);
                else
                    credentials.set(authName, request.getParameter(authName));
            }
        }
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

    private void setInputsIntoRequest(HttpServletRequest request, IProfile
            profile, IRequest req) {
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                if (inputNames != null) {
                    while (inputNames.hasMoreElements()) {
                        String inputName = inputNames.nextElement();

                        if (request.getParameter(inputName) != null) {
                            req.setExtData(inputName, request.getParameter(inputName));
                        }
                    }
                }
            }
        }
    }

    /**
     * Process the HTTP request
     * <P>
     *
     * (Certificate Request Processed - either an automated "EE" profile based cert acceptance, or an automated "EE"
     * profile based cert rejection)
     * <P>
     *
     * <ul>
     * <li>http.param profileId ID of profile to use to process request
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     * @exception EBaseException an error has occurred
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        Locale locale = getLocale(request);
        String cert_request_type =
                mServletConfig.getInitParameter("cert_request_type");
        String outputFormat = mServletConfig.getInitParameter("outputFormat");

        int reqlen = request.getContentLength();
        InputStream is = null;
        try {
            is = request.getInputStream();
        } catch (Exception ee) {
        }
        byte reqbuf[] = new byte[reqlen];
        int bytesread = 0;
        boolean partial = false;

        while (bytesread < reqlen) {
            try {
                bytesread += is.read(reqbuf, bytesread, reqlen - bytesread);
            } catch (Exception ee) {
            }

            if (partial == false) {
                if (bytesread < reqlen)
                    partial = true;
            }
        }

        requestB64 = Utils.base64encode(reqbuf);

        if (CMS.debugOn()) {
            CMS.debug("Start of ProfileSubmitCMCServlet Input Parameters");
            Enumeration<String> paramNames = request.getParameterNames();

            while (paramNames.hasMoreElements()) {
                String paramName = paramNames.nextElement();
                // added this facility so that password can be hidden,
                // all sensitive parameters should be prefixed with
                // __ (double underscores); however, in the event that
                // a security parameter slips through, we perform multiple
                // additional checks to insure that it is NOT displayed
                if (paramName.startsWith("__") ||
                        paramName.endsWith("password") ||
                        paramName.endsWith("passwd") ||
                        paramName.endsWith("pwd") ||
                        paramName.equalsIgnoreCase("admin_password_again") ||
                        paramName.equalsIgnoreCase("directoryManagerPwd") ||
                        paramName.equalsIgnoreCase("bindpassword") ||
                        paramName.equalsIgnoreCase("bindpwd") ||
                        paramName.equalsIgnoreCase("passwd") ||
                        paramName.equalsIgnoreCase("password") ||
                        paramName.equalsIgnoreCase("pin") ||
                        paramName.equalsIgnoreCase("pwd") ||
                        paramName.equalsIgnoreCase("pwdagain") ||
                        paramName.equalsIgnoreCase("uPasswd")) {
                    CMS.debug("ProfileSubmitCMCServlet Input Parameter " +
                              paramName + "='(sensitive)'");
                } else {
                    CMS.debug("ProfileSubmitCMCServlet Input Parameter " +
                              paramName + "='" +
                              request.getParameter(paramName) + "'");
                }
            }
            CMS.debug("End of ProfileSubmitCMCServlet Input Parameters");
        }

        CMS.debug("ProfileSubmitCMCServlet: start serving");

        if (mProfileSubId == null || mProfileSubId.equals("")) {
            mProfileSubId = IProfileSubsystem.ID;
        }
        CMS.debug("ProfileSubmitCMCServlet: SubId=" + mProfileSubId);
        IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem(mProfileSubId);

        if (ps == null) {
            CMS.debug("ProfileSubmitCMCServlet: ProfileSubsystem not found");
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.INTERNAL_CA_ERROR, s);
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
            CMS.debug("ProfileSubmitCMCServlet: profileId " + profileId);
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            CMS.debug("ProfileSubmitCMCServlet: profile not found profileId " +
                    profileId + " " + e.toString());
        }
        if (profile == null) {
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.INTERNAL_CA_ERROR, s);
            return;
        }

        if (!ps.isProfileEnable(profileId)) {
            CMS.debug("ProfileSubmitCMCServlet: Profile " + profileId +
                    " not enabled");
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.INTERNAL_CA_ERROR, s);
            return;
        }

        IProfileContext ctx = profile.createContext();
        if (requestB64 != null) {
            ctx.set("cert_request_type", cert_request_type);
            ctx.set("cert_request", requestB64);
        }
        // passing auths into context
        IProfileAuthenticator authenticator = null;

        try {
            authenticator = profile.getAuthenticator();
        } catch (EProfileException e) {
            // authenticator not installed correctly
        }
        if (authenticator == null) {
            CMS.debug("ProfileSubmitCMCServlet: authenticator not found");
        } else {
            CMS.debug("ProfileSubmitCMCServlet: authenticator " +
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
        CMS.debug("ProfileSubmitCMCServlet: set sslClientCertProvider");
        if (authenticator != null) {
            try {
                authToken = authenticate(authenticator, request);
                // authentication success
            } catch (EBaseException e) {
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String(e.toString());
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        OtherInfo.BAD_REQUEST, s);
                CMS.debug("ProfileSubmitCMCServlet: authentication error " +
                        e.toString());
                return;
            }

            //authorization only makes sense when request is authenticated
            AuthzToken authzToken = null;
            if (authToken != null) {
                CMS.debug("ProfileSubmitCMCServlet authToken not null");
                try {
                    authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "submit");
                } catch (Exception e) {
                    CMS.debug("ProfileSubmitCMCServlet authorization failure: " + e.toString());
                }
            }

            if (authzToken == null) {
                CMS.debug("ProfileSubmitCMCServlet authorization failure: authzToken is null");
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String("ProfileSubmitCMCServlet authorization failure");
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        OtherInfo.BAD_REQUEST, s);
                return;
            }
        }

        IRequest reqs[] = null;

        ///////////////////////////////////////////////
        // create request
        ///////////////////////////////////////////////
        try {
            reqs = profile.createRequests(ctx, locale);
        } catch (EProfileException e) {
            CMS.debug("ProfileSubmitCMCServlet: createRequests " + e.toString());
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(e.toString());
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.INTERNAL_CA_ERROR, s);
            return;
        } catch (Throwable e) {
            CMS.debug("ProfileSubmitCMCServlet: createRequests " + e.toString());
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.INTERNAL_CA_ERROR, s);
            return;
        }

        TaggedAttribute attr =
                (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_lraPOPWitness));
        if (attr != null) {
            boolean verifyAllow = true;
            try {
                verifyAllow = CMS.getConfigStore().getBoolean(
                        "cmc.lraPopWitness.verify.allow", true);
            } catch (EBaseException ee) {
            }

            if (!verifyAllow) {
                LraPopWitness lraPop = null;
                SET vals = attr.getValues();
                if (vals.size() > 0) {
                    try {
                        lraPop = (LraPopWitness) (ASN1Util.decode(LraPopWitness.getTemplate(),
                                ASN1Util.encode(vals.elementAt(0))));
                    } catch (InvalidBERException e) {
                        CMS.debug(
                                CMS.getUserMessage(locale, "CMS_PROFILE_ENCODING_ERROR"));
                    }

                    SEQUENCE bodyIds = lraPop.getBodyIds();

                    CMCOutputTemplate template = new CMCOutputTemplate();
                    template.createFullResponseWithFailedStatus(response, bodyIds,
                            OtherInfo.POP_FAILED, null);
                    return;
                }
            }
        }

        // for CMC, requests may be zero. Then check if controls exist.
        if (reqs == null) {
            Integer nums = (Integer) (context.get("numOfControls"));
            CMCOutputTemplate template = new CMCOutputTemplate();
            // if there is only one control GetCert, then simple response
            // must be returned.
            if (nums != null && nums.intValue() == 1) {
                TaggedAttribute attr1 = (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_getCert));
                if (attr1 != null) {
                    template.createSimpleResponse(response, reqs);
                } else
                    template.createFullResponse(response, reqs,
                            cert_request_type, null);
            } else
                template.createFullResponse(response, reqs,
                        cert_request_type, null);
            return;
        }

        String errorCode = null;
        String errorReason = null;

        ///////////////////////////////////////////////
        // populate request
        ///////////////////////////////////////////////
        for (int k = 0; k < reqs.length; k++) {
            // adding parameters to request
            setInputsIntoRequest(request, profile, reqs[k]);

            // serial auth token into request
            if (authToken != null) {
                Enumeration<String> tokenNames = authToken.getElements();
                while (tokenNames.hasMoreElements()) {
                    String tokenName = tokenNames.nextElement();
                    String[] vals = authToken.getInStringArray(tokenName);
                    if (vals != null) {
                        for (int i = 0; i < vals.length; i++) {
                            reqs[k].setExtData(ARG_AUTH_TOKEN + "." +
                                    tokenName + "[" + i + "]", vals[i]);
                        }
                    } else {
                        String val = authToken.getInString(tokenName);
                        if (val != null) {
                            reqs[k].setExtData(ARG_AUTH_TOKEN + "." + tokenName,
                                    val);
                        }
                    }
                }
            }

            // put profile framework parameters into the request
            reqs[k].setExtData(ARG_PROFILE, "true");
            reqs[k].setExtData(ARG_PROFILE_ID, profileId);
            reqs[k].setExtData(ARG_PROFILE_APPROVED_BY, profile.getApprovedBy());
            String setId = profile.getPolicySetId(reqs[k]);

            if (setId == null) {
                // no profile set found
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String(CMS.getUserMessage("CMS_PROFILE_NO_POLICY_SET_FOUND"));
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        OtherInfo.INTERNAL_CA_ERROR, s);
                return;
            }

            CMS.debug("ProfileSubmitCMCServlet profileSetid=" + setId);
            reqs[k].setExtData(ARG_PROFILE_SET_ID, setId);
            reqs[k].setExtData(ARG_PROFILE_REMOTE_HOST, request.getRemoteHost());
            reqs[k].setExtData(ARG_PROFILE_REMOTE_ADDR, request.getRemoteAddr());

            CMS.debug("ProfileSubmitCMCServlet: request " +
                    reqs[k].getRequestId().toString());

            try {
                CMS.debug("ProfileSubmitCMCServlet: populating request inputs");
                // give authenticator a chance to populate the request
                if (authenticator != null) {
                    authenticator.populate(authToken, reqs[k]);
                }
                profile.populateInput(ctx, reqs[k]);
                profile.populate(reqs[k]);
            } catch (EProfileException e) {
                CMS.debug("ProfileSubmitCMCServlet: populate " + e.toString());
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String(e.toString());
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        OtherInfo.BAD_REQUEST, s);
                return;
            } catch (Throwable e) {
                CMS.debug("ProfileSubmitCMCServlet: populate " + e.toString());
                //  throw new IOException("Profile " + profileId +
                //          " cannot populate");
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String(e.toString());
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        OtherInfo.INTERNAL_CA_ERROR, s);
                return;
            }
        }

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = ILogger.UNIDENTIFIED;
        String auditInfoCertValue = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        try {
            ///////////////////////////////////////////////
            // submit request
            ///////////////////////////////////////////////
            int error_codes[] = null;
            if (reqs != null && reqs.length > 0)
                error_codes = new int[reqs.length];
            for (int k = 0; k < reqs.length; k++) {
                try {
                    // reset the "auditRequesterID"
                    auditRequesterID = auditRequesterID(reqs[k]);

                    // print request debug
                    if (reqs[k] != null) {
                        Enumeration<String> reqKeys = reqs[k].getExtDataKeys();
                        while (reqKeys.hasMoreElements()) {
                            String reqKey = reqKeys.nextElement();
                            String reqVal = reqs[k].getExtDataInString(reqKey);
                            if (reqVal != null) {
                                CMS.debug("ProfileSubmitCMCServlet: key=$request." + reqKey + "$ value=" + reqVal);
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

                    CMS.debug("ProfileSubmitCMCServlet: submit " + e.toString());
                    errorCode = "2";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_PROFILE_DEFERRED",
                                e.toString());
                } catch (ERejectException e) {
                    // return error to the user
                    reqs[k].setRequestStatus(RequestStatus.REJECTED);
                    CMS.debug("ProfileSubmitCMCServlet: submit " + e.toString());
                    errorCode = "3";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_PROFILE_REJECTED",
                                e.toString());
                } catch (Throwable e) {
                    // return error to the user
                    CMS.debug("ProfileSubmitCMCServlet: submit " + e.toString());
                    errorCode = "1";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_INTERNAL_ERROR");
                }

                try {
                    if (errorCode == null) {
                        profile.getRequestQueue().markAsServiced(reqs[k]);
                    } else {
                        profile.getRequestQueue().updateRequest(reqs[k]);
                    }
                } catch (EBaseException e) {
                    CMS.debug("ProfileSubmitCMCServlet: updateRequest " +
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
                    error_codes[k] = Integer.parseInt(errorCode);
                } else
                    error_codes[k] = 0;
            }

            if (errorCode != null) {
                // create the CMC full enrollment response
                CMCOutputTemplate template = new CMCOutputTemplate();
                template.createFullResponse(response, reqs, cert_request_type, error_codes);

                return;
            }

            ///////////////////////////////////////////////
            // output output list
            ///////////////////////////////////////////////

            CMS.debug("ProfileSubmitCMCServlet: done serving");
            CMCOutputTemplate template = new CMCOutputTemplate();
            if (cert_request_type.equals("pkcs10") || cert_request_type.equals("crmf")) {

                if (outputFormat != null && outputFormat.equals("pkcs7")) {
                    byte[] pkcs7 = CMS.getPKCS7(locale, reqs[0]);
                    response.setContentType("application/pkcs7-mime");
                    response.setContentLength(pkcs7.length);
                    try {
                        OutputStream os = response.getOutputStream();
                        os.write(pkcs7);
                        os.flush();
                    } catch (Exception ee) {
                    }
                    return;
                }
                template.createSimpleResponse(response, reqs);
            } else if (cert_request_type.equals("cmc")) {
                Integer nums = (Integer) (context.get("numOfControls"));
                if (nums != null && nums.intValue() == 1) {
                    TaggedAttribute attr1 =
                            (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_getCert));
                    if (attr1 != null) {
                        template.createSimpleResponse(response, reqs);
                        return;
                    }
                }
                template.createFullResponse(response, reqs, cert_request_type,
                        error_codes);
            }
        } finally {
            SessionContext.releaseContext();
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

            base64Data = Utils.base64encode(rawData).trim();

            // extract all line separators from the "base64Data"
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < base64Data.length(); i++) {
                if (!Character.isWhitespace(base64Data.charAt(i))) {
                    sb.append(base64Data.charAt(i));
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
