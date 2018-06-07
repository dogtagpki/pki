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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.event.AuthEvent;
import com.netscape.certsrv.logging.event.CertRequestProcessedEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.ECMCBadIdentityException;
import com.netscape.certsrv.profile.ECMCBadMessageCheckException;
import com.netscape.certsrv.profile.ECMCBadRequestException;
import com.netscape.certsrv.profile.ECMCPopFailedException;
import com.netscape.certsrv.profile.ECMCPopRequiredException;
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
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.common.CMCOutputTemplate;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X509CertImpl;

/**
 * This servlet submits end-user request into the profile framework.
 *
 * @version $Revision$, $Date$
 */
public class ProfileSubmitCMCServlet extends ProfileServlet {

    /**
     *
     */
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();
    private static final long serialVersionUID = -8017841111435988197L;
    private static final String PROP_PROFILE_ID = "profileId";

    private String mProfileId = null;
    private String mProfileSubId = null;
    private String requestB64 = null;

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
        String method = "ProfileSubmitCMCServlet.setInputsIntoContext: ";
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
                        CMS.debug(method + "setting: " + inputName);
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
        String method = "ProfileSubmitCMCServlet: authenticate: ";
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

        IAuthToken authToken = null;
        String auditSubjectID = null;
        String authMgrID = authenticator.getName();
        SessionContext sc = SessionContext.getContext();

        X509Certificate clientCert =
                getSSLClientCertificate(request, false /*cert may not be required*/);
        if (clientCert != null) {
           sc.put(SessionContext.SSL_CLIENT_CERT, clientCert);
        }

        try {
            authToken = authenticator.authenticate(credentials);
            if (sc != null) {
                sc.put(SessionContext.AUTH_MANAGER_ID, authMgrID);
                auditSubjectID = authToken.getInString(IAuthToken.USER_ID);
                if (auditSubjectID != null) {
                    CMS.debug(method + "setting auditSubjectID in SessionContext:" +
                            auditSubjectID);
                    sc.put(SessionContext.USER_ID, auditSubjectID);
                } else {
                    CMS.debug(method + "no auditSubjectID found in authToken");
                }
            }

            if (!auditSubjectID.equals(ILogger.UNIDENTIFIED) &&
                    !auditSubjectID.equals(ILogger.NONROLEUSER)) {
                audit(AuthEvent.createSuccessEvent(
                        auditSubjectID,
                        authMgrID));
            }

        } catch (EBaseException e) {
            CMS.debug(method + e);
            String attempted_auditSubjectID = null;
            if (sc != null) {
                attempted_auditSubjectID =
                        (String) sc.get(SessionContext.USER_ID);
            }
            audit(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    authMgrID,
                    attempted_auditSubjectID));
            throw(e);
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

        requestB64 = Utils.base64encode(reqbuf, true);

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

        // use user-provided profile ID
        String profileId = request.getParameter("profileId");

        if (profileId == null) { // otherwise use the default one
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
                s = new UTF8String(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND",CMSTemplate.escapeJavaScriptStringHTML(profileId)));
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
                s = new UTF8String(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND",CMSTemplate.escapeJavaScriptStringHTML(profileId)));
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.INTERNAL_CA_ERROR, s);
            return;
        }

        IProfileContext ctx = profile.createContext();
        if (requestB64 != null) {
            ctx.set("cert_request_type", cert_request_type);
            ctx.set("cert_request", Utils.normalizeString(requestB64));
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
        CMS.debug("ProfileSubmitCMCServlet: set Inputs into Context");

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

        String auditSubjectID = auditSubjectID();
        if (authenticator != null) {
            try {
                authToken = authenticate(authenticator, request);
                // authentication success
                if (authToken != null) {
                    auditSubjectID = authToken.getInString(IAuthToken.USER_ID);
                }
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

                // CMCAuth should pair with additional authz check as it counts
                // as pre-approved
                String authMgrID = authenticator.getName();
                if (authMgrID.equals("CMCAuth")) {
                    authzToken = null; // reset authzToken
                    CMS.debug("ProfileSubmitCMCServlet CMCAuth requires additional authz check");
                    try {
                        authzToken = authorize(mAclMethod, authToken,
                                "certServer.ca.certrequests", "execute");
                    } catch (Exception e) {
                        CMS.debug("ProfileSubmitCMCServlet authorization failure: " + e.toString());
                    }
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

        String auditMessage = CMS.getLogMessage(
                AuditEvent.CMC_REQUEST_RECEIVED,
                auditSubjectID,
                ILogger.SUCCESS,
                Utils.normalizeString(requestB64));
        signedAuditLogger.log(auditMessage);

        IRequest reqs[] = null;

        ///////////////////////////////////////////////
        // create request
        ///////////////////////////////////////////////
        String tmpCertSerialS = ctx.get(IAuthManager.CRED_CMC_SIGNING_CERT);
        if (tmpCertSerialS != null) {
            // unlikely to happen, but do this just in case
            CMS.debug("ProfileSubmitCMCServlet: found existing CRED_CMC_SIGNING_CERT in ctx for CMCUserSignedAuth:" + tmpCertSerialS);
            CMS.debug("ProfileSubmitCMCServlet: null it out");
            ctx.set(IAuthManager.CRED_CMC_SIGNING_CERT, "");
        }
        String signingCertSerialS = null;
        if (authToken != null) {
            signingCertSerialS = (String) authToken.get(IAuthManager.CRED_CMC_SIGNING_CERT);
        }
        if (signingCertSerialS != null) {
            CMS.debug("ProfileSubmitCMCServlet: setting CRED_CMC_SIGNING_CERT in ctx for CMCUserSignedAuth");
            ctx.set(IAuthManager.CRED_CMC_SIGNING_CERT, signingCertSerialS);
        }
        try {
            reqs = profile.createRequests(ctx, locale);
        } catch (ECMCBadMessageCheckException e) {
            CMS.debug("ProfileSubmitCMCServlet: after createRequests - " + e.toString());
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(e.toString());
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.BAD_MESSAGE_CHECK, s);
            return;
        } catch (ECMCBadIdentityException e) {
            CMS.debug("ProfileSubmitCMCServlet: after createRequests - " + e.toString());
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(e.toString());
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.BAD_IDENTITY, s);
            return;
        } catch (ECMCPopFailedException e) {
            CMS.debug("ProfileSubmitCMCServlet: after createRequests - " + e.toString());
            CMCOutputTemplate template = new CMCOutputTemplate();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new INTEGER(0));
            UTF8String s = null;
            try {
                s = new UTF8String(e.toString());
            } catch (Exception ee) {
            }
            template.createFullResponseWithFailedStatus(response, seq,
                    OtherInfo.POP_FAILED, s);
            return;
        } catch (ECMCBadRequestException e) {
            CMS.debug("ProfileSubmitCMCServlet: after createRequests - " + e.toString());
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
        } catch (EProfileException e) {
            CMS.debug("ProfileSubmitCMCServlet: after createRequests - " + e.toString());
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
            CMS.debug("ProfileSubmitCMCServlet: createRequests - " + e.toString());
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
            boolean verifyAllow = false; //disable RA by default
            try {
                verifyAllow = CMS.getConfigStore().getBoolean(
                        "cmc.lraPopWitness.verify.allow", false);
            } catch (EBaseException ee) {
            }
            CMS.debug("ProfileSubmitCMCServlet: cmc.lraPopWitness.verify.allow is " + verifyAllow);

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

        // For CMC, requests may be zero. Then check if controls exist.
        // In case of decryptedPOP, request already exists, find it and
        // put in provedReq.
        IRequest provedReq = null;
        boolean isRevoke = false;
        if (reqs == null) {
            // handling DecryptedPOP request here
            BigInteger reqID = (BigInteger) context.get("cmcDecryptedPopReqId");
            if (reqID == null) {
                CMS.debug("ProfileSubmitCMCServlet: revocation request");
                isRevoke = true;
            } else {
            provedReq = profile.getRequestQueue().findRequest(new RequestId(reqID.toString()));
            if (provedReq == null) {

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
            } else {
                CMS.debug("ProfileSubmitCMCServlet: provedReq not null");
            }
            }
        }

        String errorCode = null;
        String errorReason = null;

        ///////////////////////////////////////////////
        // populate request
        ///////////////////////////////////////////////
        for (int k = 0; (!isRevoke) && (provedReq == null) &&(k < reqs.length); k++) {
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
                            reqs[k].setExtData(
                                IRequest.AUTH_TOKEN_PREFIX
                                    + "." + tokenName + "[" + i + "]",
                                vals[i]);
                        }
                    } else {
                        String val = authToken.getInString(tokenName);
                        if (val != null) {
                            reqs[k].setExtData(
                                IRequest.AUTH_TOKEN_PREFIX + "." + tokenName,
                                val);
                        }
                    }
                }

                tmpCertSerialS = reqs[k].getExtDataInString(IAuthManager.CRED_CMC_SIGNING_CERT);
                if (tmpCertSerialS != null) {
                    // unlikely to happenm, but do this just in case
                    CMS.debug("ProfileSubmitCMCServlet: found existing CRED_CMC_SIGNING_CERT in request for CMCUserSignedAuth:" + tmpCertSerialS);
                    CMS.debug("ProfileSubmitCMCServlet: null it out");
                    reqs[k].setExtData(IAuthManager.CRED_CMC_SIGNING_CERT, "");
                }
                // put CMCUserSignedAuth authToken in request
                if (signingCertSerialS != null) {
                    CMS.debug("ProfileSubmitCMCServlet: setting CRED_CMC_SIGNING_CERT in request for CMCUserSignedAuth");
                    reqs[k].setExtData(IAuthManager.CRED_CMC_SIGNING_CERT, signingCertSerialS);
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
            } catch (ECMCPopFailedException e) {
                CMS.debug("ProfileSubmitCMCServlet: after populate - " + e.toString());
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String(e.toString());
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        OtherInfo.POP_FAILED, s);
                return;
            } catch (EProfileException e) {
                CMS.debug("ProfileSubmitCMCServlet: after populate - " + e.toString());
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
                CMS.debug("ProfileSubmitCMCServlet: after populate - " + e.toString());
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
        } //for

        String auditRequesterID = ILogger.UNIDENTIFIED;

        try {
            ///////////////////////////////////////////////
            // submit request
            ///////////////////////////////////////////////
            int error_codes[] = null;
            if (reqs != null && reqs.length > 0)
                error_codes = new int[reqs.length];

            for (int k = 0; (!isRevoke) && (provedReq == null) && (k < reqs.length); k++) {
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

                    X509CertImpl x509cert = reqs[k].getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);

                    if (x509cert != null) {

                        audit(CertRequestProcessedEvent.createSuccessEvent(
                                    auditSubjectID,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                    x509cert));
                    }

                } catch (EDeferException e) {
                    // return defer message to the user
                    CMS.debug("ProfileSubmitCMCServlet: set request to PENDING");
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
                } catch (ECMCPopRequiredException e) {
                    // return popRequired message to the user
                    CMS.debug("ProfileSubmitCMCServlet: popRequired; set request to PENDING");
                    reqs[k].setRequestStatus(RequestStatus.PENDING);
                    // need to notify
                    INotify notify = profile.getRequestQueue().getPendingNotify();
                    if (notify != null) {
                        notify.notify(reqs[k]);
                    }

                    CMS.debug("ProfileSubmitCMCServlet: submit " + e.toString());
                    errorCode = "4";
                    errorReason = CMS.getUserMessage(locale,
                                "CMS_PROFILE_CMC_POP_REQUIRED",
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

                        audit(CertRequestProcessedEvent.createFailureEvent(
                                    auditSubjectID,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_REJECTION,
                                    errorReason));

                    } else if (errorCode.equals("2")) {
                        // do NOT store a message in the signed audit log file
                        // as this errorCode indicates that a process has been
                        // deferred for manual acceptance/cancellation/rejection
                    } else if (errorCode.equals("3")) {

                        audit(CertRequestProcessedEvent.createFailureEvent(
                                    auditSubjectID,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_REJECTION,
                                    errorReason));
                    }
                    error_codes[k] = Integer.parseInt(errorCode);
                } else
                    error_codes[k] = 0;
            }

            // handle provedReq
            int otherInfoCode = OtherInfo.INTERNAL_CA_ERROR;
            if (provedReq != null) {
                error_codes = new int[1];

                auditRequesterID = auditRequesterID(provedReq);
                try {
                    profile.validate(provedReq);
                    profile.execute(provedReq);
                    reqs = new IRequest[1];
                    reqs[0] = provedReq;
                    reqs[0].setRequestStatus(RequestStatus.COMPLETE);
                    //profile.getRequestQueue().markAsServiced(provedReq);

                    X509CertImpl x509cert = reqs[0].getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);

                    if (x509cert != null) {

                        audit(CertRequestProcessedEvent.createSuccessEvent(
                                auditSubjectID,
                                auditRequesterID,
                                ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                x509cert));
                    }

                } catch (ERejectException e) {
                    // return error to the user
                    provedReq.setRequestStatus(RequestStatus.REJECTED);
                    CMS.debug("ProfileSubmitCMCServlet: provedReq submit- " + e.toString());
                    errorCode = "3";
                    errorReason = CMS.getUserMessage(locale,
                            "CMS_PROFILE_REJECTED",
                            e.toString());
                    otherInfoCode = OtherInfo.BAD_REQUEST;
                } catch (Exception e) {
                    // return error to the user
                    CMS.debug("ProfileSubmitCMCServlet: provedReq submit- " + e.toString());
                    errorCode = "1";
                    errorReason = CMS.getUserMessage(locale,
                            "CMS_INTERNAL_ERROR");
                }

                if (errorCode == null) {
                    profile.getRequestQueue().markAsServiced(provedReq);
                    CMS.debug("ProfileSubmitCMCServlet: provedReq set to complete");
                } else {
                    error_codes[0] = Integer.parseInt(errorCode);
                    profile.getRequestQueue().updateRequest(provedReq);
                    CMS.debug("ProfileSubmitCMCServlet: provedReq updateRequest");
                    audit(CertRequestProcessedEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                ILogger.SIGNED_AUDIT_REJECTION,
                                errorReason));
                }
            }

            if (errorCode != null) {
                if (errorCode.equals("4") /*POP required*/) {
                    // create the CMC full enrollment response for EncryptedPOP
                    CMCOutputTemplate template = new CMCOutputTemplate();
                    template.createFullResponse(response, reqs, cert_request_type, error_codes);
                    return;
                }

                // create the CMC full enrollment response for real error conditions
                CMCOutputTemplate template = new CMCOutputTemplate();
                SEQUENCE seq = new SEQUENCE();
                seq.addElement(new INTEGER(0));
                UTF8String s = null;
                try {
                    s = new UTF8String(errorReason);
                } catch (Exception ee) {
                }
                template.createFullResponseWithFailedStatus(response, seq,
                        otherInfoCode, s);

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
}
