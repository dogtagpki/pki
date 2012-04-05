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

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This servlet submits end-user request into the profile framework.
 *
 * @author Christina Fu (renewal support)
 * @version $Revision$, $Date$
 */
public class ProfileSubmitServlet extends ProfileServlet {

    /**
     *
     */
    private static final long serialVersionUID = 7557922703180866442L;
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

    private final static String[] SIGNED_AUDIT_AUTOMATED_REJECTION_REASON = new String[] {

    /* 0 */"automated profile cert request rejection:  "
            + "indeterminate reason for inability to process "
            + "cert request due to an EBaseException"
        };
    private final static String LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";

    private final static String LOGGING_SIGNED_AUDIT_AUTH_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTH_FAIL_4";
    private final static String LOGGING_SIGNED_AUDIT_AUTH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTH_SUCCESS_3";

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
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = (String) inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = (String) inputNames.nextElement();
                    if (request.getParameter(inputName) != null) {
                        // all subject name parameters start with sn_, no other input parameters do
                        if (inputName.matches("^sn_.*")) {
                            ctx.set(inputName, escapeValueRfc1779(request.getParameter(inputName), false).toString());
                        } else {
                            ctx.set(inputName, request.getParameter(inputName));
                        }
                    }
                }
            }
        }

    }

    /*
     * fill input info from "request" to context.
     * This is expected to be used by renewal where the request
     * is retrieved from request record
     */
    private void setInputsIntoContext(IRequest request, IProfile profile, IProfileContext ctx, Locale locale) {
        // passing inputs into context
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = (String) inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = (String) inputNames.nextElement();
                    String inputValue = "";
                    CMS.debug("ProfileSubmitServlet: setInputsIntoContext() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        CMS.debug("ProfileSubmitServlet: setInputsIntoContext() getvalue() failed: " + e.toString());
                    }

                    if (inputValue != null) {
                        CMS.debug("ProfileSubmitServlet: setInputsIntoContext() setting value in ctx:" + inputValue);
                        ctx.set(inputName, inputValue);
                    } else {
                        CMS.debug("ProfileSubmitServlet: setInputsIntoContext() value null");
                    }
                }
            }
        }

    }

    private void setCredentialsIntoContext(HttpServletRequest request, IProfileAuthenticator authenticator,
            IProfileContext ctx) {
        Enumeration<String> authIds = authenticator.getValueNames();

        if (authIds != null) {
            CMS.debug("ProfileSubmitServlet:setCredentialsIntoContext() authNames not null");
            while (authIds.hasMoreElements()) {
                String authName = (String) authIds.nextElement();

                CMS.debug("ProfileSubmitServlet:setCredentialsIntoContext() authName:" +
                        authName);
                if (request.getParameter(authName) != null) {
                    CMS.debug("ProfileSubmitServlet:setCredentialsIntoContext() authName found in request");
                    ctx.set(authName, request.getParameter(authName));
                } else {
                    CMS.debug("ProfileSubmitServlet:setCredentialsIntoContext() authName not found in request");
                }
            }
        } else {
            CMS.debug("ProfileSubmitServlet:setCredentialsIntoContext() authIds` null");
        }
    }

    String getUidFromDN(String userdn) {
        StringTokenizer st = new StringTokenizer(userdn, ",");
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            int i = t.indexOf("=");

            if (i == -1) {
                continue;
            }
            String n = t.substring(0, i);
            if (n.equalsIgnoreCase("uid")) {
                String v = t.substring(i + 1);
                CMS.debug("ProfileSubmitServlet:: getUidFromDN(): uid found:" + v);
                return v;
            } else {
                continue;
            }
        }
        return null;
    }

    /*
     *   authenticate for renewal - more to add necessary params/values
     *   to the session context
     */
    public IAuthToken authenticate(IProfileAuthenticator authenticator,
            HttpServletRequest request, IRequest origReq, SessionContext context)
            throws EBaseException {
        IAuthToken authToken = authenticate(authenticator, request);
        // For renewal, fill in necessary params
        if (authToken != null) {
            String ouid = origReq.getExtDataInString("auth_token.uid");
            // if the orig cert was manually approved, then there was
            // no auth token uid.  Try to get the uid from the cert dn
            // itself, if possible
            if (ouid == null) {
                String sdn = (String) context.get("origSubjectDN");
                if (sdn != null) {
                    ouid = getUidFromDN(sdn);
                    if (ouid != null)
                        CMS.debug("ProfileSubmitServlet: renewal: authToken original uid not found");
                }
            } else {
                CMS.debug("ProfileSubmitServlet: renewal: authToken original uid found in orig request auth_token");
            }
            String auid = authToken.getInString("uid");
            if (auid != null) { // not through ssl client auth
                CMS.debug("ProfileSubmitServlet: renewal: authToken uid found:" + auid);
                // authenticated with uid
                // put "orig_req.auth_token.uid" so that authz with
                // UserOrigReqAccessEvaluator will work
                if (ouid != null) {
                    context.put("orig_req.auth_token.uid", ouid);
                    CMS.debug("ProfileSubmitServlet: renewal: authToken original uid found:" + ouid);
                } else {
                    CMS.debug("ProfileSubmitServlet: renewal: authToken original uid not found");
                }
            } else { // through ssl client auth?
                CMS.debug("ProfileSubmitServlet: renewal: authToken uid not found:");
                // put in orig_req's uid
                if (ouid != null) {
                    CMS.debug("ProfileSubmitServlet: renewal: origReq uid not null:" + ouid + ". Setting authtoken");
                    authToken.set("uid", ouid);
                    context.put(SessionContext.USER_ID, ouid);
                } else {
                    CMS.debug("ProfileSubmitServlet: renewal: origReq uid not found");
                    //                      throw new EBaseException("origReq uid not found");
                }
            }

            String userdn = origReq.getExtDataInString("auth_token.userdn");
            if (userdn != null) {
                CMS.debug("ProfileSubmitServlet: renewal: origReq userdn not null:" + userdn + ". Setting authtoken");
                authToken.set("userdn", userdn);
            } else {
                CMS.debug("ProfileSubmitServlet: renewal: origReq userdn not found");
                //                      throw new EBaseException("origReq userdn not found");
            }
        } else {
            CMS.debug("ProfileSubmitServlet: renewal: authToken null");
        }
        return authToken;
    }

    public IAuthToken authenticate(IProfileAuthenticator authenticator,
            HttpServletRequest request) throws EBaseException {
        AuthCredentials credentials = new AuthCredentials();

        // build credential
        Enumeration<String> authNames = authenticator.getValueNames();

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
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = (String) inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                if (inputNames != null) {
                    while (inputNames.hasMoreElements()) {
                        String inputName = (String) inputNames.nextElement();

                        if (request.getParameter(inputName) != null) {
                            // special characters in subject names parameters must be escaped
                            if (inputName.matches("^sn_.*")) {
                                req.setExtData(inputName, escapeValueRfc1779(request.getParameter(inputName), false)
                                        .toString());
                            } else {
                                req.setExtData(inputName, request.getParameter(inputName));
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
                String inputId = (String) inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = (String) inputNames.nextElement();
                    String inputValue = "";
                    CMS.debug("ProfileSubmitServlet: setInputsIntoRequest() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        CMS.debug("ProfileSubmitServlet: setInputsIntoRequest() getvalue() failed: " + e.toString());
                    }

                    if (inputValue != null) {
                        CMS.debug("ProfileSubmitServlet: setInputsIntoRequest() setting value in ctx:" + inputValue);
                        req.setExtData(inputName, inputValue);
                    } else {
                        CMS.debug("ProfileSubmitServlet: setInputsIntoRequest() value null");
                    }
                }
            }
        }

    }

    private void setOutputIntoArgs(IProfile profile, ArgList outputlist, Locale locale, IRequest req) {
        Enumeration<String> outputIds = profile.getProfileOutputIds();

        if (outputIds != null) {
            while (outputIds.hasMoreElements()) {
                String outputId = (String) outputIds.nextElement();
                IProfileOutput profileOutput = profile.getProfileOutput(outputId);

                Enumeration<String> outputNames = profileOutput.getValueNames();

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
        boolean xmlOutput = false;

        String v = request.getParameter("xml");
        if ((v != null) && (v.equalsIgnoreCase("true"))) {
            xmlOutput = true;
        }
        v = request.getParameter("xmlOutput");
        if ((v != null) && (v.equalsIgnoreCase("true"))) {
            xmlOutput = true;
        }
        if (xmlOutput) {
            CMS.debug("xmlOutput true");
        } else {
            CMS.debug("xmlOutput false");
        }

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("enrollment", true /* main action */);
        }

        Locale locale = getLocale(request);
        ArgSet args = new ArgSet();

        if (CMS.debugOn()) {
            CMS.debug("Start of ProfileSubmitServlet Input Parameters");
            @SuppressWarnings("unchecked")
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
                    CMS.debug("ProfileSubmitServlet Input Parameter " +
                              paramName + "='(sensitive)'");
                } else {
                    CMS.debug("ProfileSubmitServlet Input Parameter " +
                              paramName + "='" +
                              request.getParameter(paramName) + "'");
                }
            }
            CMS.debug("End of ProfileSubmitServlet Input Parameters");
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

        /*
         * Renewal - Renewal is retrofitted into the Profile Enrollment
         * Framework.  The authentication and authorization are taken from
         * the renewal profile, while the input (with requests)  and grace
         * period constraint are taken from the original cert's request record.
         *
         * Things to note:
         * * the renew request will contain the original profile instead
         *   of the new
         * * there is no request for system and admin certs generated at
         *   time of installation configuration.
         */
        String renewal = request.getParameter("renewal");
        boolean isRenewal = false;
        if ((renewal != null) && (renewal.equalsIgnoreCase("true"))) {
            CMS.debug("ProfileSubmitServlet: isRenewal true");
            isRenewal = true;
            request.setAttribute("reqType", (Object) "renewal");
        } else {
            CMS.debug("ProfileSubmitServlet: isRenewal false");
        }

        String renewProfileId = null;
        IRequest origReq = null;
        Integer origSeqNum = 0;

        // if we did not configure profileId in xml file,
        // then accept the user-provided one
        String profileId = null;

        if (mProfileId == null) {
            profileId = request.getParameter("profileId");
        } else {
            profileId = mProfileId;
        }

        CMS.debug("ProfileSubmitServlet: profileId " + profileId);
        // This is the expiration date of the orig. cert that will
        // be used in the RenewGracePeriodConstraint
        Date origNotAfter = null;
        String origSubjectDN = null;

        if (isRenewal) {
            // dig up the original request to "clone"
            renewProfileId = profileId;
            CMS.debug("ProfileSubmitServlet: renewProfileId =" + renewProfileId);
            IAuthority authority = (IAuthority) CMS.getSubsystem(mAuthorityId);
            if (authority == null) {
                CMS.debug("ProfileSubmitServlet: renewal: Authority " + mAuthorityId +
                        " not found");
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);
                return;
            }
            IRequestQueue queue = authority.getRequestQueue();

            if (queue == null) {
                CMS.debug("ProfileSubmitServlet: renewal: Request Queue of " +
                        mAuthorityId + " not found");
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);
                return;
            }

            String serial = request.getParameter("serial_num");
            BigInteger certSerial = null;
            // if serial number is sent with request, then the authentication
            // method is not ssl client auth.  In this case, an alternative
            // authentication method is used (default: ldap based)
            if (serial != null) {
                CMS.debug("ProfileSubmitServlet: renewal: found serial_num");
                certSerial = new BigInteger(serial);
                // usr_origreq evaluator should be used to authorize ownership
                // of the cert
            } else {
                CMS.debug("ProfileSubmitServlet: renewal: serial_num not found, must do ssl client auth");
                // ssl client auth is to be used
                // this is not authentication. Just use the cert to search
                // for orig request and find the right profile
                SSLClientCertProvider sslCCP = new SSLClientCertProvider(request);
                X509Certificate[] certs = sslCCP.getClientCertificateChain();
                certSerial = null;
                if (certs == null || certs.length == 0) {
                    CMS.debug("ProfileSubmitServlet: renewal: no ssl client cert chain");
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                            "CMS_INTERNAL_ERROR"));
                    outputTemplate(request, response, args);
                    return;
                } else { // has ssl client cert
                    CMS.debug("ProfileSubmitServlet: renewal: has ssl client cert chain");
                    // shouldn't expect leaf cert to be always at the
                    // same location
                    X509Certificate clientCert = null;
                    for (int i = 0; i < certs.length; i++) {
                        clientCert = certs[i];
                        byte[] extBytes = clientCert.getExtensionValue("2.5.29.19");
                        // try to see if this is a leaf cert
                        // look for BasicConstraint extension
                        if (extBytes == null) {
                            // found leaf cert
                            CMS.debug("ProfileSubmitServlet: renewal: found leaf cert");
                            break;
                        } else {
                            CMS.debug("ProfileSubmitServlet: renewal: found cert having BasicConstraints ext");
                            // it's got BasicConstraints extension
                            // so it's not likely to be a leaf cert,
                            // however, check the isCA field regardless
                            try {
                                BasicConstraintsExtension bce =
                                        new BasicConstraintsExtension(true, extBytes);
                                if (bce != null) {
                                    if (!(Boolean) bce.get("is_ca")) {
                                        CMS.debug("ProfileSubmitServlet: renewal: found CA cert in chain");
                                        break;
                                    } // else found a ca cert, continue
                                }
                            } catch (Exception e) {
                                CMS.debug("ProfileSubmitServlet: renewal: exception:" +
                                        e.toString());
                                args.set(ARG_ERROR_CODE, "1");
                                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                        "CMS_INTERNAL_ERROR"));
                                outputTemplate(request, response, args);
                                return;
                            }
                        }
                    }
                    if (clientCert == null) {
                        CMS.debug("ProfileSubmitServlet: renewal: no client cert in chain");
                        args.set(ARG_ERROR_CODE, "1");
                        args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                "CMS_INTERNAL_ERROR"));
                        outputTemplate(request, response, args);
                        return;
                    }
                    // convert to java X509 cert interface
                    try {
                        byte[] certEncoded = clientCert.getEncoded();

                        clientCert = new X509CertImpl(certEncoded);
                    } catch (Exception e) {
                        CMS.debug("ProfileSubmitServlet: renewal: exception:" + e.toString());
                        args.set(ARG_ERROR_CODE, "1");
                        args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                "CMS_INTERNAL_ERROR"));
                        outputTemplate(request, response, args);
                        return;
                    }

                    certSerial = clientCert.getSerialNumber();
                }
            }

            CMS.debug("ProfileSubmitServlet: renewal: serial number of cert to renew:" + certSerial.toString());

            try {
                ICertificateRepository certDB = null;
                if (authority instanceof ICertificateAuthority) {
                    certDB = ((ICertificateAuthority) authority).getCertificateRepository();
                }
                if (certDB == null) {
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                            "CMS_INTERNAL_ERROR"));
                    outputTemplate(request, response, args);
                    return;
                }
                ICertRecord rec = (ICertRecord) certDB.readCertificateRecord(certSerial);
                if (rec == null) {
                    CMS.debug("ProfileSubmitServlet: renewal cert record not found for serial number "
                            + certSerial.toString());
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                            "CMS_INTERNAL_ERROR"));
                    outputTemplate(request, response, args);
                    return;
                } else {
                    CMS.debug("ProfileSubmitServlet: renewal cert record found for serial number:"
                            + certSerial.toString());
                    // check to see if the cert is revoked or revoked_expired
                    if ((rec.getStatus().equals(ICertRecord.STATUS_REVOKED))
                            || (rec.getStatus().equals(ICertRecord.STATUS_REVOKED_EXPIRED))) {
                        CMS.debug("ProfileSubmitServlet: renewal cert found to be revoked. Serial number = "
                                + certSerial.toString());
                        args.set(ARG_ERROR_CODE, "1");
                        args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                "CMS_CA_CANNOT_RENEW_REVOKED_CERT", certSerial.toString()));
                        outputTemplate(request, response, args);
                        return;
                    }
                    MetaInfo metaInfo = (MetaInfo) rec.get(ICertRecord.ATTR_META_INFO);
                    // note: CA's internal certs don't have request ids
                    // so some other way needs to be done
                    if (metaInfo != null) {
                        String rid = (String) metaInfo.get(ICertRecord.META_REQUEST_ID);

                        if (rid != null) {
                            origReq = queue.findRequest(new RequestId(rid));
                            if (origReq != null) {
                                CMS.debug("ProfileSubmitServlet: renewal: found original enrollment request id:" + rid);
                                // debug: print the extData keys
                                /*
                                Enumeration<String> en = origReq.getExtDataKeys();
                                                                CMS.debug("ProfileSubmitServlet: renewal: origRequest extdata key print BEGINS");
                                                                while (en.hasMoreElements()) {
                                                                  String next = (String) en.nextElement();
                                                                  CMS.debug("ProfileSubmitServlet: renewal: origRequest extdata key:"+ next);
                                                                }
                                                                CMS.debug("ProfileSubmitServlet: renewal: origRequest extdata key print ENDS");
                                */
                                String requestorE = origReq.getExtDataInString("requestor_email");
                                CMS.debug("ProfileSubmitServlet: renewal original requestor email=" + requestorE);
                                profileId = origReq.getExtDataInString("profileId");
                                if (profileId != null)
                                    CMS.debug("ProfileSubmitServlet: renewal original profileId=" + profileId);
                                else {
                                    CMS.debug("ProfileSubmitServlet: renewal original profileId not found");
                                    args.set(ARG_ERROR_CODE, "1");
                                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                            "CMS_INTERNAL_ERROR"));
                                    outputTemplate(request, response, args);
                                    return;
                                }
                                origSeqNum = origReq.getExtDataInInteger(IEnrollProfile.REQUEST_SEQ_NUM);

                            } else { //if origReq
                                CMS.debug("ProfileSubmitServlet: renewal original request not found for request id "
                                        + rid);
                                args.set(ARG_ERROR_CODE, "1");
                                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                        "CMS_INTERNAL_ERROR"));
                                outputTemplate(request, response, args);
                                return;
                            }
                        } else {
                            CMS.debug("ProfileSubmitServlet: renewal: cert record locating request id in MetaInfo failed for serial number "
                                    + certSerial.toString());
                            CMS.debug("ProfileSubmitServlet: renewal: cert may be bootstrapped system cert during installation/configuration - no request record exists");
                            args.set(ARG_ERROR_CODE, "1");
                            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                    "CMS_INTERNAL_ERROR" + ": original request not found"));
                            outputTemplate(request, response, args);
                            return;
                        }
                    } else {
                        CMS.debug("ProfileSubmitServlet: renewal: cert record locating MetaInfo failed for serial number "
                                + certSerial.toString());
                        args.set(ARG_ERROR_CODE, "1");
                        args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                "CMS_INTERNAL_ERROR"));
                        outputTemplate(request, response, args);
                        return;
                    }
                    // get orig cert expiration date
                    CMS.debug("ProfileSubmitServlet: renewal: before getting origNotAfter");
                    X509CertImpl origCert = rec.getCertificate();
                    origNotAfter = origCert.getNotAfter();
                    CMS.debug("ProfileSubmitServlet: renewal: origNotAfter =" +
                            origNotAfter.toString());
                    origSubjectDN = origCert.getSubjectDN().getName();
                    CMS.debug("ProfileSubmitServlet: renewal: orig subj dn =" +
                            origSubjectDN);
                }
            } catch (Exception e) {
                CMS.debug("ProfileSubmitServlet: renewal: exception:" + e.toString());
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);
                return;
            }
        } // end isRenewal

        IProfile profile = null;
        IProfile renewProfile = null;

        try {
            profile = ps.getProfile(profileId);
            if (isRenewal) {
                // in case of renew, "profile" is the orig profile
                // while "renewProfile" is the current profile used for renewal
                renewProfile = ps.getProfile(renewProfileId);
            }
        } catch (EProfileException e) {
            if (profile == null) {
                CMS.debug("ProfileSubmitServlet: profile not found profileId " +
                        profileId + " " + e.toString());
            }
            if (renewProfile == null) {
                CMS.debug("ProfileSubmitServlet: profile not found renewProfileId " +
                        renewProfileId + " " + e.toString());
            }
        }
        if (profile == null) {
            if (xmlOutput) {
                outputError(response, CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_PROFILE_NOT_FOUND", profileId));
                outputTemplate(request, response, args);
            }
            return;
        }
        if (isRenewal && (renewProfile == null)) {
            if (xmlOutput) {
                outputError(response, CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", renewProfileId));
            } else {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_PROFILE_NOT_FOUND", renewProfileId));
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

        if (isRenewal) {
            if (!ps.isProfileEnable(renewProfileId)) {
                CMS.debug("ProfileSubmitServlet: renewal Profile " + renewProfileId +
                        " not enabled");
                if (xmlOutput) {
                    outputError(response, CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", renewProfileId));
                } else {
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                            "CMS_PROFILE_NOT_FOUND", renewProfileId));
                    outputTemplate(request, response, args);
                }
                return;
            }
        }

        IProfileContext ctx = profile.createContext();
        // passing auths into context
        IProfileAuthenticator authenticator = null;
        IProfileAuthenticator origAuthenticator = null;

        try {
            if (isRenewal) {
                authenticator = renewProfile.getAuthenticator();
                origAuthenticator = profile.getAuthenticator();
            } else {
                authenticator = profile.getAuthenticator();
            }
        } catch (EProfileException e) {
            // authenticator not installed correctly
            CMS.debug("ProfileSubmitServlet: renewal: exception:" + e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }
        if (authenticator == null) {
            CMS.debug("ProfileSubmitServlet: authenticator not found");
        } else {
            CMS.debug("ProfileSubmitServlet: authenticator " +
                    authenticator.getName() + " found");
            setCredentialsIntoContext(request, authenticator, ctx);
        }

        // for renewal, this will override or add auth info to the profile context
        if (isRenewal) {
            if (origAuthenticator != null) {
                CMS.debug("ProfileSubmitServlet: for renewal, original authenticator " +
                        origAuthenticator.getName() + " found");
                setCredentialsIntoContext(request, origAuthenticator, ctx);
            } else {
                CMS.debug("ProfileSubmitServlet: for renewal, original authenticator not found");
            }
        }

        CMS.debug("ProfileSubmistServlet: set Inputs into profile Context");
        if (isRenewal) {
            // for renewal, input needs to be retrieved from the orig req record
            CMS.debug("ProfileSubmitServlet: set original Inputs into profile Context");
            setInputsIntoContext(origReq, profile, ctx, locale);
            ctx.set(IEnrollProfile.CTX_RENEWAL, "true");
            ctx.set("renewProfileId", renewProfileId);
            ctx.set(IEnrollProfile.CTX_RENEWAL_SEQ_NUM, origSeqNum.toString());
        } else {
            setInputsIntoContext(request, profile, ctx);
        }

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
        if ((isRenewal == true) && (origSubjectDN != null))
            context.put("origSubjectDN", origSubjectDN);
        if (statsSub != null) {
            statsSub.startTiming("profile_authentication");
        }

        if (authenticator != null) {

            CMS.debug("ProfileSubmitServlet: authentication required.");
            String uid_cred = "Unidentified";
            String uid_attempted_cred = "Unidentified";
            Enumeration<String> authIds = authenticator.getValueNames();
            //Attempt to possibly fetch attemped uid, may not always be available.
            if (authIds != null) {
                while (authIds.hasMoreElements()) {
                    String authName = authIds.nextElement();
                    String value = request.getParameter(authName);
                    if (value != null) {
                        if (authName.equals("uid")) {
                            uid_attempted_cred = value;
                        }
                    }
                }
            }

            String authSubjectID = auditSubjectID();

            String authMgrID = authenticator.getName();
            String auditMessage = null;
            try {
                if (isRenewal) {
                    CMS.debug("ProfileSubmitServlet: renewal authenticate begins");
                    authToken = authenticate(authenticator, request, origReq, context);
                    CMS.debug("ProfileSubmitServlet: renewal authenticate ends");
                } else {
                    authToken = authenticate(authenticator, request);
                }
            } catch (EBaseException e) {
                CMS.debug("ProfileSubmitServlet: authentication error " +
                        e.toString());
                // authentication error
                if (xmlOutput) {
                    outputError(response, CMS.getUserMessage(locale, "CMS_AUTHENTICATION_ERROR"));
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

                //audit log our authentication failure

                authSubjectID += " : " + uid_cred;
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                        authSubjectID,
                        ILogger.FAILURE,
                        authMgrID,
                        uid_attempted_cred);
                audit(auditMessage);

                return;
            }

            //Log successful authentication

            //Attempt to get uid from authToken, most tokens respond to the "uid" cred.
            uid_cred = authToken.getInString("uid");

            if (uid_cred == null || uid_cred.length() == 0) {
                uid_cred = "Unidentified";
            }

            authSubjectID = authSubjectID + " : " + uid_cred;

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_SUCCESS,
                        authSubjectID,
                        ILogger.SUCCESS,
                        authMgrID);

            audit(auditMessage);

        }
        if (statsSub != null) {
            statsSub.endTiming("profile_authentication");
        }

        // authentication success
        if (authToken != null) {
            CMS.debug("ProfileSubmitServlet authToken not null");
            // do profile authorization
            String acl = null;
            if (isRenewal)
                acl = renewProfile.getAuthzAcl();
            else
                acl = profile.getAuthzAcl();
            CMS.debug("ProfileSubmitServlet: authz using acl: " + acl);
            if (acl != null && acl.length() > 0) {
                try {
                    String resource = profileId + ".authz.acl";
                    authorize(mAclMethod, resource, authToken, acl);
                } catch (Exception e) {
                    CMS.debug("ProfileSubmitServlet authorize: " + e.toString());
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
            CMS.debug("ProfileSubmitServlet: createRequests " + e.toString());
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
            if (isRenewal) {
                setInputsIntoRequest(origReq, profile, reqs[k], locale);
                // set orig expiration date to be used in Validity constraint
                reqs[k].setExtData("origNotAfter",
                        BigInteger.valueOf(origNotAfter.getTime()));
                // set subjectDN to be used in subject name default
                reqs[k].setExtData(IProfileAuthenticator.AUTHENTICATED_NAME, origSubjectDN);
                // set request type
                reqs[k].setRequestType("renewal");
            } else
                setInputsIntoRequest(request, profile, reqs[k]);

            // serial auth token into request
            if (authToken != null) {
                Enumeration<String> tokenNames = authToken.getElements();
                while (tokenNames.hasMoreElements()) {
                    String tokenName = tokenNames.nextElement();
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
                CMS.debug("ProfileSubmitServlet: request from RA: " + uid);
                reqs[k].setExtData(ARG_REQUEST_OWNER, uid);
            }

            // put profile framework parameters into the request
            reqs[k].setExtData(ARG_PROFILE, "true");
            reqs[k].setExtData(ARG_PROFILE_ID, profileId);
            if (isRenewal)
                reqs[k].setExtData(ARG_RENEWAL_PROFILE_ID, request.getParameter("profileId"));
            reqs[k].setExtData(ARG_PROFILE_APPROVED_BY, profile.getApprovedBy());
            String setId = profile.getPolicySetId(reqs[k]);

            if (setId == null) {
                // no profile set found
                CMS.debug("ProfileSubmitServlet: no profile policy set found");
                if (xmlOutput) {
                    outputError(response, FAILED, CMS.getUserMessage("CMS_PROFILE_NO_POLICY_SET_FOUND"),
                            reqs[k].getRequestId().toString());
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
                    outputError(response, FAILED, e.toString(), reqs[k].getRequestId().toString());
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
                    outputError(response, FAILED, CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"),
                            reqs[k].getRequestId().toString());
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
            String requestIds = ""; // deliminated with double space
            for (int k = 0; k < reqs.length; k++) {
                try {
                    // reset the "auditRequesterID"
                    auditRequesterID = auditRequesterID(reqs[k]);

                    // print request debug
                    if (reqs[k] != null) {
                        requestIds += "  " + reqs[k].getRequestId().toString();
                        Enumeration<String> reqKeys = reqs[k].getExtDataKeys();
                        while (reqKeys.hasMoreElements()) {
                            String reqKey = reqKeys.nextElement();
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
                    if (errorCode == null) {
                        profile.getRequestQueue().markAsServiced(reqs[k]);
                    } else {
                        profile.getRequestQueue().updateRequest(reqs[k]);
                    }
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
                    // when errorCode is not null, requestIds should have >=1
                    outputError(response, errorCode, errorReason, requestIds);
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
            SessionContext.releaseContext();
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
            CMS.debug("ProfileSubmitServlet xmlOutput: req len = " + reqs.length);

            for (int i = 0; i < reqs.length; i++) {
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
                Enumeration<String> outputIds = profile.getProfileOutputIds();
                if (outputIds != null) {
                    while (outputIds.hasMoreElements()) {
                        String outputId = outputIds.nextElement();
                        IProfileOutput profileOutput = profile.getProfileOutput(outputId);
                        Enumeration<String> outputNames = profileOutput.getValueNames();
                        if (outputNames != null) {
                            while (outputNames.hasMoreElements()) {
                                String outputName = outputNames.nextElement();
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
                                    CMS.debug("ProfileSubmitServlet xmlOutput: " + e.toString());
                                } catch (Exception e) {
                                    CMS.debug("ProfileSubmitServlet xmlOutput: " + e.toString());
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
