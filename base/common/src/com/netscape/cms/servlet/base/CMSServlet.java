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
package com.netscape.cms.servlet.base;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.apps.ICommandQueue;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.common.CMSFileLoader;
import com.netscape.cms.servlet.common.CMSGateway;
import com.netscape.cms.servlet.common.CMSLoadTemplate;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.GenErrorTemplateFiller;
import com.netscape.cms.servlet.common.GenPendingTemplateFiller;
import com.netscape.cms.servlet.common.GenRejectedTemplateFiller;
import com.netscape.cms.servlet.common.GenSuccessTemplateFiller;
import com.netscape.cms.servlet.common.GenSvcPendingTemplateFiller;
import com.netscape.cms.servlet.common.GenUnexpectedErrorTemplateFiller;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cms.servlet.common.ServletUtils;
import com.netscape.cmsutil.util.Utils;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This is the base class of all CS servlet.
 *
 * @version $Revision$, $Date$
 */
public abstract class CMSServlet extends HttpServlet {
    /**
     *
     */
    private static final long serialVersionUID = -3886300199374147160L;
    // servlet init params
    // xxxx todo:Should enforce init param value checking!
    public final static String SUCCESS = "0";
    public final static String FAILURE = "1";
    public final static String AUTH_FAILURE = "2";

    public final static String PROP_ID = "ID";
    public final static String PROP_AUTHORITY = "authority";
    public final static String PROP_AUTHORITYID = "authorityId";
    public final static String PROP_AUTHMGR = "AuthMgr";
    public final static String PROP_CLIENTAUTH = "GetClientCert";
    public final static String PROP_RESOURCEID = "resourceID";

    public final static String AUTHZ_SRC_LDAP = "ldap";
    public final static String AUTHZ_SRC_TYPE = "sourceType";
    public final static String AUTHZ_CONFIG_STORE = "authz";
    public final static String AUTHZ_SRC_XML = "web.xml";
    public final static String PROP_AUTHZ_MGR = "AuthzMgr";
    public final static String PROP_ACL = "ACLinfo";
    public final static String AUTHZ_MGR_BASIC = "BasicAclAuthz";
    public final static String AUTHZ_MGR_LDAP = "DirAclAuthz";
    private final static String HDR_LANG = "accept-language";

    // final error message - if error and exception templates don't work
    // send out this text string directly to output.

    public final static String PROP_FINAL_ERROR_MSG = "finalErrorMsg";
    public final static String ERROR_MSG_TOKEN = "$ERROR_MSG";
    public final static String FINAL_ERROR_MSG =
            "<HTML>\n" +
                    "<BODY BGCOLOR=white>\n" +
                    "<P>\n" +
                    "The Certificate System has encountered " +
                    "an unrecoverable error.\n" +
                    "<P>\n" +
                    "Error Message:<BR>\n" +
                    "<I>$ERROR_MSG</I>\n" +
                    "<P>\n" +
                    "Please contact your local administrator for assistance.\n" +
                    "</BODY>\n" +
                    "</HTML>\n";

    // properties from configuration.

    protected final static String PROP_UNAUTHORIZED_TEMPLATE = "unauthorizedTemplate";
    protected final static String UNAUTHORIZED_TEMPLATE = "/GenUnauthorized.template";
    protected final static String PROP_SUCCESS_TEMPLATE = "successTemplate";
    protected final static String SUCCESS_TEMPLATE = "/GenSuccess.template";
    protected final static String PROP_PENDING_TEMPLATE = "pendingTemplate";
    protected final static String PENDING_TEMPLATE = "/GenPending.template";
    protected final static String PROP_SVC_PENDING_TEMPLATE = "svcpendingTemplate";
    protected final static String SVC_PENDING_TEMPLATE = "/GenSvcPending.template";
    protected final static String PROP_REJECTED_TEMPLATE = "rejectedTemplate";
    protected final static String REJECTED_TEMPLATE = "/GenRejected.template";
    protected final static String PROP_ERROR_TEMPLATE = "errorTemplate";
    protected final static String ERROR_TEMPLATE = "/GenError.template";
    protected final static String PROP_EXCEPTION_TEMPLATE = "unexpectedErrorTemplate";
    protected final static String EXCEPTION_TEMPLATE = "/GenUnexpectedError.template";

    private final static String PROP_UNAUTHOR_TEMPLATE_FILLER = "unauthorizedTemplateFiller";
    protected final static String PROP_SUCCESS_TEMPLATE_FILLER = "successTemplateFiller";
    private final static String PROP_ERROR_TEMPLATE_FILLER = "errorTemplateFiller";
    private final static String PROP_PENDING_TEMPLATE_FILLER = "pendingTemplateFiller";
    private final static String PROP_SVC_PENDING_TEMPLATE_FILLER = "svcpendingTemplateFiller";
    private final static String PROP_REJECTED_TEMPLATE_FILLER = "rejectedTemplateFiller";
    private final static String PROP_EXCEPTION_TEMPLATE_FILLER = "exceptionTemplateFiller";

    protected final static String RA_AGENT_GROUP = "Registration Manager Agents";
    protected final static String CA_AGENT_GROUP = "Certificate Manager Agents";
    protected final static String KRA_AGENT_GROUP = "Data Recovery Manager Agents";
    protected final static String OCSP_AGENT_GROUP = "Online Certificate Status Manager Agents";
    protected final static String TRUSTED_RA_GROUP = "Trusted Managers";
    protected final static String ADMIN_GROUP = "Administrators";

    // default http params NOT to save in request.(config values added to list )
    private static final String PROP_DONT_SAVE_HTTP_PARAMS = "dontSaveHttpParams";
    private static final String[] DONT_SAVE_HTTP_PARAMS = { "pwd", "password", "passwd",
            "challengePassword", "confirmChallengePassword" };

    // default http headers to save in request. (config values added to list)
    private static final String PROP_SAVE_HTTP_HEADERS = "saveHttpHeaders";
    private static final String[] SAVE_HTTP_HEADERS = { "accept-language", "user-agent", };

    // request prefixes to distinguish from other request attributes.
    public static final String PFX_HTTP_HEADER = "HTTP_HEADER";
    public static final String PFX_HTTP_PARAM = "HTTP_PARAM";
    public static final String PFX_AUTH_TOKEN = "AUTH_TOKEN";

    /* input http params */
    protected final static String AUTHMGR_PARAM = "authenticator";

    /* fixed credential passed to auth managers */
    protected final static String CERT_AUTH_CRED = "sslClientCert";

    public static final String CERT_ATTR =
            "javax.servlet.request.X509Certificate";

    // members.

    protected ServletConfig servletConfig;

    protected boolean mRenderResult = true;
    protected String mFinalErrorMsg = FINAL_ERROR_MSG;
    protected Hashtable<Integer, CMSLoadTemplate> mTemplates = new Hashtable<Integer, CMSLoadTemplate>();

    protected ServletConfig mServletConfig = null;
    protected ServletContext mServletContext = null;
    private CMSFileLoader mFileLoader = null;

    protected Vector<String> mDontSaveHttpParams = new Vector<String>();
    protected Vector<String> mSaveHttpHeaders = new Vector<String>();

    protected String mId = null;
    protected IConfigStore mConfig = null;

    // the authority, RA, CA, KRA this servlet is serving.
    protected IAuthority mAuthority = null;
    protected ICertificateAuthority certAuthority;
    protected IRequestQueue mRequestQueue = null;

    // system logger.
    protected ILogger mLogger = CMS.getLogger();
    protected int mLogCategory = ILogger.S_OTHER;
    private MessageDigest mSHADigest = null;

    protected String mGetClientCert = "false";
    protected String mAuthMgr = null;
    protected IAuthzSubsystem mAuthz = null;

    protected String mAclMethod = null;
    protected String mAuthzResourceName = null;

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    protected String mOutputTemplatePath = null;
    private IUGSubsystem mUG = (IUGSubsystem)
            CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    private final static String LOGGING_SIGNED_AUDIT_AUTH_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTH_FAIL_4";
    private final static String LOGGING_SIGNED_AUDIT_AUTH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTH_SUCCESS_3";
    private final static String LOGGING_SIGNED_AUDIT_AUTHZ_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTHZ_FAIL_4";
    private final static String LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS_4";
    private final static String LOGGING_SIGNED_AUDIT_ROLE_ASSUME =
            "LOGGING_SIGNED_AUDIT_ROLE_ASSUME_3";

    public CMSServlet() {
    }

    public static Hashtable<String, String> toHashtable(HttpServletRequest req) {
        Hashtable<String, String> httpReqHash = new Hashtable<String, String>();
        Enumeration<?> names = req.getParameterNames();

        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();

            httpReqHash.put(name, req.getParameter(name));
        }
        return httpReqHash;
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        this.servletConfig = sc;

        mAuthz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
        mId = sc.getInitParameter(PROP_ID);

        try {
            mAclMethod = ServletUtils.initializeAuthz(sc, mAuthz, mId);
        } catch (ServletException e) {
            log(ILogger.LL_FAILURE, e.toString());
            throw e;
        }

        mConfig = CMS.getConfigStore().getSubStore(CMSGateway.PROP_CMSGATEWAY);
        mServletConfig = sc;
        mServletContext = sc.getServletContext();
        mFileLoader = new CMSFileLoader();

        mGetClientCert = sc.getInitParameter(PROP_CLIENTAUTH);
        mAuthMgr = sc.getInitParameter(PROP_AUTHMGR);
        mAuthzResourceName = sc.getInitParameter(PROP_RESOURCEID);
        mOutputTemplatePath = sc.getInitParameter("templatePath");

        String authority = sc.getInitParameter(PROP_AUTHORITY);
        if (authority == null) {
            authority = sc.getInitParameter(PROP_AUTHORITYID);
        }

        if (authority != null) {
            mAuthority = (IAuthority) CMS.getSubsystem(authority);
            if (mAuthority instanceof ICertificateAuthority)
                certAuthority = (ICertificateAuthority) mAuthority;
        }
        if (mAuthority != null)
            mRequestQueue = mAuthority.getRequestQueue();

        // set default templates.
        setDefaultTemplates(sc);

        // for logging to the right authority category.
        if (mAuthority == null) {
            mLogCategory = ILogger.S_OTHER;
        } else {
            if (mAuthority instanceof ICertificateAuthority)
                mLogCategory = ILogger.S_CA;
            else if (mAuthority instanceof IRegistrationAuthority)
                mLogCategory = ILogger.S_RA;
            else if (mAuthority instanceof IKeyRecoveryAuthority)
                mLogCategory = ILogger.S_KRA;
            else
                mLogCategory = ILogger.S_OTHER;
        }

        try {
            // get final error message.
            // used when templates can't even be loaded.
            String eMsg =
                    sc.getInitParameter(PROP_FINAL_ERROR_MSG);

            if (eMsg != null)
                mFinalErrorMsg = eMsg;

            // get any configured templates.
            Enumeration<CMSLoadTemplate> templs = mTemplates.elements();

            while (templs.hasMoreElements()) {
                CMSLoadTemplate templ = templs.nextElement();

                if (templ == null || templ.mPropName == null) {
                    continue;
                }
                String tName =
                        sc.getInitParameter(templ.mPropName);

                if (tName != null)
                    templ.mTemplateName = tName;
                String fillerName =
                        sc.getInitParameter(templ.mFillerPropName);

                if (fillerName != null) {
                    ICMSTemplateFiller filler = newFillerObject(fillerName);

                    if (filler != null)
                        templ.mFiller = filler;
                }
            }

            // get http params NOT to store in a IRequest and
            // get http headers TO store in a IRequest.
            getDontSaveHttpParams(sc);
            getSaveHttpHeaders(sc);
        } catch (Exception e) {
            // should never occur since we provide defaults above.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_CONF_TEMP_PARAMS",
                            e.toString()));
            throw new ServletException(e.toString());
        }

        try {
            mSHADigest = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_CONF_TEMP_PARAMS",
                            e.toString()));
            throw new ServletException(e.toString());
        }
    }

    public String getId() {
        return mId;
    }

    public String getAuthMgr() {
        return mAuthMgr;
    }

    public boolean isClientCertRequired() {
        if (mGetClientCert != null && mGetClientCert.equals("true"))
            return true;
        else
            return false;
    }

    public void outputHttpParameters(HttpServletRequest httpReq) {
        CMS.debug("CMSServlet:service() uri = " + httpReq.getRequestURI());
        Enumeration<?> paramNames = httpReq.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String pn = (String) paramNames.nextElement();
            // added this facility so that password can be hidden,
            // all sensitive parameters should be prefixed with
            // __ (double underscores); however, in the event that
            // a security parameter slips through, we perform multiple
            // additional checks to insure that it is NOT displayed
            if (pn.startsWith("__") ||
                    pn.endsWith("password") ||
                    pn.endsWith("passwd") ||
                    pn.endsWith("pwd") ||
                    pn.equalsIgnoreCase("admin_password_again") ||
                    pn.equalsIgnoreCase("directoryManagerPwd") ||
                    pn.equalsIgnoreCase("bindpassword") ||
                    pn.equalsIgnoreCase("bindpwd") ||
                    pn.equalsIgnoreCase("passwd") ||
                    pn.equalsIgnoreCase("password") ||
                    pn.equalsIgnoreCase("pin") ||
                    pn.equalsIgnoreCase("pwd") ||
                    pn.equalsIgnoreCase("pwdagain") ||
                    pn.startsWith("p12Password") ||
                    pn.equalsIgnoreCase("uPasswd")) {
                CMS.debug("CMSServlet::service() param name='" + pn +
                        "' value='(sensitive)'");
            } else {
                CMS.debug("CMSServlet::service() param name='" + pn +
                        "' value='" + httpReq.getParameter(pn) + "'");
            }
        }
    }

    public void service(HttpServletRequest httpReq,
            HttpServletResponse httpResp)
            throws ServletException, IOException {

        boolean running_state = CMS.isInRunningState();

        if (!running_state)
            throw new IOException(
                    "CS server is not ready to serve.");

        try {
            if (CMS.getConfigStore().getBoolean("useThreadNaming", false)) {
                String currentName = Thread.currentThread().getName();

                Thread.currentThread().setName(currentName + "-" + httpReq.getServletPath());
            }
        } catch (Exception e) {
        }

        httpReq.setCharacterEncoding("UTF-8");

        if (CMS.debugOn()) {
            outputHttpParameters(httpReq);
        }
        CMS.debug("CMSServlet: " + mId + " start to service.");

        // get a cms request
        CMSRequest cmsRequest = newCMSRequest();

        // set argblock
        cmsRequest.setHttpParams(CMS.createArgBlock("http-request-params", toHashtable(httpReq)));

        // set http request
        cmsRequest.setHttpReq(httpReq);

        // set http response
        cmsRequest.setHttpResp(httpResp);

        // set servlet config.
        cmsRequest.setServletConfig(mServletConfig);

        // set servlet context.
        cmsRequest.setServletContext(mServletContext);

        IArgBlock httpArgs = cmsRequest.getHttpParams();

        // authenticator value from http overrides the value in web.xml.
        String authMgr_http = httpArgs.getValueAsString(AUTHMGR_PARAM, null);

        if (authMgr_http != null) {
            mAuthMgr = authMgr_http;
        } else {
            mAuthMgr = mServletConfig.getInitParameter(PROP_AUTHMGR);
        }

        // process request.
        ICommandQueue iCommandQueue = CMS.getCommandQueue();

        try {
            if (iCommandQueue.registerProcess(cmsRequest, this) == false) {
                cmsRequest.setStatus(ICMSRequest.ERROR);
                renderResult(cmsRequest);
                SessionContext.releaseContext();
                return;
            }
            long startTime = CMS.getCurrentDate().getTime();
            process(cmsRequest);
            renderResult(cmsRequest);
            Date endDate = CMS.getCurrentDate();
            long endTime = endDate.getTime();
            if (CMS.debugOn()) {
                CMS.debug(CMS.DEBUG_INFORM, "CMSServlet: curDate="
                        + endDate + " id=" + mId + " time=" + (endTime - startTime));
            }
            iCommandQueue.unRegisterProccess(cmsRequest, this);
        } catch (EBaseException e) {
            iCommandQueue.unRegisterProccess(cmsRequest, this);
            // ByteArrayOutputStream os = new ByteArrayOutputStream(); for debugging only
            // PrintStream ps = new PrintStream(os);
            //e.printStackTrace(ps);
            log(e.toString());
            renderException(cmsRequest, e);
        } catch (Exception ex) {
            iCommandQueue.unRegisterProccess(cmsRequest, this);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(os);

            ex.printStackTrace(ps);
            log(os.toString());
            renderFinalError(cmsRequest, ex);
        }

        // destroy SessionContext
        SessionContext.releaseContext();

        return;
    }

    /**
     * Create a new CMSRequest object. This should be overriden by servlets
     * implementing different types of request
     *
     * @return a new CMSRequest object
     */
    protected CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * process an HTTP request. Servlets must override this with their
     * own implementation
     *
     * @throws EBaseException if the servlet was unable to satisfactorily
     *             process the request
     */
    protected void process(CMSRequest cmsRequest)
            throws EBaseException {
    }

    /**
     * Output a template.
     * If an error occurs while outputing the template the exception template
     * is used to display the error.
     *
     * @param cmsReq the CS request
     */
    protected void renderResult(CMSRequest cmsReq)
            throws IOException {

        if (!mRenderResult)
            return;
        Integer status = cmsReq.getStatus();

        CMSLoadTemplate ltempl = mTemplates.get(status);

        if (ltempl == null || ltempl.mTemplateName == null) {
            // result is previously outputed.
            return;
        }
        ICMSTemplateFiller filler = ltempl.mFiller;

        renderTemplate(cmsReq, ltempl.mTemplateName, filler);
    }

    private static final String PRESERVED = "preserved";
    public static final String TEMPLATE_NAME = "templateName";

    protected void outputArgBlockAsXML(XMLObject xmlObj, Node parent,
                                       String argBlockName, IArgBlock argBlock) {
        Node argBlockContainer = xmlObj.createContainer(parent, argBlockName);

        if (argBlock != null) {
            Enumeration<String> names = argBlock.getElements();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                String val = argBlock.get(name).toString();
                val = val.trim();
                xmlObj.addItemToContainer(argBlockContainer, name, val);
            }
        }
    }

    protected void outputXML(HttpServletResponse httpResp, CMSTemplateParams params) {
        XMLObject xmlObj = null;
        try {
            xmlObj = new XMLObject();

            Node root = xmlObj.createRoot("xml");
            outputArgBlockAsXML(xmlObj, root, "header", params.getHeader());
            outputArgBlockAsXML(xmlObj, root, "fixed", params.getFixed());

            Enumeration<IArgBlock> records = params.queryRecords();
            Node recordsNode = xmlObj.createContainer(root, "records");
            if (records != null) {
                while (records.hasMoreElements()) {
                    IArgBlock record = records.nextElement();
                    outputArgBlockAsXML(xmlObj, recordsNode, "record", record);
                }
            }

            byte[] cb = xmlObj.toByteArray();
            OutputStream os = httpResp.getOutputStream();
            httpResp.setContentType("application/xml");
            httpResp.setContentLength(cb.length);
            os.write(cb);
            os.flush();
        } catch (Exception e) {
            CMS.debug("failed in outputing XML " + e);
        }
    }

    protected void renderTemplate(
            CMSRequest cmsReq, String templateName, ICMSTemplateFiller filler)
            throws IOException {
        try {
            IArgBlock httpParams = cmsReq.getHttpParams();

            Locale[] locale = new Locale[1];
            CMSTemplate template =
                    getTemplate(templateName, cmsReq.getHttpReq(), locale);
            CMSTemplateParams templateParams = null;

            if (filler != null) {
                templateParams = filler.getTemplateParams(
                            cmsReq, mAuthority, locale[0], null);
            }

            // just output arg blocks as XML
            CMS.debug("CMSServlet.java: renderTemplate");
            String xmlOutput = cmsReq.getHttpReq().getParameter("xml");
            if (xmlOutput != null && xmlOutput.equals("true")) {
                CMS.debug("CMSServlet.java: xml parameter detected, returning xml");
                outputXML(cmsReq.getHttpResp(), templateParams);
                return;
            }

            if (httpParams != null) {
                String httpTemplateName =
                        httpParams.getValueAsString(
                                TEMPLATE_NAME, null);

                if (httpTemplateName != null) {
                    templateName = httpTemplateName;
                }
            }

            if (templateParams == null)
                templateParams = new CMSTemplateParams(null, null);

            // #359630
            // inject preserved http parameter into the template
            if (httpParams != null) {
                String preserved = httpParams.getValueAsString(
                        PRESERVED, null);

                if (preserved != null) {
                    IArgBlock fixed = templateParams.getFixed();

                    if (fixed != null) {
                        fixed.set(PRESERVED, preserved);
                    }
                }
            }

            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            template.renderOutput(bos, templateParams);
            cmsReq.getHttpResp().setContentType("text/html");
            cmsReq.getHttpResp().setContentLength(bos.size());
            bos.writeTo(cmsReq.getHttpResp().getOutputStream());
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_OUT_TEMPLATE", templateName, e.toString()));
            renderException(cmsReq,
                    new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE")));
            return;
        }
    }

    /**
     * Output exception (unexpected error) template
     * This is different from other templates in that if an exception occurs
     * while rendering the exception a message is printed out directly.
     * If the message gets an error an IOException is thrown.
     * In others if an exception occurs while rendering the template the
     * exception template (this) is called.
     * <p>
     *
     * @param cmsReq the CS request to pass to template filler if any.
     * @param e the unexpected exception
     */
    protected void renderException(CMSRequest cmsReq, EBaseException e)
            throws IOException {
        try {
            Locale[] locale = new Locale[1];
            CMSLoadTemplate loadTempl =
                    mTemplates.get(ICMSRequest.EXCEPTION);
            CMSTemplate template = getTemplate(loadTempl.mTemplateName,
                    cmsReq.getHttpReq(), locale);
            ICMSTemplateFiller filler = loadTempl.mFiller;
            CMSTemplateParams templateParams = null;

            // When an exception occurs the exit is non-local which probably
            // will leave the requestStatus value set to something other
            // than CMSRequest.EXCEPTION, so force the requestStatus to
            // EXCEPTION since it must be that if we're here.
            cmsReq.setStatus(ICMSRequest.EXCEPTION);

            if (filler != null) {
                templateParams = filler.getTemplateParams(
                            cmsReq, mAuthority, locale[0], e);
            }
            if (templateParams == null) {
                templateParams = new CMSTemplateParams(null, CMS.createArgBlock());
            }
            if (e != null) {
                templateParams.getFixed().set(
                        ICMSTemplateFiller.EXCEPTION, e.toString(locale[0]));
            }

            // just output arg blocks as XML
            CMS.debug("CMSServlet.java: renderTemplate");
            String xmlOutput = cmsReq.getHttpReq().getParameter("xml");
            if (xmlOutput != null && xmlOutput.equals("true")) {
                CMS.debug("CMSServlet.java: xml parameter detected, returning xml");
                outputXML(cmsReq.getHttpResp(), templateParams);
                return;
            }

            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            template.renderOutput(bos, templateParams);
            cmsReq.getHttpResp().setContentType("text/html");
            cmsReq.getHttpResp().setContentLength(bos.size());
            bos.writeTo(cmsReq.getHttpResp().getOutputStream());
        } catch (Exception ex) {
            renderFinalError(cmsReq, ex);
        }
    }

    public void renderFinalError(CMSRequest cmsReq, Exception ex)
            throws IOException {
        // this template is the last resort for all other unexpected
        // errors in other templates so we can only output text.
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        httpResp.setContentType("text/html");
        ServletOutputStream out = httpResp.getOutputStream();

        // replace $ERRORMSG with exception message if included.
        String finalErrMsg = mFinalErrorMsg;
        int tokenIdx = mFinalErrorMsg.indexOf(ERROR_MSG_TOKEN);

        if (tokenIdx != -1) {
            finalErrMsg =
                    mFinalErrorMsg.substring(0, tokenIdx) +
                            ex.toString() +
                            mFinalErrorMsg.substring(
                                    tokenIdx + ERROR_MSG_TOKEN.length());
        }
        out.println(finalErrMsg);
        return;
    }

    /**
     * Invalidates a SSL Session. So client auth will happen again.
     */
    protected static void invalidateSSLSession(HttpServletRequest httpReq) {

        /*
         try {
         s = (SSLSocket) ((HTTPRequest) httpReq).getConnection().getSocket();
         } catch (ClassCastException e) {
         CMS.getLogger().log(
         ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_WARN,
         CMS.getLogMessage("CMSGW_SSL_NO_INVALIDATE"));
         // ignore.
         return;
         }
         try {
         s.invalidateSession();
         s.resetHandshake();
         }catch (SocketException se) {
         }
         */
        return;
    }

    /**
     * construct a authentication credentials to pass into authentication
     * manager.
     */
    public static AuthCredentials getAuthCreds(
            IAuthManager authMgr, IArgBlock argBlock, X509Certificate clientCert)
            throws EBaseException {
        // get credentials from http parameters.
        String[] reqCreds = authMgr.getRequiredCreds();
        AuthCredentials creds = new AuthCredentials();

        for (int i = 0; i < reqCreds.length; i++) {
            String reqCred = reqCreds[i];

            if (reqCred.equals(IAuthManager.CRED_SSL_CLIENT_CERT)) {
                // cert could be null;
                creds.set(reqCred, new X509Certificate[] { clientCert }
                        );
            } else {
                String value = argBlock.getValueAsString(reqCred);

                creds.set(reqCred, value); // value could be null;
            }
        }
        // Inserted by bskim
        creds.setArgBlock(argBlock);
        // Insert end
        return creds;
    }

    /**
     * get ssl client authenticated certificate
     */
    protected X509Certificate getSSLClientCertificate(HttpServletRequest httpReq) throws EBaseException {

        X509Certificate cert = null;

        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_INFO,
                CMS.getLogMessage("CMSGW_GETTING_SSL_CLIENT_CERT"));

        // iws60 support Java Servlet Spec V2.2, attribute
        // javax.servlet.request.X509Certificate now contains array
        // of X509Certificates instead of one X509Certificate object
        X509Certificate[] allCerts = (X509Certificate[]) httpReq.getAttribute(CERT_ATTR);

        if (allCerts == null || allCerts.length == 0) {
            throw new EBaseException("You did not provide a valid certificate for this operation");
        }

        cert = allCerts[0];

        if (cert == null) {
            // just don't have a cert.
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_SSL_CL_CERT_FAIL"));
            return null;
        }

        // convert to sun's x509 cert interface.
        try {
            byte[] certEncoded = cert.getEncoded();

            cert = new X509CertImpl(certEncoded);
        } catch (CertificateEncodingException e) {
            mLogger.log(
                    ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_SSL_CL_CERT_FAIL_ENCODE", e.getMessage()));
            return null;
        } catch (CertificateException e) {
            mLogger.log(
                    ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_SSL_CL_CERT_FAIL_DECODE", e.getMessage()));
            return null;
        }
        return cert;
    }

    /**
     * get a template based on result status.
     */
    protected CMSTemplate getTemplate(
            String templateName, HttpServletRequest httpReq, Locale[] locale)
            throws EBaseException, IOException {
        // this converts to system dependent file seperator char.
        if (mServletConfig == null) {
            CMS.debug("CMSServlet:getTemplate() - mServletConfig is null!");
            return null;
        }
        if (mServletConfig.getServletContext() == null) {
        }
        if (templateName == null) {
        }
        String realpath =
                mServletConfig.getServletContext().getRealPath("/" + templateName);

        if (realpath == null) {
            mLogger.log(
                    ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_NO_FIND_TEMPLATE", templateName));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }

        File realpathFile = new File(realpath);
        File templateFile =
                getLangFile(httpReq, realpathFile, locale);
        String charSet = httpReq.getCharacterEncoding();

        if (charSet == null) {
            charSet = "UTF8";
        }
        CMSTemplate template =
                (CMSTemplate) mFileLoader.getCMSFile(templateFile, charSet);

        return template;
    }

    /**
     * log according to authority category.
     */
    protected void log(int event, int level, String msg) {
        mLogger.log(event, mLogCategory, level,
                "Servlet " + mId + ": " + msg);
    }

    protected void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, mLogCategory, level,
                "Servlet " + mId + ": " + msg);
    }

    /**
     * get http parameters not to save from configuration.
     */
    protected void getDontSaveHttpParams(ServletConfig sc) {
        String dontSaveParams = null;

        try {
            for (int i = 0; i < DONT_SAVE_HTTP_PARAMS.length; i++) {
                mDontSaveHttpParams.addElement(DONT_SAVE_HTTP_PARAMS[i]);
            }
            dontSaveParams = sc.getInitParameter(
                        PROP_DONT_SAVE_HTTP_PARAMS);
            if (dontSaveParams != null) {
                StringTokenizer params =
                        new StringTokenizer(dontSaveParams, ",");

                while (params.hasMoreTokens()) {
                    String param = params.nextToken();

                    mDontSaveHttpParams.addElement(param);
                }
            }
        } catch (Exception e) {
            // should never happen
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_NO_CONFIG_VALUE", PROP_DONT_SAVE_HTTP_PARAMS, e.toString()));
            // default just in case.
            for (int i = 0; i < DONT_SAVE_HTTP_PARAMS.length; i++) {
                mDontSaveHttpParams.addElement(DONT_SAVE_HTTP_PARAMS[i]);
            }
            return;
        }
    }

    /**
     * get http headers to save from configuration.
     */
    protected void getSaveHttpHeaders(ServletConfig sc) {
        try {
            // init save http headers. default will always be saved.
            for (int i = 0; i < SAVE_HTTP_HEADERS.length; i++) {
                mSaveHttpHeaders.addElement(SAVE_HTTP_HEADERS[i]);
            }

            // now get from config file if there's more.
            String saveHeaders =
                    sc.getInitParameter(PROP_SAVE_HTTP_HEADERS);

            if (saveHeaders != null) {
                StringTokenizer headers =
                        new StringTokenizer(saveHeaders, ",");

                while (headers.hasMoreTokens()) {
                    String hdr = headers.nextToken();

                    mSaveHttpHeaders.addElement(hdr);
                }
            }
        } catch (Exception e) {
            // should never happen
            log(ILogger.LL_WARN, CMS.getLogMessage("CMSGW_NO_CONFIG_VALUE", PROP_SAVE_HTTP_HEADERS, e.toString()));
            return;
        }
    }

    /**
     * save http headers in a IRequest.
     */
    protected void saveHttpHeaders(
            HttpServletRequest httpReq, IRequest req)
            throws EBaseException {
        Hashtable<String, String> headers = new Hashtable<String, String>();
        Enumeration<String> hdrs = mSaveHttpHeaders.elements();

        while (hdrs.hasMoreElements()) {
            String hdr = hdrs.nextElement();
            String val = httpReq.getHeader(hdr);

            if (val != null) {
                headers.put(hdr, val);
            }
        }
        req.setExtData(IRequest.HTTP_HEADERS, headers);
    }

    /**
     * save http headers in a IRequest.
     */
    protected void saveHttpParams(
            IArgBlock httpParams, IRequest req) {
        Hashtable<String, String> saveParams = new Hashtable<String, String>();

        Enumeration<String> names = httpParams.elements();

        while (names.hasMoreElements()) {
            String name = names.nextElement();
            Enumeration<String> params = mDontSaveHttpParams.elements();
            boolean dosave = true;

            while (params.hasMoreElements()) {
                String param = params.nextElement();

                if (name.equalsIgnoreCase(param)) {
                    dosave = false;
                    break;
                }
            }
            if (dosave) {
                // kmccarth
                // fear not - service() calls toHashtable() which only
                // retrieves string values.
                // TODO - when we can use JDK5 features we should typecast
                // the params until they get here
                saveParams.put(name, (String) httpParams.get(name));
            }
        }
        req.setExtData(IRequest.HTTP_PARAMS, saveParams);
    }

    /**
     * handy routine for getting a cert record given a serial number.
     */
    protected ICertRecord getCertRecord(BigInteger serialNo) {
        if (mAuthority == null ||
                !(mAuthority instanceof ICertificateAuthority)) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_NON_CERT_AUTH"));
            return null;
        }
        ICertificateRepository certdb =
                ((ICertificateAuthority) mAuthority).getCertificateRepository();

        if (certdb == null) {
            log(ILogger.LL_WARN, CMS.getLogMessage("CMSGW_CERT_DB_NULL", mAuthority.toString()));
            return null;
        }
        ICertRecord certRecord = null;

        try {
            certRecord = certdb.readCertificateRecord(serialNo);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_NO_CERT_REC", serialNo.toString(16), e.toString()));
            return null;
        }
        return certRecord;
    }

    /**
     * handy routine for validating if a cert is from this CA.
     * mAuthority must be a CA.
     */
    protected boolean isCertFromCA(X509Certificate cert) {
        BigInteger serialno = cert.getSerialNumber();
        X509CertImpl certInDB = (X509CertImpl) getX509Certificate(serialno);

        if (certInDB == null || !certInDB.equals(cert))
            return false;
        return true;
    }

    /**
     * handy routine for checking if a list of certs is from this CA.
     * mAuthortiy must be a CA.
     */
    protected boolean areCertsFromCA(X509Certificate[] certs) {
        for (int i = certs.length - 1; i >= 0; i--) {
            if (!isCertFromCA(certs[i]))
                return false;
        }
        return true;
    }

    /**
     * handy routine for getting a certificate from the certificate
     * repository. mAuthority must be a CA.
     */
    protected X509Certificate getX509Certificate(BigInteger serialNo) {
        if (mAuthority == null ||
                !(mAuthority instanceof ICertificateAuthority)) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_NOT_CERT_AUTH"));
            return null;
        }
        ICertificateRepository certdb =
                ((ICertificateAuthority) mAuthority).getCertificateRepository();

        if (certdb == null) {
            log(ILogger.LL_WARN, CMS.getLogMessage("CMSGW_CERT_DB_NULL", mAuthority.toString()));
            return null;
        }
        X509Certificate cert = null;

        try {
            cert = certdb.getX509Certificate(serialNo);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_NO_CERT_REC", serialNo.toString(16), e.toString()));
            return null;
        }
        return cert;
    }

    /**
     * instantiate a new filler from a class name,
     *
     * @return null if can't be instantiated, new instance otherwise.
     */
    protected ICMSTemplateFiller newFillerObject(String fillerClass) {
        ICMSTemplateFiller filler = null;

        try {
            filler = (ICMSTemplateFiller)
                    Class.forName(fillerClass).newInstance();
        } catch (Exception e) {
            if ((e instanceof RuntimeException)) {
                throw (RuntimeException) e;
            } else {
                log(ILogger.LL_WARN,
                        CMS.getLogMessage("CMSGW_CANT_LOAD_FILLER", fillerClass, e.toString()));
                return null;
            }
        }
        return filler;
    }

    /**
     * set default templates.
     * subclasses can override, and should override at least the success
     * template
     */
    protected void setDefaultTemplates(ServletConfig sc) {
        // Subclasses should override these for diff templates and params in
        // their constructors.
        // Set a template name to null to not use these standard ones.
        // When template name is set to null nothing will be displayed.
        // Servlet is assumed to have rendered its own output.
        // The only exception is the unexpected error template where the
        // default one will always be used if template name is null.
        String successTemplate = null;
        String errorTemplate = null;
        String unauthorizedTemplate = null;
        String pendingTemplate = null;
        String svcpendingTemplate = null;
        String rejectedTemplate = null;
        String unexpectedErrorTemplate = null;

        String gateway = sc.getInitParameter("interface");
        String authority = sc.getInitParameter(PROP_AUTHORITY);
        if (authority == null) {
            authority = sc.getInitParameter("authorityId");
        }

        try {
            successTemplate = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (successTemplate == null) {
                successTemplate = SUCCESS_TEMPLATE;
                if (gateway != null)
                    //successTemplate = "/"+gateway+successTemplate;
                    successTemplate = "/" + gateway + successTemplate;
            }

            errorTemplate = sc.getInitParameter(
                        PROP_ERROR_TEMPLATE);
            if (errorTemplate == null) {
                errorTemplate = ERROR_TEMPLATE;
                if (gateway != null)
                    //errorTemplate = "/"+gateway+errorTemplate;
                    errorTemplate = "/" + gateway + errorTemplate;
            }

            unauthorizedTemplate = sc.getInitParameter(
                        PROP_UNAUTHORIZED_TEMPLATE);
            if (unauthorizedTemplate == null) {
                unauthorizedTemplate = UNAUTHORIZED_TEMPLATE;
                if (gateway != null)
                    //unauthorizedTemplate = "/"+gateway+unauthorizedTemplate;
                    unauthorizedTemplate = "/" + gateway + unauthorizedTemplate;
            }

            pendingTemplate = sc.getInitParameter(
                        PROP_PENDING_TEMPLATE);
            if (pendingTemplate == null) {
                pendingTemplate = PENDING_TEMPLATE;
                if (gateway != null)
                    //pendingTemplate = "/"+gateway+pendingTemplate;
                    pendingTemplate = "/" + gateway + pendingTemplate;
            }

            svcpendingTemplate = sc.getInitParameter(
                        PROP_SVC_PENDING_TEMPLATE);
            if (svcpendingTemplate == null) {
                svcpendingTemplate = SVC_PENDING_TEMPLATE;
                if (gateway != null)
                    //svcpendingTemplate = "/"+gateway+svcpendingTemplate;
                    svcpendingTemplate = "/" + gateway + svcpendingTemplate;
            }

            rejectedTemplate = sc.getInitParameter(
                        PROP_REJECTED_TEMPLATE);
            if (rejectedTemplate == null) {
                rejectedTemplate = REJECTED_TEMPLATE;
                if (gateway != null)
                    //rejectedTemplate = "/"+gateway+rejectedTemplate;
                    rejectedTemplate = "/" + gateway + rejectedTemplate;
            }

            unexpectedErrorTemplate = sc.getInitParameter(
                        PROP_EXCEPTION_TEMPLATE);
            if (unexpectedErrorTemplate == null) {
                unexpectedErrorTemplate = EXCEPTION_TEMPLATE;
                if (gateway != null)
                    //unexpectedErrorTemplate = "/"+gateway+unexpectedErrorTemplate;
                    unexpectedErrorTemplate = "/" + gateway + unexpectedErrorTemplate;
            }
        } catch (Exception e) {
            // this should never happen.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IMP_INIT_SERV_ERR", e.toString(),
                            mId));
        }

        mTemplates.put(
                ICMSRequest.UNAUTHORIZED,
                new CMSLoadTemplate(
                        PROP_UNAUTHORIZED_TEMPLATE, PROP_UNAUTHOR_TEMPLATE_FILLER,
                        unauthorizedTemplate, null));
        mTemplates.put(
                ICMSRequest.SUCCESS,
                new CMSLoadTemplate(
                        PROP_SUCCESS_TEMPLATE, PROP_SUCCESS_TEMPLATE_FILLER,
                        successTemplate, new GenSuccessTemplateFiller()));
        mTemplates.put(
                ICMSRequest.PENDING,
                new CMSLoadTemplate(
                        PROP_PENDING_TEMPLATE, PROP_PENDING_TEMPLATE_FILLER,
                        pendingTemplate, new GenPendingTemplateFiller()));
        mTemplates.put(
                ICMSRequest.SVC_PENDING,
                new CMSLoadTemplate(
                        PROP_SVC_PENDING_TEMPLATE, PROP_SVC_PENDING_TEMPLATE_FILLER,
                        svcpendingTemplate, new GenSvcPendingTemplateFiller()));
        mTemplates.put(
                ICMSRequest.REJECTED,
                new CMSLoadTemplate(
                        PROP_REJECTED_TEMPLATE, PROP_REJECTED_TEMPLATE_FILLER,
                        rejectedTemplate, new GenRejectedTemplateFiller()));
        mTemplates.put(
                ICMSRequest.ERROR,
                new CMSLoadTemplate(
                        PROP_ERROR_TEMPLATE, PROP_ERROR_TEMPLATE_FILLER,
                        errorTemplate, new GenErrorTemplateFiller()));
        mTemplates.put(
                ICMSRequest.EXCEPTION,
                new CMSLoadTemplate(
                        PROP_EXCEPTION_TEMPLATE, PROP_EXCEPTION_TEMPLATE_FILLER,
                        unexpectedErrorTemplate, new GenUnexpectedErrorTemplateFiller()));
    }

    /**
     * handy routine to check if client is navigator based on user-agent.
     */
    public static boolean clientIsNav(HttpServletRequest httpReq) {
        String useragent = httpReq.getHeader("user-agent");

        if (useragent.startsWith("Mozilla") &&
                useragent.indexOf("MSIE") == -1)
            return true;
        return false;
    }

    /**
     * handy routine to check if client is msie based on user-agent.
     */
    public static boolean clientIsMSIE(HttpServletRequest httpReq) {
        String useragent = httpReq.getHeader("user-agent");

        if (useragent != null && useragent.indexOf("MSIE") != -1)
            return true;
        return false;
    }

    /**
     * handy routine to check if client is cartman based on hidden http input
     * set using cartman JS. (no other way to tell)
     */
    private static String CMMF_RESPONSE = "cmmfResponse";

    public static boolean doCMMFResponse(IArgBlock httpParams) {
        if (httpParams.getValueAsBoolean(CMMF_RESPONSE, false))
            return true;
        else
            return false;
    }

    private static final String IMPORT_CERT = "importCert";
    private static final String IMPORT_CHAIN = "importCAChain";
    private static final String IMPORT_CERT_MIME_TYPE = "importCertMimeType";
    // default mime type
    private static final String NS_X509_USER_CERT = "application/x-x509-user-cert";
    private static final String NS_X509_EMAIL_CERT = "application/x-x509-email-cert";

    // CMC mime types
    public static final String SIMPLE_ENROLLMENT_REQUEST = "application/pkcs10";
    public static final String SIMPLE_ENROLLMENT_RESPONSE = "application/pkcs7-mime";
    public static final String FULL_ENROLLMENT_REQUEST = "application/pkcs7-mime";
    public static final String FULL_ENROLLMENT_RESPONSE = "application/pkcs7-mime";

    /**
     * handy routine to check if client want full enrollment response
     */
    public static String FULL_RESPONSE = "fullResponse";

    public static boolean doFullResponse(IArgBlock httpParams) {
        if (httpParams.getValueAsBoolean(FULL_RESPONSE, false))
            return true;
        else
            return false;
    }

    /**
     * @return false if import cert directly set to false.
     * @return true if import cert directly is true and import cert.
     */
    protected boolean checkImportCertToNav(
            HttpServletResponse httpResp, IArgBlock httpParams, X509CertImpl cert)
            throws EBaseException {
        if (!httpParams.getValueAsBoolean(IMPORT_CERT, false)) {
            return false;
        }
        boolean importCAChain =
                httpParams.getValueAsBoolean(IMPORT_CHAIN, true);
        // XXX Temporary workaround because of problem with passing Mime type
        boolean emailCert =
                httpParams.getValueAsBoolean("emailCert", false);
        String importMimeType = (emailCert) ?
                httpParams.getValueAsString(IMPORT_CERT_MIME_TYPE, NS_X509_EMAIL_CERT) :
                httpParams.getValueAsString(IMPORT_CERT_MIME_TYPE, NS_X509_USER_CERT);

        //		String importMimeType =
        //			httpParams.getValueAsString(
        //				IMPORT_CERT_MIME_TYPE, NS_X509_USER_CERT);
        importCertToNav(httpResp, cert, importMimeType, importCAChain);
        return true;
    }

    /**
     * handy routine to import cert to old navigator in nav mime type.
     */
    public void importCertToNav(
            HttpServletResponse httpResp, X509CertImpl cert,
            String contentType, boolean importCAChain)
            throws EBaseException {
        ServletOutputStream out = null;
        byte[] encoding = null;

        CMS.debug("CMSServlet: importCertToNav " +
                       "contentType=" + contentType + " " +
                       "importCAChain=" + importCAChain);
        try {
            out = httpResp.getOutputStream();
            // CA chain.
            if (importCAChain) {
                CertificateChain caChain = null;
                X509Certificate[] caCerts = null;
                PKCS7 p7 = null;

                caChain = ((ICertAuthority) mAuthority).getCACertChain();
                caCerts = caChain.getChain();

                // set user + CA cert chain in pkcs7
                X509CertImpl[] userChain =
                        new X509CertImpl[caCerts.length + 1];

                userChain[0] = cert;
                int m = 1, n = 0;

                for (; n < caCerts.length; m++, n++) {
                    userChain[m] = (X509CertImpl) caCerts[n];

                    /*
                     System.out.println(
                     m+"th Cert "+userChain[m].toString());
                     */
                }
                p7 = new PKCS7(new AlgorithmId[0],
                            new ContentInfo(new byte[0]),
                            userChain,
                            new SignerInfo[0]);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();

                p7.encodeSignedData(bos, false);
                encoding = bos.toByteArray();
                CMS.debug("CMServlet: return P7 " + CMS.BtoA(encoding));
            } else {
                encoding = cert.getEncoded();
                CMS.debug("CMServlet: return Certificate " + CMS.BtoA(encoding));
            }
            httpResp.setContentType(contentType);
            out.write(encoding);
        } catch (IOException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_RET_CERT_IMPORT_ERR", e.toString()));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_RETURNING_CERT"));
        } catch (CertificateEncodingException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_NO_ENCODED_IMP_CERT", e.toString()));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_ENCODING_ISSUED_CERT"));
        }
    }

    protected static void saveAuthToken(IAuthToken token, IRequest req) {
        if (token != null && req != null)
            req.setExtData(IRequest.AUTH_TOKEN, token);

        // # 56230 - expose auth token parameters to the policy predicate
        if (token != null && req != null) {
            Enumeration<String> e = token.getElements();
            while (e.hasMoreElements()) {
                String n = e.nextElement();
                String[] x1 = token.getInStringArray(n);
                if (x1 != null) {
                    for (int i = 0; i < x1.length; i++) {
                        CMS.debug("Setting " + IRequest.AUTH_TOKEN + "-" + n +
                                "(" + i + ")=" + x1[i]);
                        req.setExtData(IRequest.AUTH_TOKEN + "-" + n + "(" + i + ")",
                                x1[i]);
                    }
                } else {
                    String x = token.getInString(n);
                    if (x != null) {
                        CMS.debug("Setting " + IRequest.AUTH_TOKEN + "-" + n + "=" + x);
                        req.setExtData(IRequest.AUTH_TOKEN + "-" + n, x);
                    }
                }
            } // while
        } // if
    }

    protected IAuthToken getAuthToken(IRequest req) {
        return req.getExtDataInAuthToken(IRequest.AUTH_TOKEN);
    }

    protected static boolean connectionIsSSL(HttpServletRequest httpReq) {
        return httpReq.isSecure();
    }

    /**
     * handy routine for getting agent's relative path
     */
    protected String getRelPath(IAuthority authority) {
        if (authority instanceof ICertificateAuthority)
            return "ca/";
        else if (authority instanceof IRegistrationAuthority)
            return "ra/";
        else if (authority instanceof IKeyRecoveryAuthority)
            return "kra/";
        else
            return "/";
    }

    /**
     * A system certificate such as the CA signing certificate
     * should not be allowed to delete.
     * The main purpose is to avoid revoking the self signed
     * CA certificate accidentially.
     */
    protected boolean isSystemCertificate(BigInteger serialNo) {
        if (!(mAuthority instanceof ICertificateAuthority)) {
            return false;
        }
        X509Certificate caCert =
                ((ICertificateAuthority) mAuthority).getCACert();
        if (caCert != null) {
            /* only check this if we are self-signed */
            if (caCert.getSubjectDN().equals(caCert.getIssuerDN())) {
                if (caCert.getSerialNumber().equals(serialNo)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * make a CRL entry from a serial number and revocation reason.
     *
     * @return a RevokedCertImpl that can be entered in a CRL.
     */
    protected RevokedCertImpl formCRLEntry(
            BigInteger serialNo, RevocationReason reason)
            throws EBaseException {
        CRLReasonExtension reasonExt = new CRLReasonExtension(reason);
        CRLExtensions crlentryexts = new CRLExtensions();

        try {
            crlentryexts.set(CRLReasonExtension.NAME, reasonExt);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_CRL_REASON", reason.toString(), e.toString()));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_SETTING_CRLREASON"));
        }
        RevokedCertImpl crlentry =
                new RevokedCertImpl(serialNo, CMS.getCurrentDate(), crlentryexts);

        return crlentry;
    }

    /**
     * check if a certificate (serial number) is revoked on a CA.
     *
     * @return true if cert is marked revoked in the CA's database.
     * @return false if cert is not marked revoked.
     */
    protected boolean certIsRevoked(BigInteger serialNum)
            throws EBaseException {
        ICertRecord certRecord = getCertRecord(serialNum);

        if (certRecord == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_BAD_CERT_SER_NUM", String.valueOf(serialNum)));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_INVALID_CERT"));
        }
        if (certRecord.getStatus().equals(ICertRecord.STATUS_REVOKED))
            return true;
        return false;
    }

    public static String generateSalt() {
        Random rnd = new Random();
        String salt = new Integer(rnd.nextInt()).toString();
        return salt;
    }

    protected String hashPassword(String pwd) {
        String salt = generateSalt();
        byte[] pwdDigest = mSHADigest.digest((salt + pwd).getBytes());
        String b64E = Utils.base64encode(pwdDigest);

        return "{SHA}" + salt + ";" + b64E;
    }

    /**
     * @param req http servlet request
     * @param realpathFile the file to get.
     * @param locale array of at least one to be filled with locale found.
     */
    public static File getLangFile(
            HttpServletRequest req, File realpathFile, Locale[] locale)
            throws IOException {
        File file = null;
        String acceptLang = req.getHeader("accept-language");

        if (acceptLang != null && !acceptLang.equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(acceptLang, ",");
            int numLangs = tokenizer.countTokens();

            if (numLangs > 0) {
                // languages are searched in order.
                String parent = realpathFile.getParent();

                if (parent == null) {
                    parent = "." + File.separatorChar;
                }
                String name = realpathFile.getName();

                if (name == null) { // filename should never be null.
                    throw new IOException("file has no name");
                }
                int i;

                for (i = 0; i < numLangs; i++) {
                    String lang = null;
                    String token = tokenizer.nextToken();

                    int semicolon = token.indexOf(';');

                    if (semicolon == -1) {
                        lang = token.trim();
                    } else {
                        if (semicolon < 2)
                            continue; // protocol error.
                        lang = token.substring(0, semicolon).trim();
                    }
                    // if browser locale is the same as default locale,
                    // use the default form. (is this the right thing to do ?)
                    Locale l = getLocale(lang);

                    if (Locale.getDefault().equals(l)) {
                        locale[0] = l;
                        file = realpathFile;
                        break;
                    }

                    String langfilepath =
                            parent + File.separatorChar +
                                    lang + File.separatorChar + name;

                    file = new File(langfilepath);
                    if (file.exists()) {
                        locale[0] = getLocale(lang);
                        break;
                    }
                }
                // if no file for lang was found use default
                if (i == numLangs) {
                    file = realpathFile;
                    locale[0] = Locale.getDefault();
                }
            }
        } else {
            // use default if accept-language is not availabe
            file = realpathFile;
            locale[0] = Locale.getDefault();
        }
        return file;
    }

    public static Locale getLocale(String lang) {
        int dash = lang.indexOf('-');

        if (dash == -1)
            return new Locale(lang, "");
        else
            return new Locale(lang.substring(0, dash), lang.substring(dash + 1));
    }

    public IAuthToken authenticate(CMSRequest req)
            throws EBaseException {
        return authenticate(req, mAuthMgr);
    }

    public IAuthToken authenticate(HttpServletRequest httpReq)
            throws EBaseException {
        return authenticate(httpReq, mAuthMgr);
    }

    public IAuthToken authenticate(CMSRequest req, String authMgrName)
            throws EBaseException {
        IAuthToken authToken = authenticate(req.getHttpReq(),
                authMgrName);

        saveAuthToken(authToken, req.getIRequest());
        return authToken;
    }

    /**
     * Authentication
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTH_FAIL used when authentication fails (in case of SSL-client auth, only
     * webserver env can pick up the SSL violation; CS authMgr can pick up cert mis-match, so this event is used)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTH_SUCCESS used when authentication succeeded
     * </ul>
     *
     * @exception EBaseException an error has occurred
     */
    public IAuthToken authenticate(HttpServletRequest httpReq, String authMgrName)
            throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = ILogger.UNIDENTIFIED;
        String auditAuthMgrID = ILogger.UNIDENTIFIED;
        String auditUID = ILogger.UNIDENTIFIED;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String getClientCert = mGetClientCert;

            IArgBlock httpArgs = CMS.createArgBlock(toHashtable(httpReq));
            SessionContext ctx = SessionContext.getContext();
            String ip = httpReq.getRemoteAddr();
            CMS.debug("IP: " + ip);

            if (ip != null) {
                ctx.put(SessionContext.IPADDRESS, ip);
            }
            if (authMgrName != null) {
                CMS.debug("AuthMgrName: " + authMgrName);
                ctx.put(SessionContext.AUTH_MANAGER_ID, authMgrName);
            }
            // put locale into session context
            ctx.put(SessionContext.LOCALE, getLocale(httpReq));

            //
            // check ssl client authentication if specified.
            //
            X509Certificate clientCert = null;

            if (getClientCert != null && getClientCert.equals("true")) {
                CMS.debug("CMSServlet: retrieving SSL certificate");
                clientCert = getSSLClientCertificate(httpReq);
            }

            //
            // check authentication by auth manager if any.
            //
            if (authMgrName == null) {

                // Fixed Blackflag Bug #613900:  Since this code block does
                // NOT actually constitute an authentication failure, but
                // rather the case in which a given servlet has been correctly
                // configured to NOT require an authentication manager, the
                // audit message called LOGGING_SIGNED_AUDIT_AUTH_FAIL has
                // been removed.

                CMS.debug("CMSServlet: no authMgrName");
                return null;
            } else {
                // save the "Subject DN" of this certificate in case it
                // must be audited as an authentication failure
                if (clientCert == null) {
                    CMS.debug("CMSServlet: no client certificate found");
                } else {
                    String certUID = clientCert.getSubjectDN().getName();
                    CMS.debug("CMSServlet: certUID=" + certUID);

                    if (certUID != null) {
                        certUID = certUID.trim();

                        if (!(certUID.equals(""))) {
                            // reset the "auditUID"
                            auditUID = certUID;
                        }
                    }
                }

                // reset the "auditAuthMgrID"
                auditAuthMgrID = authMgrName;
            }
            AuthToken authToken = CMSGateway.checkAuthManager(httpReq,
                    httpArgs,
                    clientCert,
                    authMgrName);
            if (authToken == null) {
                return null;
            }
            String userid = authToken.getInString(IAuthToken.USER_ID);

            CMS.debug("CMSServlet: userid=" + userid);

            if (userid != null) {
                ctx.put(SessionContext.USER_ID, userid);
            }

            // reset the "auditSubjectID"
            auditSubjectID = auditSubjectID();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_SUCCESS,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditAuthMgrID);

            audit(auditMessage);

            return authToken;
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditAuthMgrID,
                        auditUID);
            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    public AuthzToken authorize(String authzMgrName, String resource, IAuthToken authToken,
            String exp) throws EBaseException {
        AuthzToken authzToken = null;
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditGroupID = auditGroupID();
        String auditACLResource = resource;
        String auditOperation = "enroll";

        try {
            authzToken = mAuthz.authorize(authzMgrName, authToken, exp);
            if (authzToken != null) {
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditACLResource,
                            auditOperation);

                audit(auditMessage);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditGroupID);

                audit(auditMessage);
            } else {
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditACLResource,
                            auditOperation);

                audit(auditMessage);

                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditGroupID);

                audit(auditMessage);
            }
            return authzToken;
        } catch (Exception e) {
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditACLResource,
                        auditOperation);

            audit(auditMessage);

            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditGroupID);

            audit(auditMessage);
            throw new EBaseException(e.toString());
        }
    }

    /**
     * Authorize must occur after Authenticate
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTHZ_FAIL used when authorization has failed
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS used when authorization is successful
     * <li>signed.audit LOGGING_SIGNED_AUDIT_ROLE_ASSUME used when user assumes a role (in current CS that's when one
     * accesses a role port)
     * </ul>
     *
     * @param authzMgrName string representing the name of the authorization
     *            manager
     * @param authToken the authentication token
     * @param resource a string representing the ACL resource id as defined in
     *            the ACL resource list
     * @param operation a string representing one of the operations as defined
     *            within the ACL statement (e. g. - "read" for an ACL statement containing
     *            "(read,write)")
     * @exception EBaseException an error has occurred
     * @return the authorization token
     */
    public AuthzToken authorize(String authzMgrName, IAuthToken authToken,
            String resource, String operation)
            throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditGroupID = auditGroupID();
        String auditID = auditSubjectID;
        String auditACLResource = resource;
        String auditOperation = operation;

        SessionContext auditContext = SessionContext.getExistingContext();
        String authManagerId = null;

        if (auditContext != null) {
            authManagerId = (String) auditContext.get(SessionContext.AUTH_MANAGER_ID);

            if (authManagerId != null && authManagerId.equals("TokenAuth")) {
                if (auditSubjectID.equals(ILogger.NONROLEUSER) ||
                        auditSubjectID.equals(ILogger.UNIDENTIFIED)) {
                    CMS.debug("CMSServlet: in authorize... TokenAuth auditSubjectID unavailable, changing to auditGroupID");
                    auditID = auditGroupID;
                }
            }
        }

        // "normalize" the "auditACLResource" value
        if (auditACLResource != null) {
            auditACLResource = auditACLResource.trim();
        }

        // "normalize" the "auditOperation" value
        if (auditOperation != null) {
            auditOperation = auditOperation.trim();
        }

        if (authzMgrName == null) {
            // Fixed Blackflag Bug #613900:  Since this code block does
            // NOT actually constitute an authorization failure, but
            // rather the case in which a given servlet has been correctly
            // configured to NOT require an authorization manager, the
            // audit message called LOGGING_SIGNED_AUDIT_AUTHZ_FAIL and
            // the audit message called LOGGING_SIGNED_AUDIT_ROLE_ASSUME
            // (marked as a failure) have been removed.

            return null;
        }

        try {
            AuthzToken authzTok = mAuthz.authorize(authzMgrName,
                    authToken,
                    resource,
                    operation);

            if (authzTok != null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditACLResource,
                            auditOperation);

                audit(auditMessage);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                            auditID,
                            ILogger.SUCCESS,
                            auditGroups(auditSubjectID));

                audit(auditMessage);
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditACLResource,
                            auditOperation);

                audit(auditMessage);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                            auditID,
                            ILogger.FAILURE,
                            auditGroups(auditSubjectID));

                audit(auditMessage);
            }

            return authzTok;
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditACLResource,
                        auditOperation);

            audit(auditMessage);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                        auditID,
                        ILogger.FAILURE,
                        auditGroups(auditSubjectID));

            audit(auditMessage);

            return null;
        } catch (Exception eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditACLResource,
                        auditOperation);

            audit(auditMessage);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditGroups(auditSubjectID));

            audit(auditMessage);

            return null;
        }
    }

    /**
     * Signed Audit Log
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditSubjectID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        CMS.debug("CMSServlet: in auditSubjectID");
        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        CMS.debug("CMSServlet: auditSubjectID auditContext " + auditContext);
        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            CMS.debug("CMSServlet auditSubjectID: subjectID: " + subjectID);
            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    /**
     * Signed Audit Log Group ID
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to obtain the "gid" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditGroupID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        CMS.debug("CMSServlet: in auditGroupID");
        String groupID = null;

        // Initialize groupID
        SessionContext auditContext = SessionContext.getExistingContext();

        CMS.debug("CMSServlet: auditGroupID auditContext " + auditContext);
        if (auditContext != null) {
            groupID = (String)
                    auditContext.get(SessionContext.GROUP_ID);

            CMS.debug("CMSServlet auditGroupID: groupID: " + groupID);
            if (groupID != null) {
                groupID = groupID.trim();
            } else {
                groupID = ILogger.NONROLEUSER;
            }
        } else {
            groupID = ILogger.UNIDENTIFIED;
        }

        return groupID;
    }

    /**
     * Signed Audit Groups
     *
     * This method is called to extract all "groups" associated
     * with the "auditSubjectID()".
     * <P>
     *
     * @param SubjectID string containing the signed audit log message SubjectID
     * @return a delimited string of groups associated
     *         with the "auditSubjectID()"
     */
    private String auditGroups(String SubjectID) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        if ((SubjectID == null) ||
                (SubjectID.equals(ILogger.UNIDENTIFIED))) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        Enumeration<IGroup> groups = null;

        try {
            groups = mUG.findGroups("*");
        } catch (Exception e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        StringBuffer membersString = new StringBuffer();

        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            if (group.isMember(SubjectID) == true) {
                if (membersString.length() != 0) {
                    membersString.append(", ");
                }

                membersString.append(group.getGroupID());
            }
        }

        if (membersString.length() != 0) {
            return membersString.toString();
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
    }

    /**
     * Retrieves locale based on the request.
     */
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader(HDR_LANG);

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                        UserInfo.getUserCountry(lang));
        }
        return locale;
    }

    protected void outputResult(HttpServletResponse httpResp,
            String contentType, byte[] content) {
        try {
            OutputStream os = httpResp.getOutputStream();

            httpResp.setContentType(contentType);
            httpResp.setContentLength(content.length);
            os.write(content);
            os.flush();
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()));
            return;
        }
    }

    protected void outputError(HttpServletResponse httpResp, String errorString) {
        outputError(httpResp, FAILURE, errorString, null);
    }

    protected void outputError(HttpServletResponse httpResp, String errorString, String requestId) {
        outputError(httpResp, FAILURE, errorString, null);
    }

    protected void outputError(HttpServletResponse httpResp, String status, String errorString, String requestId) {
        XMLObject xmlObj = null;
        try {
            xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", status);
            xmlObj.addItemToContainer(root, "Error", errorString);
            if (requestId != null) {
                xmlObj.addItemToContainer(root, "RequestId", requestId);
            }
            byte[] cb = xmlObj.toByteArray();

            OutputStream os = httpResp.getOutputStream();
            httpResp.setContentType("application/xml");
            httpResp.setContentLength(cb.length);
            os.write(cb);
            os.flush();
            return;
        } catch (Exception ee) {
            CMS.debug("Failed to send XML output to the server.");
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", ee.toString()));
        }
    }
}
