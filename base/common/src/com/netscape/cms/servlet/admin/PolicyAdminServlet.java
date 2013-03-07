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
package com.netscape.cms.servlet.admin;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.policy.IPolicyRule;
import com.netscape.certsrv.ra.IRegistrationAuthority;

/**
 * This class is an administration servlet for policy management.
 *
 * Each service (CA, KRA, RA) should be responsible
 * for registering an instance of this with the remote
 * administration subsystem.
 *
 * @deprecated
 * @version $Revision$, $Date$
 */
public class PolicyAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = 8850646362111106656L;

    public final static String PROP_AUTHORITY = "authority";

    private final static String INFO = "PolicyAdminServlet";
    private final static String PW_PASSWORD_CACHE_ADD =
            "PASSWORD_CACHE_ADD";

    public final static String PROP_PREDICATE = "predicate";
    private IPolicyProcessor mProcessor = null;
    private IAuthority mAuthority = null;

    // These will be moved to PolicyResources
    public static String INVALID_POLICY_SCOPE = "Invalid policy administration scope";
    public static String INVALID_POLICY_IMPL_OP = "Invalid operation for policy implementation management";
    public static String NYI = "Not Yet Implemented";
    public static String INVALID_POLICY_IMPL_CONFIG = "Invalid policy implementation configuration";
    public static String INVALID_POLICY_INSTANCE_CONFIG = "Invalid policy instance configuration";
    public static String MISSING_POLICY_IMPL_ID = "Missing policy impl id in request";
    public static String MISSING_POLICY_IMPL_CLASS = "Missing policy impl class in request";
    public static String INVALID_POLICY_IMPL_ID = "Invalid policy impl id in request";
    public static String MISSING_POLICY_INST_ID = "Missing policy impl id in request";
    public static String INVALID_POLICY_INST_ID = "Invalid policy impl id in request";
    public static String COMMA = ",";
    public static String MISSING_POLICY_ORDERING = "Missing policy ordering";

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY =
            "LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY_3";

    /**
     * Constructs administration servlet.
     */
    public PolicyAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String authority = config.getInitParameter(PROP_AUTHORITY);
        String policyStatus = null;

        CMS.debug("PolicyAdminServlet: In Policy Admin Servlet init!");

        // CMS 6.1 began utilizing the "Certificate Profiles" framework
        // instead of the legacy "Certificate Policies" framework.
        //
        // Beginning with CS 8.1, to meet the Common Criteria evaluation
        // performed on this version of the product, it was determined
        // that this legacy "Certificate Policies" framework would be
        // deprecated and disabled by default (see Bugzilla Bug #472597).
        //
        // NOTE:  The "Certificate Policies" framework ONLY applied to
        //        to CA, KRA, and legacy RA (pre-CMS 7.0) subsystems.
        //
        //        Further, the "PolicyAdminServlet.java" servlet is ONLY used
        //        by the CA Console for the following:
        //
        //            SERVLET-NAME           URL-PATTERN
        //            ====================================================
        //            capolicy               ca/capolicy
        //
        //        Finally, the "PolicyAdminServlet.java" servlet is ONLY used
        //        by the KRA Console for the following:
        //
        //            SERVLET-NAME           URL-PATTERN
        //            ====================================================
        //            krapolicy              kra/krapolicy
        //
        if (authority != null)
            mAuthority = (IAuthority) CMS.getSubsystem(authority);
        if (mAuthority != null)
            if (mAuthority instanceof ICertificateAuthority) {
                mProcessor = ((ICertificateAuthority) mAuthority).getPolicyProcessor();
                try {
                    policyStatus = ICertificateAuthority.ID
                                 + "." + "Policy"
                                 + "." + IPolicyProcessor.PROP_ENABLE;
                    if (mConfig.getBoolean(policyStatus, true) == true) {
                        // NOTE:  If "ca.Policy.enable=<boolean>" is missing,
                        //        then the referenced instance existed prior
                        //        to this name=value pair existing in its
                        //        'CS.cfg' file, and thus we err on the
                        //        side that the user may still need to
                        //        use the policy framework.
                        CMS.debug("PolicyAdminServlet::init "
                                 + "Certificate Policy Framework (deprecated) "
                                 + "is ENABLED");
                    } else {
                        // CS 8.1 Default:  ca.Policy.enable=false
                        CMS.debug("PolicyAdminServlet::init "
                                 + "Certificate Policy Framework (deprecated) "
                                 + "is DISABLED");
                        return;
                    }
                } catch (EBaseException e) {
                    throw new ServletException(authority
                                              + " does not have a "
                                              + "master policy switch called '"
                                              + policyStatus + "'");
                }
            } else if (mAuthority instanceof IRegistrationAuthority) {
                // this refers to the legacy RA (pre-CMS 7.0)
                mProcessor = ((IRegistrationAuthority) mAuthority).getPolicyProcessor();
            } else if (mAuthority instanceof IKeyRecoveryAuthority) {
                mProcessor = ((IKeyRecoveryAuthority) mAuthority).getPolicyProcessor();
                try {
                    policyStatus = IKeyRecoveryAuthority.ID
                                + "." + "Policy"
                                + "." + IPolicyProcessor.PROP_ENABLE;
                    if (mConfig.getBoolean(policyStatus, true) == true) {
                        // NOTE:  If "kra.Policy.enable=<boolean>" is missing,
                        //        then the referenced instance existed prior
                        //        to this name=value pair existing in its
                        //        'CS.cfg' file, and thus we err on the
                        //        side that the user may still need to
                        //        use the policy framework.
                        CMS.debug("PolicyAdminServlet::init "
                                 + "Certificate Policy Framework (deprecated) "
                                 + "is ENABLED");
                    } else {
                        // CS 8.1 Default:  kra.Policy.enable=false
                        CMS.debug("PolicyAdminServlet::init "
                                 + "Certificate Policy Framework (deprecated) "
                                 + "is DISABLED");
                        return;
                    }
                } catch (EBaseException e) {
                    throw new ServletException(authority
                                              + " does not have a "
                                              + "master policy switch called '"
                                              + policyStatus + "'");
                }
            } else
                throw new ServletException(authority + "  does not have policy processor!");
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * retrieve extended plugin info such as brief description, type info
     * from policy, authentication,
     * need to add: listener, mapper and publishing plugins
     */
    private void getExtendedPluginInfo(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        if (!readAuthorize(req, resp))
            return;
        String id = req.getParameter(Constants.RS_ID);
        NameValuePairs params = null;

        int colon = id.indexOf(':');

        String implType = id.substring(0, colon);
        String implName1 = id.substring(colon + 1);
        String implName = implName1;
        String instName = null;

        colon = implName1.indexOf(':');
        if (colon > -1) {
            implName = implName1.substring(0, colon);
            instName = implName1.substring(colon + 1);
            params = getExtendedPluginInfo(getLocale(req), implType, implName, instName);
        } else {
            params = getExtendedPluginInfo(getLocale(req), implType, implName);
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    private NameValuePairs getExtendedPluginInfo(Locale locale, String implType, String implName) {
        IExtendedPluginInfo ext_info = null;
        Object impl = null;
        IPolicyRule policy = mProcessor.getPolicyImpl(implName);

        impl = policy;

        if (impl != null) {
            if (impl instanceof IExtendedPluginInfo) {
                ext_info = (IExtendedPluginInfo) impl;
            }
        }

        NameValuePairs nvps = null;

        if (ext_info == null) {
            nvps = new NameValuePairs();
        } else {
            nvps = convertStringArrayToNVPairs(ext_info.getExtendedPluginInfo(locale));
        }

        return nvps;
    }

    public NameValuePairs getExtendedPluginInfo(Locale locale, String pluginType,
            String implName,
            String instName) {
        IExtendedPluginInfo ext_info = null;

        Object impl = null;

        IPolicyRule policy = mProcessor.getPolicyInstance(instName);

        impl = policy;
        if (impl == null) {
            impl = mProcessor.getPolicyImpl(implName);
        }
        if (impl != null) {
            if (impl instanceof IExtendedPluginInfo) {
                ext_info = (IExtendedPluginInfo) impl;
            }
        }

        NameValuePairs nvps = null;

        if (ext_info == null) {
            nvps = new NameValuePairs();
        } else {
            nvps = convertStringArrayToNVPairs(ext_info.getExtendedPluginInfo(locale));

        }

        if (nvps != null) {
            addDefaultParams(impl, nvps);
        }

        return nvps;
    }

    private void addDefaultParams(Object ext_info, NameValuePairs nvps) {

        /* make sure policy rules have 'enable' and 'predicate' */

        if (ext_info instanceof IPolicyRule) {
            if (nvps.get(IPolicyRule.PROP_ENABLE) == null) {
                nvps.put(IPolicyRule.PROP_ENABLE, "boolean;Enable this policy rule");
            }
            if (nvps.get(PROP_PREDICATE) == null) {
                nvps.put(PROP_PREDICATE, "string;Rules describing when this policy should run.");
            }
        }
    }

    /**
     * Serves HTTP admin request.
     */
    public void service(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        super.authenticate(req);

        AUTHZ_RES_NAME = "certServer.policy.configuration";
        String scope = req.getParameter(Constants.OP_SCOPE);

        if (scope.equals(ScopeDef.SC_POLICY_RULES))
            processPolicyRuleMgmt(req, resp);
        else if (scope.equals(ScopeDef.SC_POLICY_IMPLS))
            processPolicyImplMgmt(req, resp);
        else if (scope.equals(ScopeDef.SC_EXTENDED_PLUGIN_INFO)) {
            try {
                getExtendedPluginInfo(req, resp);
            } catch (EBaseException e) {
                sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
                return;
            }
        } else
            sendResponse(ERROR, INVALID_POLICY_SCOPE, null, resp);
    }

    private boolean readAuthorize(HttpServletRequest req,
            HttpServletResponse resp) throws IOException {
        mOp = "read";
        if ((mToken = super.authorize(req)) == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                    null, resp);
            return false;
        }
        return true;
    }

    private boolean modifyAuthorize(HttpServletRequest req,
            HttpServletResponse resp) throws IOException {
        mOp = "modify";
        if ((mToken = super.authorize(req)) == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                    null, resp);
            return false;
        }
        return true;
    }

    /**
     * Process Policy Implementation Management.
     */
    public void processPolicyImplMgmt(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_SEARCH)) {
            if (!readAuthorize(req, resp))
                return;
            listPolicyImpls(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deletePolicyImpl(req, resp);
        } else if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getPolicyImplConfig(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addPolicyImpl(req, resp);
        } else
            sendResponse(ERROR, INVALID_POLICY_IMPL_OP,
                    null, resp);
    }

    public void processPolicyRuleMgmt(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_SEARCH)) {
            if (!readAuthorize(req, resp))
                return;
            listPolicyInstances(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deletePolicyInstance(req, resp);
        } else if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getPolicyInstanceConfig(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addPolicyInstance(req, resp);
        } else if (op.equals(OpDef.OP_MODIFY)) {
            if (!modifyAuthorize(req, resp))
                return;
            String id = req.getParameter(Constants.RS_ID);

            if (id.equalsIgnoreCase(Constants.RS_ID_ORDER))
                changePolicyInstanceOrdering(req, resp);
            else
                modifyPolicyInstance(req, resp);
        } else
            sendResponse(ERROR, INVALID_POLICY_IMPL_OP,
                    null, resp);
    }

    public void listPolicyImpls(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        Enumeration<String> policyImplNames = mProcessor.getPolicyImplsInfo();
        Enumeration<IPolicyRule> policyImpls = mProcessor.getPolicyImpls();

        if (policyImplNames == null ||
                policyImpls == null) {
            sendResponse(ERROR, INVALID_POLICY_IMPL_CONFIG, null, resp);
            return;
        }

        // Assemble a name value pair;
        NameValuePairs nvp = new NameValuePairs();

        while (policyImplNames.hasMoreElements() &&
                policyImpls.hasMoreElements()) {
            String id = policyImplNames.nextElement();
            IPolicyRule impl = policyImpls.nextElement();
            String className =
                    impl.getClass().getName();
            String desc = impl.getDescription();

            nvp.put(id, className + "," + desc);
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void listPolicyInstances(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        Enumeration<String> instancesInfo = mProcessor.getPolicyInstancesInfo();

        if (instancesInfo == null) {
            sendResponse(ERROR, INVALID_POLICY_INSTANCE_CONFIG, null, resp);
            return;
        }

        // Assemble name value pairs
        NameValuePairs nvp = new NameValuePairs();

        while (instancesInfo.hasMoreElements()) {
            String info = instancesInfo.nextElement();
            int i = info.indexOf(";");

            nvp.put(info.substring(0, i), info.substring(i + 1));

        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    /**
     * Delete policy implementation
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY used when configuring cert policy constraints and
     * extensions
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void deletePolicyImpl(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id.
            String id = req.getParameter(Constants.RS_ID).trim();

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
                return;
            }

            try {
                mProcessor.deletePolicyImpl(id);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, null, resp);
            } catch (Exception e) {
                //e.printStackTrace();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, e.toString(), null, resp);
            }
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }
    }

    public void getPolicyImplConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get the policy impl id.
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }

        Vector<String> v = mProcessor.getPolicyImplConfig(id);

        if (v == null) {
            sendResponse(ERROR, INVALID_POLICY_IMPL_ID, null, resp);
            return;
        }
        NameValuePairs nvp = new NameValuePairs();

        for (Enumeration<String> e = v.elements(); e.hasMoreElements();) {
            String nv = e.nextElement();
            int index = nv.indexOf("=");

            nvp.put(nv.substring(0, index), nv.substring(index + 1));
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    /**
     * Add policy implementation
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY used when configuring cert policy constraints and
     * extensions
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addPolicyImpl(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id and class path.
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
                return;
            }

            String classPath = req.getParameter(Constants.PR_POLICY_CLASS);

            if (classPath == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_IMPL_CLASS, null, resp);
                return;
            }
            try {
                mProcessor.addPolicyImpl(id, classPath);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, null, resp);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, e.toString(), null, resp);
            }
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }
    }

    /**
     * Delete policy instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY used when configuring cert policy constraints and
     * extensions
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void deletePolicyInstance(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id.
            String id = req.getParameter(Constants.RS_ID).trim();

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_INST_ID, null, resp);
                return;
            }

            try {
                mProcessor.deletePolicyInstance(id);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, null, resp);
            } catch (Exception e) {
                //e.printStackTrace();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, e.toString(), null, resp);
            }
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }
    }

    public void getPolicyInstanceConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get the policy rule id.
        String id = req.getParameter(Constants.RS_ID).trim();

        if (id == null) {
            sendResponse(ERROR, MISSING_POLICY_INST_ID, null, resp);
            return;
        }

        Vector<String> v = mProcessor.getPolicyInstanceConfig(id);

        if (v == null) {
            sendResponse(ERROR, INVALID_POLICY_INST_ID, null, resp);
            return;
        }
        NameValuePairs nvp = new NameValuePairs();

        for (Enumeration<String> e = v.elements(); e.hasMoreElements();) {
            String nv = e.nextElement();
            int index = nv.indexOf("=");
            String name = nv.substring(0, index);
            String value = nv.substring(index + 1);

            if (value == null) {
                value = "";
            }

            nvp.put(name, value);

        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void
            putUserPWPair(String combo) {
        int semicolon;

        semicolon = combo.indexOf(";");
        String user = combo.substring(0, semicolon);
        String pw = combo.substring(semicolon + 1);

        CMS.putPasswordCache(user, pw);
    }

    /**
     * Add policy instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY used when configuring cert policy constraints and
     * extensions
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addPolicyInstance(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id and class path.
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_INST_ID, null, resp);
                return;
            }

            // Get the default config params for the implementation.
            String implName = req.getParameter(IPolicyRule.PROP_IMPLNAME);

            if (implName == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
                return;
            }

            // We need to fetch parameters: enable, predicate and implname
            // always, and any additional parameters as required by the
            // implementation.
            Hashtable<String, String> ht = new Hashtable<String, String>();
            String val = req.getParameter(IPolicyRule.PROP_ENABLE).trim();

            if (val == null)
                val = "true";
            ht.put(IPolicyRule.PROP_ENABLE, val);

            val = req.getParameter(IPolicyRule.PROP_PREDICATE);
            if (val != null)
                ht.put(IPolicyRule.PROP_PREDICATE, val);
            ht.put(IPolicyRule.PROP_IMPLNAME, implName);

            Vector<String> v = mProcessor.getPolicyImplConfig(implName);

            if (v == null) {
                // Invalid impl id

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, INVALID_POLICY_IMPL_ID, null, resp);
                return;
            }
            for (Enumeration<String> e = v.elements(); e.hasMoreElements();) {
                String nv = e.nextElement();
                int index = nv.indexOf("=");
                String key = nv.substring(0, index);

                val = req.getParameter(key).trim();
                if (val != null)
                    ht.put(key, val);
            }

            String pwadd = req.getParameter(PW_PASSWORD_CACHE_ADD);

            if (pwadd != null) {
                putUserPWPair(pwadd);
            }

            try {
                mProcessor.addPolicyInstance(id, ht);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, null, resp);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, e.toString(), null, resp);
            }
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }
    }

    /**
     * Change ordering of policy instances
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY used when configuring cert policy constraints and
     * extensions
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void changePolicyInstanceOrdering(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String policyOrder =
                    req.getParameter(Constants.PR_POLICY_ORDER);

            if (policyOrder == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_ORDERING, null, resp);
                return;
            }
            try {
                mProcessor.changePolicyInstanceOrdering(policyOrder);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, null, resp);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, e.toString(), null, resp);
            }
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }
    }

    /**
     * Modify policy instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY used when configuring cert policy constraints and
     * extensions
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void modifyPolicyInstance(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id and class path.
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_INST_ID, null, resp);
                return;
            }

            // Get the default config params for the implementation.
            String implName = req.getParameter(IPolicyRule.PROP_IMPLNAME).trim();

            if (implName == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
                return;
            }

            // We need to fetch parameters: enable, predicate and implname
            // always, and any additional parameters as required by the
            // implementation.
            Hashtable<String, String> ht = new Hashtable<String, String>();
            String val = req.getParameter(IPolicyRule.PROP_ENABLE).trim();

            if (val == null)
                val = "true";
            ht.put(IPolicyRule.PROP_ENABLE, val);

            val = req.getParameter(IPolicyRule.PROP_PREDICATE);
            if (val != null)
                ht.put(IPolicyRule.PROP_PREDICATE, val);
            ht.put(IPolicyRule.PROP_IMPLNAME, implName);
            Vector<String> v = mProcessor.getPolicyImplConfig(implName);

            if (v == null) {
                // Invalid impl id

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, INVALID_POLICY_IMPL_ID, null, resp);
                return;
            }
            // XXX
            for (Enumeration<String> n = req.getParameterNames(); n.hasMoreElements();) {
                String p = n.nextElement();
                String l = req.getParameter(p);

                if (l != null)
                    ht.put(p, l);
            }

            /*
             for(Enumeration e = v.elements(); e.hasMoreElements(); )
             {
             String nv = (String)e.nextElement();
             int index = nv.indexOf("=");
             String key = nv.substring(0, index);
             val = req.getParameter(key);
             if (val != null)
             ht.put(key, val);
             }
             */

            try {
                mProcessor.modifyPolicyInstance(id, ht);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, null, resp);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, e.toString(), null, resp);
            }
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }
    }
}
