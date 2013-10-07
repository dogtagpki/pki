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

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileEx;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;

/**
 * This class is an administration servlet for policy management.
 *
 * Each service (CA, KRA, RA) should be responsible
 * for registering an instance of this with the remote
 * administration subsystem.
 *
 * @version $Revision$, $Date$
 */
public class ProfileAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = 4828203666899891742L;

    public final static String PROP_AUTHORITY = "authority";

    private final static String INFO = "ProfileAdminServlet";

    public final static String PROP_PREDICATE = "predicate";
    private IPluginRegistry mRegistry = null;
    private IProfileSubsystem mProfileSub = null;

    // These will be moved to PolicyResources
    public static String INVALID_POLICY_SCOPE = "Invalid policy administration scope";
    public static String INVALID_POLICY_IMPL_OP = "Invalid operation for policy implementation management";
    public static String NYI = "Not Yet Implemented";
    public static String INVALID_POLICY_IMPL_CONFIG = "Invalid policy implementation configuration";
    public static String INVALID_POLICY_INSTANCE_CONFIG = "Invalid policy instance configuration";
    public static String MISSING_POLICY_IMPL_ID = "Missing policy impl id in request";
    public static String MISSING_POLICY_IMPL_CLASS = "Missing policy impl class in request";
    public static String INVALID_POLICY_IMPL_ID = "Invalid policy impl id in request";
    public static String MISSING_POLICY_INST_ID = "Missing policy id in request";
    public static String POLICY_INST_ID_ALREADY_USED = "policy id already used";
    public static String INVALID_POLICY_INST_ID = "Invalid policy id in request";
    public static String COMMA = ",";
    public static String MISSING_POLICY_ORDERING = "Missing policy ordering";
    public static String BAD_CONFIGURATION_VAL = "Invalid configuration value.";

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE_3";

    /**
     * Constructs administration servlet.
     */
    public ProfileAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        mRegistry = (IPluginRegistry) CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        mProfileSub = (IProfileSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_PROFILE);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP admin request.
     */
    public void service(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        super.authenticate(req);

        AUTHZ_RES_NAME = "certServer.profile.configuration";
        String scope = req.getParameter(Constants.OP_SCOPE);

        CMS.debug("ProfileAdminServlet: service scope: " + scope);
        if (scope.equals(ScopeDef.SC_PROFILE_RULES)) {
            processProfileRuleMgmt(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_POLICIES)) {
            processProfilePolicy(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_DEFAULT_POLICY)) {
            processPolicyDefaultConfig(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_CONSTRAINT_POLICY)) {
            processPolicyConstraintConfig(req, resp);
        } else if (scope.equals(ScopeDef.SC_POLICY_IMPLS)) {
            processPolicyImplMgmt(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_INPUT)) {
            processProfileInput(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_OUTPUT)) {
            processProfileOutput(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_INPUT_CONFIG)) {
            processProfileInputConfig(req, resp);
        } else if (scope.equals(ScopeDef.SC_PROFILE_OUTPUT_CONFIG)) {
            processProfileOutputConfig(req, resp);
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

    public void processProfilePolicy(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getProfilePolicy(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addProfilePolicy(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deleteProfilePolicy(req, resp);
        }
    }

    public void processProfileInput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getProfileInput(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addProfileInput(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deleteProfileInput(req, resp);
        }
    }

    public void processProfileOutput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getProfileOutput(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addProfileOutput(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deleteProfileOutput(req, resp);
        }
    }

    public void processProfileInputConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getInputConfig(req, resp);
        } else if (op.equals(OpDef.OP_MODIFY)) {
            if (!modifyAuthorize(req, resp))
                return;
            modifyInputConfig(req, resp);
        }
    }

    public void processProfileOutputConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getOutputConfig(req, resp);
        } else if (op.equals(OpDef.OP_MODIFY)) {
            if (!modifyAuthorize(req, resp))
                return;
            modifyOutputConfig(req, resp);
        }
    }

    public void processPolicyDefaultConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getPolicyDefaultConfig(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addPolicyDefaultConfig(req, resp);
        } else if (op.equals(OpDef.OP_MODIFY)) {
            if (!modifyAuthorize(req, resp))
                return;
            modifyPolicyDefaultConfig(req, resp);
        }
    }

    public void processPolicyConstraintConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        CMS.debug("ProfileAdminServlet: processPolicyConstraintConfig op " + op);
        if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getPolicyConstraintConfig(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addPolicyConstraintConfig(req, resp);
        } else if (op.equals(OpDef.OP_MODIFY)) {
            if (!modifyAuthorize(req, resp))
                return;
            modifyPolicyConstraintConfig(req, resp);
        }
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
            listProfileImpls(req, resp);
        } else
            sendResponse(ERROR, INVALID_POLICY_IMPL_OP,
                    null, resp);
    }

    public void processProfileRuleMgmt(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_SEARCH)) {
            if (!readAuthorize(req, resp))
                return;
            listProfileInstances(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deleteProfileInstance(req, resp);
        } else if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getProfileInstanceConfig(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addProfileInstance(req, resp);
        } else if (op.equals(OpDef.OP_MODIFY)) {
            if (!modifyAuthorize(req, resp))
                return;
            modifyProfileInstance(req, resp);
        } else
            sendResponse(ERROR, INVALID_POLICY_IMPL_OP,
                    null, resp);
    }

    /**
     * Lists all registered profile impementations
     */
    public void listProfileImpls(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        Enumeration<String> impls = mRegistry.getIds("profile");
        NameValuePairs nvp = new NameValuePairs();

        while (impls.hasMoreElements()) {
            String id = impls.nextElement();
            IPluginInfo info = mRegistry.getPluginInfo("profile", id);

            nvp.put(id, info.getClassName() + "," +
                    info.getDescription(getLocale(req)));
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    /**
     * Add policy profile
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addProfilePolicy(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        CMS.debug("ProfileAdminServlet: in addProfilePolicy");
        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String policyId = st.nextToken();
            String defImpl = st.nextToken();
            String conImpl = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            if (mProfileSub.isProfileEnable(profileId)) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req),
                                "CMS_PROFILE_CREATE_POLICY_FAILED",
                                "Profile is currently enabled"),
                        null, resp);
                return;
            }

            StringTokenizer ss = new StringTokenizer(policyId, ":");
            String setId = ss.nextToken();
            String pId = ss.nextToken();

            try {
                if (!isValidId(setId)) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req),
                                    "CMS_PROFILE_CREATE_POLICY_FAILED",
                                    "Invalid set id " + setId),
                            null, resp);
                    return;
                }
                if (!isValidId(pId)) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req),
                                    "CMS_PROFILE_CREATE_POLICY_FAILED",
                                    "Invalid policy id " + pId),
                            null, resp);
                    return;
                }
                profile.createProfilePolicy(setId, pId,
                            defImpl, conImpl);
            } catch (EBaseException e1) {
                // error
                CMS.debug("ProfileAdminServlet: addProfilePolicy " +
                        e1.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_PROFILE_CREATE_POLICY_FAILED",
                                e1.toString()),
                        null, resp);
                return;
            }
            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Add profile input
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addProfileInput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String inputId = st.nextToken();
            String inputImpl = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            Enumeration<String> names = req.getParameterNames();
            NameValuePairs nvps = new NameValuePairs();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;
                nvps.put(name, req.getParameter(name));
            }

            try {
                profile.createProfileInput(inputId, inputImpl, nvps);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_PROFILE_CREATE_INPUT_FAILED",
                                e1.toString()),
                        null, resp);

                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Add profile output
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addProfileOutput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String outputId = st.nextToken();
            String outputImpl = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            Enumeration<String> names = req.getParameterNames();
            NameValuePairs nvps = new NameValuePairs();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;
                nvps.put(name, req.getParameter(name));
            }

            try {
                profile.createProfileOutput(outputId, outputImpl,
                            nvps);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_PROFILE_CREATE_OUTPUT_FAILED",
                                e1.toString()),
                        null, resp);

                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Delete policy profile
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void deleteProfilePolicy(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String profileId = "";
            String policyId = "";
            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    profileId = req.getParameter(name);
                if (name.equals("POLICYID"))
                    policyId = req.getParameter(name);
            }
            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            StringTokenizer ss = new StringTokenizer(policyId, ":");
            String setId = ss.nextToken();
            String pId = ss.nextToken();

            try {
                profile.deleteProfilePolicy(setId, pId);
            } catch (EBaseException e1) {
                CMS.debug("ProfileAdminServlet: " + e1.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Delete profile input
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void deleteProfileInput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String profileId = "";
            String inputId = "";
            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    profileId = req.getParameter(name);
                if (name.equals("INPUTID"))
                    inputId = req.getParameter(name);
            }
            CMS.debug("ProfileAdminServlet: deleteProfileInput profileId -> " + profileId);
            CMS.debug("ProfileAdminServlet: deleteProfileInput inputId -> " + inputId);
            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            CMS.debug("deleteProfileInput profile -> " + profile);
            try {
                profile.deleteProfileInput(inputId);
            } catch (EBaseException e1) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Delete profile output
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void deleteProfileOutput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String profileId = "";
            String outputId = "";
            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    profileId = req.getParameter(name);
                if (name.equals("OUTPUTID"))
                    outputId = req.getParameter(name);
            }
            CMS.debug("ProfileAdminServlet: deleteProfileOutput profileId -> " + profileId);
            CMS.debug("ProfileAdminServlet: deleteProfileOutput outputId -> " + outputId);
            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            CMS.debug("ProfileAdminServlet: deleteProfileOutput profile -> " + profile);
            try {
                profile.deleteProfileOutput(outputId);
            } catch (EBaseException e1) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Add default policy profile configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addPolicyDefaultConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String policyId = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            StringTokenizer ss = new StringTokenizer(policyId, ":");
            String setId = ss.nextToken();
            String pId = ss.nextToken();

            IProfilePolicy policy = profile.getProfilePolicy(setId, pId);
            IPolicyDefault def = policy.getDefault();

            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;
                try {
                    def.setConfig(name, req.getParameter(name));

                } catch (EPropertyException e) {

                    CMS.debug("ProfileAdminServlet: modifyPolicyDefConfig setConfig exception.");
                    try {
                        profile.deleteProfilePolicy(setId, pId);
                    } catch (Exception e11) {
                    }
                    sendResponse(ERROR, BAD_CONFIGURATION_VAL, null, resp);
                    return;
                }
                // defConfig.putString("params." + name, req.getParameter(name));
            }
            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }
            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Add policy constraints profile configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addPolicyConstraintConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String policyId = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            StringTokenizer ss = new StringTokenizer(policyId, ":");
            String setId = ss.nextToken();
            String pId = ss.nextToken();

            IProfilePolicy policy = profile.getProfilePolicy(setId, pId);
            IPolicyConstraint con = policy.getConstraint();

            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;

                try {
                    con.setConfig(name, req.getParameter(name));

                } catch (EPropertyException e) {

                    CMS.debug("ProfileAdminServlet: addPolicyConstraintsConfig setConfig exception.");
                    try {
                        profile.deleteProfilePolicy(setId, pId);
                    } catch (Exception e11) {
                    }
                    sendResponse(ERROR, BAD_CONFIGURATION_VAL, null, resp);
                    return;
                }
                // conConfig.putString("params." + name, req.getParameter(name));
            }
            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Modify default policy profile configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void modifyPolicyDefaultConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String policyId = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            StringTokenizer ss = new StringTokenizer(policyId, ":");
            String setId = ss.nextToken();
            String pId = ss.nextToken();
            IProfilePolicy policy = profile.getProfilePolicy(setId, pId);
            IPolicyDefault def = policy.getDefault();

            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;
                try {
                    def.setConfig(name, req.getParameter(name));

                } catch (EPropertyException e) {

                    CMS.debug("ProfileAdminServlet: modifyPolicyDefConfig setConfig exception.");
                    sendResponse(ERROR, BAD_CONFIGURATION_VAL, null, resp);
                    return;
                }
                //  defConfig.putString("params." + name, req.getParameter(name));
            }
            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }
            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Modify profile input configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void modifyInputConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String inputId = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            IProfileInput input = profile.getProfileInput(inputId);
            IConfigStore inputConfig = input.getConfigStore();

            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;
                inputConfig.putString("params." + name, req.getParameter(name));
            }
            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }
            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Modify profile output configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void modifyOutputConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String outputId = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            IProfileOutput output = profile.getProfileOutput(outputId);
            IConfigStore outputConfig = output.getConfigStore();

            Enumeration<String> names = req.getParameterNames();

            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;
                outputConfig.putString("params." + name,
                        req.getParameter(name));
            }
            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }
            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Modify policy constraints profile configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void modifyPolicyConstraintConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            StringTokenizer st = new StringTokenizer(id, ";");
            String profileId = st.nextToken();
            String policyId = st.nextToken();

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(profileId);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            StringTokenizer ss = new StringTokenizer(policyId, ":");
            String setId = ss.nextToken();
            String pId = ss.nextToken();
            IProfilePolicy policy = profile.getProfilePolicy(setId, pId);
            IPolicyConstraint con = policy.getConstraint();

            Enumeration<String> names = req.getParameterNames();

            CMS.debug("ProfileAdminServlet: modifyPolicyConstraintConfig policy " + policy + " con " + con);
            while (names.hasMoreElements()) {
                String name = names.nextElement();

                if (name.equals("OP_SCOPE"))
                    continue;
                if (name.equals("OP_TYPE"))
                    continue;
                if (name.equals("RS_ID"))
                    continue;

                //   CMS.debug("ProfileAdminServlet: modifyPolicyConstraintConfig name" + name  + " val " + req.getParameter(name));
                try {
                    con.setConfig(name, req.getParameter(name));

                } catch (EPropertyException e) {

                    CMS.debug("ProfileAdminServlet: modifyPolicyConstraintsConfig setConfig exception.");
                    sendResponse(ERROR, BAD_CONFIGURATION_VAL, null, resp);
                    return;
                }
                //conConfig.putString("params." + name, req.getParameter(name));
            }
            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            NameValuePairs nvp = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, nvp, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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

    public void getPolicyDefaultConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String id = req.getParameter(Constants.RS_ID);

        StringTokenizer st = new StringTokenizer(id, ";");
        String profileId = st.nextToken();
        String policyId = st.nextToken();

        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(profileId);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getPolicyDefaultConfig() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        IProfilePolicy policy = null;
        IPolicyDefault rule = null;

        StringTokenizer ss = new StringTokenizer(policyId, ":");
        String setId = ss.nextToken();
        String pId = ss.nextToken();

        policy = profile.getProfilePolicy(setId, pId);
        rule = policy.getDefault();

        NameValuePairs nvp = new NameValuePairs();
        Enumeration<String> names = rule.getConfigNames();

        while (names.hasMoreElements()) {
            String name = names.nextElement();
            IDescriptor desc = rule.getConfigDescriptor(getLocale(req), name);

            if (desc == null) {
                nvp.put(name, ";" + ";" + rule.getConfig(name));
            } else {
                nvp.put(name,
                        desc.getSyntax()
                                + ";" + ";" + getNonNull(desc.getConstraint()) + ";"
                                + desc.getDescription(getLocale(req)) + ";" + rule.getConfig(name));
            }
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getPolicyConstraintConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String id = req.getParameter(Constants.RS_ID);
        String constraintsList = req.getParameter(Constants.PR_CONSTRAINTS_LIST);

        // this one gets called when one of the elements in the default list get
        // selected, then it returns the list of supported constraintsPolicy
        if (constraintsList != null) {

        }

        StringTokenizer st = new StringTokenizer(id, ";");
        String profileId = st.nextToken();
        String policyId = st.nextToken();

        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(profileId);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getPolicyConstraintConfig() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        StringTokenizer ss = new StringTokenizer(policyId, ":");
        String setId = ss.nextToken();
        String pId = ss.nextToken();
        IProfilePolicy policy = profile.getProfilePolicy(setId, pId);
        IPolicyConstraint rule = policy.getConstraint();

        NameValuePairs nvp = new NameValuePairs();
        Enumeration<String> names = rule.getConfigNames();

        while (names.hasMoreElements()) {
            String name = names.nextElement();
            IDescriptor desc = rule.getConfigDescriptor(getLocale(req), name);

            if (desc == null) {
                nvp.put(name, ";" + rule.getConfig(name));
            } else {
                nvp.put(name,
                        desc.getSyntax()
                                + ";" + getNonNull(desc.getConstraint()) + ";" + desc.getDescription(getLocale(req))
                                + ";" + rule.getConfig(name));
            }
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getProfilePolicy(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String id = req.getParameter(Constants.RS_ID);

        // only allow profile retrival if it is disabled

        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(id);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getProfilePolicy() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        NameValuePairs nvp = new NameValuePairs();
        Enumeration<String> setIds = profile.getProfilePolicySetIds();

        if (!setIds.hasMoreElements()) {
            // no set id; this is a brand new profile
            sendResponse(SUCCESS, null, nvp, resp);
            return;
        }
        while (setIds.hasMoreElements()) {
            String setId = setIds.nextElement();
            Enumeration<IProfilePolicy> policies = profile.getProfilePolicies(setId);

            while (policies.hasMoreElements()) {
                IProfilePolicy policy = policies.nextElement();
                IPolicyDefault def = policy.getDefault();
                IPolicyConstraint con = policy.getConstraint();

                nvp.put(setId + ":" + policy.getId(),
                        def.getName(getLocale(req)) + ";" +
                                con.getName(getLocale(req)));
            }
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getProfileOutput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String id = req.getParameter(Constants.RS_ID);
        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(id);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getProfileOutput() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        NameValuePairs nvp = new NameValuePairs();
        Enumeration<String> outputs = profile.getProfileOutputIds();

        while (outputs.hasMoreElements()) {
            String outputId = outputs.nextElement();
            IProfileOutput output = profile.getProfileOutput(outputId);

            nvp.put(outputId, output.getName(getLocale(req)));
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getProfileInput(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String id = req.getParameter(Constants.RS_ID);
        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(id);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getProfileInput() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        NameValuePairs nvp = new NameValuePairs();
        Enumeration<String> inputs = profile.getProfileInputIds();

        while (inputs.hasMoreElements()) {
            String inputId = inputs.nextElement();
            IProfileInput input = profile.getProfileInput(inputId);

            nvp.put(inputId, input.getName(getLocale(req)));
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getInputConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        String id = req.getParameter(Constants.RS_ID);
        StringTokenizer st = new StringTokenizer(id, ";");
        String profileId = st.nextToken();
        String inputId = st.nextToken();
        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(profileId);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getInputConfig() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        IProfileInput profileInput = null;
        NameValuePairs nvp = new NameValuePairs();

        profileInput = profile.getProfileInput(inputId);
        Enumeration<String> names = profileInput.getConfigNames();

        while (names.hasMoreElements()) {
            String name = names.nextElement();
            IDescriptor desc = profileInput.getConfigDescriptor(
                    getLocale(req), name);
            if (desc == null) {
                nvp.put(name, ";" + ";" + profileInput.getConfig(name));
            } else {
                nvp.put(name, desc.getSyntax() + ";" +
                        getNonNull(desc.getConstraint()) + ";" +
                        desc.getDescription(getLocale(req)) + ";" +
                        profileInput.getConfig(name));
            }
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getOutputConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        String id = req.getParameter(Constants.RS_ID);
        StringTokenizer st = new StringTokenizer(id, ";");
        String profileId = st.nextToken();
        String outputId = st.nextToken();
        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(profileId);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getOutputConfig() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        IProfileOutput profileOutput = null;
        NameValuePairs nvp = new NameValuePairs();

        profileOutput = profile.getProfileOutput(outputId);
        Enumeration<String> names = profileOutput.getConfigNames();

        while (names.hasMoreElements()) {
            String name = names.nextElement();
            IDescriptor desc = profileOutput.getConfigDescriptor(
                    getLocale(req), name);
            if (desc == null) {
                nvp.put(name, ";" + ";" + profileOutput.getConfig(name));
            } else {
                nvp.put(name, desc.getSyntax() + ";" +
                        getNonNull(desc.getConstraint()) + ";" +
                        desc.getDescription(getLocale(req)) + ";" +
                        profileOutput.getConfig(name));
            }
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void listProfileInstances(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        NameValuePairs nvp = new NameValuePairs();
        Enumeration<String> e = mProfileSub.getProfileIds();

        while (e.hasMoreElements()) {
            String profileId = e.nextElement();

            String status = null;

            if (mProfileSub.isProfileEnable(profileId)) {
                status = "enabled";
            } else {
                status = "disabled";
            }

            // mInstanceId + ";visible;" + enabled
            nvp.put(profileId, profileId + ";visible;" + status);
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getProfileInstanceConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        String id = req.getParameter(Constants.RS_ID);
        IProfile profile = null;

        try {
            profile = mProfileSub.getProfile(id);
        } catch (EBaseException e1) {
            CMS.debug("ProfileAdminServlet::getProfileInstanceConfig() - " +
                       "profile is null!");
            throw new ServletException(e1.toString());
        }

        NameValuePairs nvp = new NameValuePairs();

        nvp.put("name", profile.getName(getLocale(req)));
        nvp.put("desc", profile.getDescription(getLocale(req)));
        nvp.put("visible", Boolean.toString(profile.isVisible()));
        nvp.put("enable", Boolean.toString(
                mProfileSub.isProfileEnable(id)));

        String authid = profile.getAuthenticatorId();

        if (authid == null) {
            nvp.put("auth", "");
        } else {
            nvp.put("auth", authid);
        }
        CMS.debug("ProfileAdminServlet: authid=" + authid);
        nvp.put("plugin", mProfileSub.getProfileClassId(id));

        sendResponse(SUCCESS, null, nvp, resp);
    }

    /**
     * Delete profile instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void deleteProfileInstance(HttpServletRequest req,
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
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_INST_ID, null, resp);
                return;
            }

            String config = null;

            try {
                config = CMS.getConfigStore().getString("profile." + id + ".config");
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            try {
                mProfileSub.deleteProfile(id, config);
            } catch (EProfileException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), e.toString(), id), null, resp);
                return;
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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

    public void
            putUserPWPair(String combo) {
        int semicolon;

        semicolon = combo.indexOf(";");
        String user = combo.substring(0, semicolon);
        String pw = combo.substring(semicolon + 1);

        CMS.putPasswordCache(user, pw);
    }

    public boolean isValidId(String id) {
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (!Character.isLetterOrDigit(c))
                return false;
        }
        return true;
    }

    /**
     * Add profile instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void addProfileInstance(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id and class path.
            String id = req.getParameter(Constants.RS_ID);

            if (id == null || id.trim().equals("") || !isValidId(id)) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, MISSING_POLICY_INST_ID, null, resp);
                return;
            }

            // see if profile id already used
            IProfile p = null;

            try {
                p = mProfileSub.getProfile(id);
            } catch (EProfileException e1) {
            }
            if (p != null) {
                sendResponse(ERROR, POLICY_INST_ID_ALREADY_USED, null, resp);
                return;
            }

            String impl = req.getParameter("impl");
            String name = req.getParameter("name");
            String visible = req.getParameter("visible");
            String auth = req.getParameter("auth");
            String config = null;

            ISubsystem subsystem = CMS.getSubsystem("ca");
            String subname = "ca";

            if (subsystem == null)
                subname = "ra";

            String subpath = "/profiles/";

            try {
                String version = CMS.getConfigStore().getString("cms.version");
                if (version.indexOf('.') > -1) {
                    version = version.substring(0, version.indexOf('.'));
                }
                int v = Integer.parseInt(version);
                if (v >= 10) {
                    subpath = "/ca/profiles/";
                }
                config = CMS.getConfigStore().getString("instanceRoot") + subpath + subname + "/" + id + ".cfg";
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            IPluginInfo info = mRegistry.getPluginInfo("profile", impl);

            IProfile profile = null;

            // create configuration file
            File configFile = new File(config);

            configFile.createNewFile();

            // create profile
            try {
                profile = mProfileSub.createProfile(id, impl,
                            info.getClassName(),
                            config);
                profile.setName(getLocale(req), name);
                profile.setDescription(getLocale(req), name);
                if (visible != null && visible.equals("true")) {
                    profile.setVisible(true);
                } else {
                    profile.setVisible(false);
                }
                profile.setAuthenticatorId(auth);
                profile.getConfigStore().commit(false);

                mProfileSub.createProfileConfig(id, impl, config);
                if (profile instanceof IProfileEx) {
                    // populates profile specific plugins such as
                    // policies, inputs and outputs
                    ((IProfileEx) profile).populate();
                }
            } catch (Exception e) {
                CMS.debug("ProfileAdminServlet: " + e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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
     * Modify profile instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE used when configuring cert profile (general settings
     * and cert profile; obsoletes extensions and constraints policies)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     */
    public void modifyProfileInstance(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // Get the policy impl id and class path.
            String id = req.getParameter(Constants.RS_ID);

            IProfile profile = null;

            try {
                profile = mProfileSub.getProfile(id);
            } catch (EBaseException e1) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, null, null, resp);
                return;
            }
            String name = req.getParameter("name");
            String desc = req.getParameter("desc");
            String auth = req.getParameter("auth");
            String visible = req.getParameter("visible");

            // String config = req.getParameter("config");

            profile.setAuthenticatorId(auth);
            profile.setName(getLocale(req), name);
            profile.setDescription(getLocale(req), desc);
            if (visible != null && visible.equals("true")) {
                profile.setVisible(true);
            } else {
                profile.setVisible(false);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            try {
                profile.getConfigStore().commit(false);
            } catch (Exception e) {
            }

            sendResponse(SUCCESS, null, null, resp);
        } catch (IOException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
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

    protected String getNonNull(String s) {
        if (s == null)
            return "";
        return s;
    }

}
