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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;

/**
 * This implements the administration servlet for registry subsystem.
 *
 * @version $Revision$, $Date$
 */
public class RegistryAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = 2104924641665675578L;

    public final static String PROP_AUTHORITY = "authority";

    private final static String INFO = "RegistryAdminServlet";

    public final static String PROP_PREDICATE = "predicate";
    private IPluginRegistry mRegistry = null;

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

    /**
     * Constructs administration servlet.
     */
    public RegistryAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mRegistry = (IPluginRegistry) CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
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

        AUTHZ_RES_NAME = "certServer.registry.configuration";
        String scope = req.getParameter(Constants.OP_SCOPE);
        String op = req.getParameter(Constants.OP_TYPE);

        if (scope.equals(ScopeDef.SC_SUPPORTED_CONSTRAINTPOLICIES)) {
            if (op.equals(OpDef.OP_READ))
                if (!readAuthorize(req, resp))
                    return;
            getSupportedConstraintPolicies(req, resp);
        } else {
            processImplMgmt(req, resp);
        }
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
    public void processImplMgmt(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {
        // Get operation type
        String op = req.getParameter(Constants.OP_TYPE);

        if (op.equals(OpDef.OP_SEARCH)) {
            if (!readAuthorize(req, resp))
                return;
            listImpls(req, resp);
        } else if (op.equals(OpDef.OP_READ)) {
            if (!readAuthorize(req, resp))
                return;
            getProfileImplConfig(req, resp);
        } else if (op.equals(OpDef.OP_DELETE)) {
            if (!modifyAuthorize(req, resp))
                return;
            deleteImpl(req, resp);
        } else if (op.equals(OpDef.OP_ADD)) {
            if (!modifyAuthorize(req, resp))
                return;
            addImpl(req, resp);
        } else
            sendResponse(ERROR, INVALID_POLICY_IMPL_OP,
                    null, resp);
    }

    public void addImpl(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        // Get the policy impl id.
        String id = req.getParameter(Constants.RS_ID);
        String scope = req.getParameter(Constants.OP_SCOPE);
        String classPath = req.getParameter(Constants.PR_POLICY_CLASS);
        String desc = req.getParameter(Constants.PR_POLICY_DESC);

        if (id == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }

        NameValuePairs nvp = new NameValuePairs();

        IPluginInfo info = mRegistry.createPluginInfo(id, desc, classPath);
        try {
            mRegistry.addPluginInfo(scope, id, info);
        } catch (Exception e) {
            CMS.debug(e.toString());
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void deleteImpl(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        // Get the policy impl id.
        String id = req.getParameter(Constants.RS_ID);
        String scope = req.getParameter(Constants.OP_SCOPE);

        if (id == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }

        IPluginInfo info = mRegistry.getPluginInfo(scope, id);

        if (info == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }

        NameValuePairs nvp = new NameValuePairs();

        try {
            mRegistry.removePluginInfo(scope, id);
        } catch (Exception e) {
            CMS.debug(e.toString());
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    /**
     * Lists all registered profile impementations
     */
    public void listImpls(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        String scope = req.getParameter(Constants.OP_SCOPE);
        Enumeration<String> impls = mRegistry.getIds(scope);
        NameValuePairs nvp = new NameValuePairs();

        while (impls.hasMoreElements()) {
            String id = impls.nextElement();
            IPluginInfo info = mRegistry.getPluginInfo(scope, id);

            nvp.put(id, info.getClassName() + "," +
                    info.getDescription(getLocale(req)) + "," + info.getName(getLocale(req)));
        }

        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getSupportedConstraintPolicies(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }
        NameValuePairs nvp = new NameValuePairs();

        try {
            IPluginInfo info = mRegistry.getPluginInfo("defaultPolicy", id);
            String className = info.getClassName();
            IPolicyDefault policyDefaultClass = (IPolicyDefault)
                    Class.forName(className).newInstance();

            if (policyDefaultClass != null) {
                Enumeration<String> impls = mRegistry.getIds("constraintPolicy");

                while (impls.hasMoreElements()) {
                    String constraintID = impls.nextElement();
                    IPluginInfo constraintInfo = mRegistry.getPluginInfo(
                            "constraintPolicy", constraintID);
                    IPolicyConstraint policyConstraintClass = (IPolicyConstraint)
                            Class.forName(constraintInfo.getClassName()).newInstance();

                    CMS.debug("RegistryAdminServlet: getSUpportedConstraint " + constraintInfo.getClassName());

                    if (policyConstraintClass.isApplicable(policyDefaultClass)) {
                        CMS.debug("RegistryAdminServlet: getSUpportedConstraint isApplicable "
                                + constraintInfo.getClassName());
                        nvp.put(constraintID,
                                constraintInfo.getClassName()
                                        + "," +
                                        constraintInfo.getDescription(getLocale(req)) + ","
                                        + constraintInfo.getName(getLocale(req)));
                    }
                }
            }
        } catch (Exception ex) {
            CMS.debug("RegistyAdminServlet: getSupportConstraintPolicies: " + ex.toString());
            CMS.debug(ex);
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    public void getProfileImplConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException {

        // Get the policy impl id.
        String id = req.getParameter(Constants.RS_ID);
        String scope = req.getParameter(Constants.OP_SCOPE);

        if (id == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }

        IPluginInfo info = mRegistry.getPluginInfo(scope, id);

        if (info == null) {
            sendResponse(ERROR, MISSING_POLICY_IMPL_ID, null, resp);
            return;
        }

        NameValuePairs nvp = new NameValuePairs();

        String className = info.getClassName();
        IConfigTemplate template = null;

        try {
            template = (IConfigTemplate)
                    Class.forName(className).newInstance();
        } catch (Exception e) {
        }
        if (template != null) {
            Enumeration<String> names = template.getConfigNames();

            if (names != null) {
                while (names.hasMoreElements()) {
                    String name = names.nextElement();
                    CMS.debug("RegistryAdminServlet: getProfileImpl descriptor " + name);
                    IDescriptor desc = template.getConfigDescriptor(getLocale(req), name);

                    if (desc != null) {
                        try {
                            String value =
                                    getNonNull(desc.getSyntax())
                                            + ";" + getNonNull(desc.getConstraint()) + ";"
                                            + desc.getDescription(getLocale(req)) + ";"
                                            + getNonNull(desc.getDefaultValue());

                            CMS.debug("RegistryAdminServlet: getProfileImpl " + value);
                            nvp.put(name, value);
                        } catch (Exception e) {

                            CMS.debug("RegistryAdminServlet: getProfileImpl skipped descriptor for " + name);
                        }
                    } else {
                        CMS.debug("RegistryAdminServlet: getProfileImpl cannot find descriptor for " + name);
                    }
                }
            }
        }
        sendResponse(SUCCESS, null, nvp, resp);
    }

    protected String getNonNull(String s) {
        if (s == null)
            return "";
        return s;
    }
}
