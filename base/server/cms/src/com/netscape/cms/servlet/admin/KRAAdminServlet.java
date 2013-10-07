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
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class representings an administration servlet for Key
 * Recovery Authority. This servlet is responsible to serve
 * KRA administrative operation such as configuration
 * parameter updates.
 *
 * @version $Revision$, $Date$
 */
public class KRAAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = -5794220348195666729L;

    protected static final String PROP_ENABLED = "enabled";

    private final static String INFO = "KRAAdminServlet";

    private IKeyRecoveryAuthority mKRA = null;

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_DRM =
            "LOGGING_SIGNED_AUDIT_CONFIG_DRM_3";

    /**
     * Constructs KRA servlet.
     */
    public KRAAdminServlet() {
        super();
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mKRA = (IKeyRecoveryAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_KRA);
    }

    /**
     * Returns serlvet information.
     *
     * @return name of this servlet
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP admin request.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        super.authenticate(req);
        String scope = req.getParameter(Constants.OP_SCOPE);

        if (scope == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                    null, resp);
            return;
        }
        String op = req.getParameter(Constants.OP_TYPE);

        if (op == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_TYPE", op),
                    null, resp);
            return;
        }

        try {
            AUTHZ_RES_NAME = "certServer.kra.configuration";
            if (op.equals(OpDef.OP_READ)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                /* Functions not implemented in console
                if (scope.equals(ScopeDef.SC_AUTO_RECOVERY)) {
                    readAutoRecoveryConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_RECOVERY)) {
                    readRecoveryConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_RIQ)) {
                    getNotificationRIQConfig(req, resp);
                    return;
                } else
                */
                if (scope.equals(ScopeDef.SC_GENERAL)) {
                    getGeneralConfig(req, resp);
                    return;
                }
            } else if (op.equals(OpDef.OP_MODIFY)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                /* Functions not implemented in console
                if (scope.equals(ScopeDef.SC_AUTO_RECOVERY)) {
                    modifyAutoRecoveryConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_AGENT_PWD)) {
                    changeAgentPwd(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_MNSCHEME)) {
                    changeMNScheme(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_RIQ)) {
                    setNotificationRIQConfig(req, resp);
                    return;
                } else
                */
                if (scope.equals(ScopeDef.SC_GENERAL)) {
                    setGeneralConfig(req, resp);
                }
            }
        } catch (EBaseException e) {
            // convert exception into locale-specific message
            sendResponse(ERROR, e.toString(getLocale(req)),
                    null, resp);
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
        sendResponse(ERROR,
                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                null, resp);
    }

    private void getGeneralConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        int value = 1;

        value = mKRA.getNoOfRequiredAgents();
        params.put(Constants.PR_NO_OF_REQUIRED_RECOVERY_AGENTS, Integer.toString(value));

        sendResponse(SUCCESS, null, params, resp);
    }

    private void setGeneralConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        boolean restart = false;

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_NO_OF_REQUIRED_RECOVERY_AGENTS)) {
                try {
                    int number = Integer.parseInt(value);
                    mKRA.setNoOfRequiredAgents(number);
                } catch (NumberFormatException e) {
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                    audit(auditMessage);
                    throw new EBaseException("Number of agents must be an integer");
                }
            }
        }

        commit(true);

        auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                auditSubjectID,
                ILogger.SUCCESS,
                auditParams(req));

        audit(auditMessage);

        if (restart)
            sendResponse(RESTART, null, null, resp);
        else
            sendResponse(SUCCESS, null, null, resp);
    }
}
