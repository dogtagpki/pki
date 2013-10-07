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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequestListener;

/**
 * A class representings an administration servlet for Registration
 * Authority. This servlet is responsible to serve RA
 * administrative operations such as configuration parameter
 * updates.
 *
 * @version $Revision$, $Date$
 */
public class RAAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = 8417319111438832435L;

    protected static final String PROP_ENABLED = "enabled";

    /*==========================================================
     * variables
     *==========================================================*/
    private final static String INFO = "RAAdminServlet";
    private IRegistrationAuthority mRA = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * Constructs RA servlet.
     */
    public RAAdminServlet() {
        super();
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mRA = (IRegistrationAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_RA);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request. Each request is authenticated to
     * the authenticate manager.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        //get all operational flags
        String op = req.getParameter(Constants.OP_TYPE);
        String scope = req.getParameter(Constants.OP_SCOPE);

        //check operational flags
        if ((op == null) || (scope == null)) {
            sendResponse(1, "Invalid Protocol", null, resp);
            return;
        }

        //authenticate the user
        super.authenticate(req);

        //perform services
        try {
            AUTHZ_RES_NAME = "certServer.ra.configuration";
            if (op.equals(OpDef.OP_READ)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_GENERAL)) {
                    readGeneralConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_CONNECTOR)) {
                    getConnectorConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_REQ_COMP)) {
                    getNotificationReqCompConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_REV_COMP)) {
                    getNotificationRevCompConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_RIQ)) {
                    getNotificationRIQConfig(req, resp);
                    return;
                } else {
                    sendResponse(1, "Unknown operation", null, resp);
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
                if (scope.equals(ScopeDef.SC_GENERAL)) {
                    modifyGeneralConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_CONNECTOR)) {
                    setConnectorConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_REQ_COMP)) {
                    setNotificationReqCompConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_REV_COMP)) {
                    setNotificationRevCompConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_NOTIFICATION_RIQ)) {
                    setNotificationRIQConfig(req, resp);
                    return;
                } else {
                    sendResponse(1, "Unknown operation", null, resp);
                    return;
                }
            }
        } catch (Exception e) {
            //System.out.println("XXX >>>" + e.toString() + "<<<");
            sendResponse(1, "Unknown operation", null, resp);
        }

        return;
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    /*
     * handle getting completion (cert issued) notification config info
     */
    private void getNotificationCompConfig(HttpServletRequest req,
            HttpServletResponse resp, IConfigStore rc) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            params.put(name, rc.getString(name, ""));
        }

        params.put(Constants.PR_ENABLE,
                rc.getString(PROP_ENABLED, Constants.FALSE));
        //System.out.println("Send: "+params.toString());
        sendResponse(SUCCESS, null, params, resp);
    }

    private void getNotificationReqCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore config = mRA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(IRegistrationAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore rc = nc.getSubStore(IRegistrationAuthority.PROP_CERT_ISSUED_SUBSTORE);

        getNotificationCompConfig(req, resp, rc);

    }

    private void getNotificationRevCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore config = mRA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(IRegistrationAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore rc = nc.getSubStore(IRegistrationAuthority.PROP_CERT_REVOKED_SUBSTORE);

        getNotificationCompConfig(req, resp, rc);

    }

    /*
     * handle getting request in queue notification config info
     */
    private void getNotificationRIQConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        IConfigStore config = mRA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(IRegistrationAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore riq = nc.getSubStore(IRegistrationAuthority.PROP_REQ_IN_Q_SUBSTORE);

        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            params.put(name, riq.getString(name, ""));
        }

        params.put(Constants.PR_ENABLE,
                riq.getString(PROP_ENABLED, Constants.FALSE));
        //System.out.println("Send: "+params.toString());
        sendResponse(SUCCESS, null, params, resp);
    }

    /*
     * handle setting request in queue notification config info
     */
    private void setNotificationRIQConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore config = mRA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(IRegistrationAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore riq = nc.getSubStore(IRegistrationAuthority.PROP_REQ_IN_Q_SUBSTORE);

        //set rest of the parameters
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            String val = req.getParameter(name);

            riq.putString(name, val);
            mRA.getRequestInQListener().set(name, val);
        }

        // set enable flag
        String enabledString = req.getParameter(Constants.PR_ENABLE);

        riq.putString(PROP_ENABLED, enabledString);
        mRA.getRequestInQListener().set(PROP_ENABLED, enabledString);

        commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    /*
     * handle setting request complete notification config info
     */
    private void setNotificationCompConfig(HttpServletRequest req,
            HttpServletResponse resp, IConfigStore rc, IRequestListener thisListener) throws ServletException,
            IOException, EBaseException {
        //set rest of the parameters
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            String val = req.getParameter(name);

            rc.putString(name, val);
            thisListener.set(name, val);
        }

        // set enable flag
        String enabledString = req.getParameter(Constants.PR_ENABLE);

        rc.putString(PROP_ENABLED, enabledString);
        thisListener.set(PROP_ENABLED, enabledString);

        commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    private void setNotificationReqCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore config = mRA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(IRegistrationAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore rc = nc.getSubStore(IRegistrationAuthority.PROP_CERT_ISSUED_SUBSTORE);

        setNotificationCompConfig(req, resp, rc, mRA.getCertIssuedListener());

    }

    private void setNotificationRevCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore config = mRA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(IRegistrationAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore rc = nc.getSubStore(IRegistrationAuthority.PROP_CERT_REVOKED_SUBSTORE);

        setNotificationCompConfig(req, resp, rc, mRA.getCertRevokedListener());
    }

    private void getConnectorConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore raConfig = mRA.getConfigStore();
        IConfigStore connectorConfig = raConfig.getSubStore("connector");
        IConfigStore caConnectorConfig = null;

        if (isCAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("CA");
        } else if (isRAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("RA");
        } else if (isKRAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("KRA");
        }

        /*
         Enumeration enum = req.getParameterNames();
         NameValuePairs params = new NameValuePairs();
         while (enum.hasMoreElements()) {
         String key = (String)enum.nextElement();
         if (key.equals("RS_ID")) {
         String val = req.getParameter(key);
         if (val.equals("CA Connector"))
         }
         }
         */

        Enumeration<String> enum1 = req.getParameterNames();
        NameValuePairs params = new NameValuePairs();

        if (caConnectorConfig != null) {
            while (enum1.hasMoreElements()) {
                String name = enum1.nextElement();

                if (name.equals(Constants.RS_ID))
                    continue;
                if (name.equals(Constants.OP_SCOPE))
                    continue;
                if (name.equals(Constants.OP_TYPE))
                    continue;

                params.put(name, caConnectorConfig.getString(name, ""));
            }
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    private void setConnectorConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore raConfig = mRA.getConfigStore();
        IConfigStore connectorConfig = raConfig.getSubStore("connector");
        IConfigStore caConnectorConfig = null;
        //       String nickname = raConfig.getString("certNickname", "");

        if (isCAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("CA");
        } else if (isRAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("RA");
        } else if (isKRAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("KRA");
        }

        Enumeration<String> enum1 = req.getParameterNames();

        if (caConnectorConfig != null) {
            while (enum1.hasMoreElements()) {
                String name = enum1.nextElement();

                if (name.equals(Constants.OP_TYPE))
                    continue;
                if (name.equals(Constants.RS_ID))
                    continue;
                if (name.equals(Constants.OP_SCOPE))
                    continue;
                /*
                                if (name.equals("nickName")) {
                                    caConnectorConfig.putString(name, nickname);
                                    continue;
                                }
                */
                caConnectorConfig.putString(name, req.getParameter(name));
            }
        }

        commit(true);
        sendResponse(RESTART, null, null, resp);
    }

    private boolean isCAConnector(HttpServletRequest req) {

        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();

            if (key.equals("RS_ID")) {
                String val = req.getParameter(key);

                if (val.equals("Certificate Manager Connector"))
                    return true;
                else
                    return false;
            }
        }
        return false;
    }

    private boolean isRAConnector(HttpServletRequest req) {

        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();

            if (key.equals("RS_ID")) {
                String val = req.getParameter(key);

                if (val.equals("Registration Manager Connector"))
                    return true;
                else
                    return false;
            }
        }
        return false;
    }

    private boolean isKRAConnector(HttpServletRequest req) {

        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();

            if (key.equals("RS_ID")) {
                String val = req.getParameter(key);

                if (val.equals("Data Recovery Manager Connector"))
                    return true;
                else
                    return false;
            }
        }
        return false;
    }

    //reading the RA general information
    private void readGeneralConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        /*
         ISubsystem eeGateway =
         SubsystemRegistry.getInstance().get("eeGateway");
         String value = "false";
         if (eeGateway != null) {
         IConfigStore eeConfig = eeGateway.getConfigStore();
         if (eeConfig != null)
         value = eeConfig.getString("enabled", "true");
         }
         params.add(Constants.PR_EE_ENABLED, value);
         */

        sendResponse(SUCCESS, null, params, resp);
    }

    //mdify RA General Information
    private void modifyGeneralConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        /*
         ISubsystem eeGateway =
         SubsystemRegistry.getInstance().get("eeGateway");
         IConfigStore eeConfig = null;
         if (eeGateway != null)
         eeConfig = eeGateway.getConfigStore();

         Enumeration enum = req.getParameterNames();
         while (enum.hasMoreElements()) {
         String key = (String)enum.nextElement();
         if (key.equals(Constants.PR_EE_ENABLED)) {
         if (eeConfig != null)
         eeConfig.putString("enabled",
         req.getParameter(Constants.PR_EE_ENABLED));
         }
         }

         */
        sendResponse(RESTART, null, null, resp);
        commit(true);
    }
}
