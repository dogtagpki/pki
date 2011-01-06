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


import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.password.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.kra.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.usrgrp.*;


/**
 * A class representings an administration servlet for Key
 * Recovery Authority. This servlet is responsible to serve 
 * KRA administrative operation such as configuration 
 * parameter updates.
 *
 * @version $Revision$, $Date$
 */
public class KRAAdminServlet extends AdminServlet {
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
                    setGeneralConfig(req,resp);
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
        params.add(Constants.PR_NO_OF_REQUIRED_RECOVERY_AGENTS, Integer.toString(value));

        sendResponse(SUCCESS, null, params, resp);
    }

    private void setGeneralConfig(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration enum1 = req.getParameterNames();
        boolean restart = false;

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        while (enum1.hasMoreElements()) {
            String key = (String) enum1.nextElement();
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

    /**
     * Changes M-N scheme.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_DRM used when configuring
     * DRM (Key recovery scheme, change of any secret component)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception EBaseException an error has occurred
     */
    private synchronized void changeMNScheme(HttpServletRequest req, 
        HttpServletResponse resp) throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            try {
                NameValuePairs params = new NameValuePairs();
                String recN = getParameter(req, 
                        Constants.PR_RECOVERY_N);
                String recM = getParameter(req, 
                        Constants.PR_RECOVERY_M);
                String oldAgents = getParameter(req, 
                        Constants.PR_OLD_RECOVERY_AGENT);
                String agents = getParameter(req, 
                        Constants.PR_RECOVERY_AGENT);

                if (recN == null) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                       LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                       auditSubjectID,
                                       ILogger.FAILURE,
                                       auditParams(req));

                    audit(auditMessage);

                    throw new EKRAException(
                                  CMS.getLogMessage("KRA_INVALID_N"));
                }

                if (recM == null) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                       LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                       auditSubjectID,
                                       ILogger.FAILURE,
                                       auditParams(req));

                    audit(auditMessage);

                    throw new EKRAException(
                                  CMS.getLogMessage("KRA_INVALID_M"));
                }

                if (recN != null && recM != null && oldAgents != null 
                    && agents != null) {
                    int nVal = Integer.parseInt(recN);

                    int mVal = Integer.parseInt(recM);

                    Credential oldcreds[] = 
                        parseCredentialStr(oldAgents);

                    if (oldcreds == null) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req));

                        audit(auditMessage);

                        throw new EKRAException(	
                                CMS.getLogMessage("KRA_INVALID_PASSWORD"));
                    }

                    Credential creds[] = 
                        parseCredentialStr(agents);

                    if (creds == null) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req));

                        audit(auditMessage);

                        throw new EKRAException(	
                                CMS.getLogMessage("KRA_INVALID_PASSWORD"));
                    } else {
                        for (int i = 0; i < creds.length; i++) {
                            Credential credential = creds[i];
                            String pass = credential.getPassword();
                            IPasswordCheck checker = CMS.getPasswordChecker();

                            if (!checker.isGoodPassword(pass)) {
                                // store a message in the signed audit log file
                                auditMessage = CMS.getLogMessage(
                                            LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                            auditSubjectID,
                                            ILogger.FAILURE,
                                            auditParams(req));

                                audit(auditMessage);

                                throw new EBaseException(checker.getReason(pass));
                            }
                        }
                    }
                    if (mKRA.getStorageKeyUnit().changeAgentMN(
                            nVal, mVal, oldcreds, creds)) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    auditParams(req));

                        audit(auditMessage);

                        // successful operation
                        sendResponse(SUCCESS, null, params, 
                            resp);
                        return;
                    }
                }
            } catch (IOException e) {
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_OPERATION"));
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    /**
     * Changes recovery agent password.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_DRM used when configuring
     * DRM (Key recovery scheme, change of any secret component)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception EBaseException an error has occurred
     */
    private synchronized void changeAgentPwd(HttpServletRequest req, 
        HttpServletResponse resp) throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            try {
                String id = getParameter(req, Constants.RS_ID);
                String oldpwd = getParameter(req, 
                        Constants.PR_OLD_AGENT_PWD);
                String newpwd = getParameter(req, 
                        Constants.PR_AGENT_PWD);
                IPasswordCheck checker = CMS.getPasswordChecker();

                if (!checker.isGoodPassword(newpwd)) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    throw new EBaseException(checker.getReason(newpwd));
                }
          
                if (mKRA.getStorageKeyUnit().changeAgentPassword(id, 
                        oldpwd, newpwd)) {
                    NameValuePairs params = new NameValuePairs();

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                auditSubjectID,
                                ILogger.SUCCESS,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(SUCCESS, null, params, resp);
                    return;
                } else {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    throw new EKRAException(	
                            CMS.getLogMessage("KRA_INVALID_PASSWORD"));
                }
            } catch (IOException e) {
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_OPERATION"));
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    /**
     * Modifies auto recovery configuration.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_DRM used when configuring
     * DRM (Key recovery scheme, change of any secret component)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception EBaseException an error has occurred
     */
    private synchronized void modifyAutoRecoveryConfig(
        HttpServletRequest req, HttpServletResponse resp) 
        throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            try {
                NameValuePairs params = new NameValuePairs();
                String autoOn = getParameter(req, 
                        Constants.PR_AUTO_RECOVERY_ON);
                String agents = getParameter(req, 
                        Constants.PR_RECOVERY_AGENT);

                if (autoOn.equals(Constants.TRUE)) {
                    Credential creds[] = parseCredentialStr(
                            agents);

                    if (mKRA.setAutoRecoveryState(creds, true)) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    auditParams(req));

                        audit(auditMessage);

                        sendResponse(SUCCESS, null, params, 
                            resp);
                        return;
                    }
                } else if (autoOn.equals(Constants.FALSE)) {
                    if (mKRA.setAutoRecoveryState(null, false)) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    auditParams(req));

                        audit(auditMessage);

                        sendResponse(SUCCESS, null, params, 
                            resp);
                        return;
                    }
                }
            } catch (IOException e) {
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_OPERATION"));
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    /**
     * Reads auto recovery status.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    private synchronized void readAutoRecoveryConfig(
        HttpServletRequest req, HttpServletResponse resp) 
        throws EBaseException {
        try {
            NameValuePairs params = new NameValuePairs();

            params.add(Constants.PR_AUTO_RECOVERY_ON, 
                mKRA.getAutoRecoveryState() ?
                Constants.TRUE : Constants.FALSE);
            sendResponse(SUCCESS, null, params, resp);
        } catch (IOException e) {
            throw new EBaseException(
                    CMS.getLogMessage("BASE_INVALID_OPERATION"));
        }
    }

    /**
     * Reads recovery configuration.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    private synchronized void readRecoveryConfig(
        HttpServletRequest req, HttpServletResponse resp) 
        throws EBaseException {
        try {
            IStorageKeyUnit sku = mKRA.getStorageKeyUnit();
            NameValuePairs params = new NameValuePairs();

            params.add(Constants.PR_RECOVERY_N, 
                Integer.toString(sku.getNoOfAgents()));
            params.add(Constants.PR_RECOVERY_M, 
                Integer.toString(sku.getNoOfRequiredAgents()));
            Enumeration e = sku.getAgentIdentifiers();
            StringBuffer as = new StringBuffer();

            while (e.hasMoreElements()) {
                as.append((String)e.nextElement());
                if (e.hasMoreElements()) {
                    as.append(",");
                }
            }
            params.add(Constants.PR_RECOVERY_AGENT, as.toString());
            sendResponse(SUCCESS, null, params, resp);
        } catch (IOException e) {
            throw new EBaseException(
                    CMS.getLogMessage("BASE_INVALID_OPERATION"));
        }
    }

    /**
     * Reads information about auto recovery agents.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    private synchronized void readAutoRecoveryAgents(
        HttpServletRequest req, HttpServletResponse resp) 
        throws EBaseException {
        try {
            // send the entire list anyway
            NameValuePairs params = new NameValuePairs();
            Enumeration e = mKRA.getAutoRecoveryIDs();
            StringBuffer users = new StringBuffer();

            while (e.hasMoreElements()) {
                users.append((String) e.nextElement());
                if (e.hasMoreElements()) {
                    users.append(",");
                }
            }
            params.add(Constants.PR_GROUP_USER, users.toString());
            params.add(Constants.PR_GROUP_DESC, 
                "Auto Recovery Agents"); // XXX - localized
            sendResponse(SUCCESS, null, params, resp);
        } catch (IOException e) {
            throw new EBaseException(
                    CMS.getLogMessage("BASE_INVALID_OPERATION"));
        }
    }

    /**
     * Modifies information about auto recovery agents.
     *
     * @param req HTTP request
     * @param resp HTTP response
     */
    private synchronized void modifyAutoRecoveryAgents(
        HttpServletRequest req, HttpServletResponse resp) 
        throws EBaseException {
        Vector v = new Vector();
        String users = getParameter(req, 
                Constants.PR_GROUP_USER);
        StringTokenizer st = new StringTokenizer(users, ",");

        while (st.hasMoreTokens()) {
            v.addElement(st.nextToken());
        }
        String desc = getParameter(req, 
                Constants.PR_GROUP_DESC);
        String agents = getParameter(req, 
                Constants.PR_RECOVERY_AGENT);
        Credential creds[] = parseCredentialStr(
                agents);
        // XXX - check if the given password matched
        // put ids into hashtable so that we can
        // figure out what should be saved and deleted
        Enumeration e = mKRA.getAutoRecoveryIDs();	
        Hashtable h = new Hashtable();

        while (e.hasMoreElements()) {
            h.put(e.nextElement(), "");
        }

        // go through each of the user in the new list
        for (int i = 0; i < v.size(); i++) {
            String key = (String) v.elementAt(i);

            if (h.containsKey(key)) {
                h.remove(key);
            } else {
                mKRA.addAutoRecovery(key, creds);
            }
        }

        // delete all the unreferenced
        Enumeration dels = h.keys();

        while (dels.hasMoreElements()) {
            mKRA.removeAutoRecovery((String)
                dels.nextElement());
        }
    }

    /**
     * Parses uid0=pwd0,uid1=pwd1,... into AgentCredential.
     *
     * @param s credential string
     * @return a list of credentials
     */
    private Credential[] parseCredentialStr(String s) {
        StringTokenizer st = new StringTokenizer(s, ",");
        Vector v = new Vector();

        while (st.hasMoreTokens()) {
            String a = st.nextToken();
            StringTokenizer st0 = new StringTokenizer(a, "=");

            v.addElement(new Credential(st0.nextToken(),
                    st0.nextToken()));
        }
        Credential ac[] = new Credential[v.size()];

        v.copyInto(ac);
        return ac;
    }

    /*
     * handle getting request in queue notification config info
     */
    private void getNotificationRIQConfig(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        IConfigStore config = mKRA.getConfigStore();
        IConfigStore nc =
            config.getSubStore(mKRA.PROP_NOTIFY_SUBSTORE);

        IConfigStore riq = nc.getSubStore(mKRA.PROP_REQ_IN_Q_SUBSTORE);

        Enumeration e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            params.add(name, riq.getString(name, ""));
        }

        params.add(Constants.PR_ENABLE, 
            riq.getString(PROP_ENABLED, Constants.FALSE));
        //System.out.println("Send: "+params.toString());
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Handle setting request in queue notification config info
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_DRM used when configuring
     * DRM (Key recovery scheme, change of any secret component)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setNotificationRIQConfig(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            IConfigStore config = mKRA.getConfigStore();
            IConfigStore nc =
                config.getSubStore(mKRA.PROP_NOTIFY_SUBSTORE);

            IConfigStore riq = nc.getSubStore(mKRA.PROP_REQ_IN_Q_SUBSTORE);

            //set rest of the parameters
            Enumeration e = req.getParameterNames();

            while (e.hasMoreElements()) {
                String name = (String) e.nextElement();

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
                mKRA.getRequestInQListener().set(name, val);
            }

            // set enable flag
            String enabledString = req.getParameter(Constants.PR_ENABLE);

            riq.putString(PROP_ENABLED, enabledString);
            mKRA.getRequestInQListener().set(PROP_ENABLED, enabledString);

            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_DRM,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }
}
