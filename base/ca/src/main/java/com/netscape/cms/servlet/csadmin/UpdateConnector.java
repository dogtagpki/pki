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
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.json.JSONObject;

/**
 * This servlet creates a KRA connector and also a subsystem user for KRA.
 *
 * The user needs to be added in this servlet since KRA installation with
 * external certs (including CMC) will not use caInternalAuthSubsystemCert
 * or caECInternalAuthSubsystemCert profiles.
 *
 * See also SubsystemGroupUpdater.
 */
public class UpdateConnector extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UpdateConnector.class);

    private static final long serialVersionUID = 972871860008509849L;
    private final static String SUCCESS = "0";
    private final static String FAILED = "1";
    private final static String AUTH_FAILURE = "2";

    public UpdateConnector() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        logger.debug("UpdateConnector: initializing...");
        super.init(sc);
        logger.debug("UpdateConnector: done initializing...");
    }

    public KRAConnectorInfo createConnectorInfo(HttpServletRequest httpReq) {
        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setHost(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".host"));
        info.setPort(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".port"));
        info.setTimeout(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".timeout"));
        info.setSubsystemCert(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".subsystemCert"));
        info.setTransportCert(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".transportCert"));
        info.setTransportCertNickname(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".transportCertNickname"));
        info.setUri(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".uri"));
        info.setLocal(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".local"));
        info.setEnable(httpReq.getParameter(KRAConnectorProcessor.PREFIX + ".enable"));
        return info;
    }

    /**
     * Process the HTTP request.
     */
    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {
        logger.debug("UpdateConnector: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        AuthToken authToken = null;
        try {
            authToken = authenticate(cmsReq);
            logger.debug("UpdateConnector authentication successful.");
        } catch (Exception e) {
            logger.error("UpdateConnector: authentication failed: " + e.getMessage(), e);
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated", null);
            return;
        }

        if (authToken == null) {
            logger.error("UpdateConnector: authentication failed.");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        AuthzToken authzToken = null;
        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "modify");
            logger.debug("UpdateConnector authorization successful.");
        } catch (EAuthzAccessDenied e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            outputError(httpResp, "Error: Not authorized");
            return;
        } catch (Exception e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            outputError(httpResp, "Error: Encountered problem during authorization.");
            return;
        }

        if (authzToken == null) {
            outputError(httpResp, "Error: Not authorized");
            return;
        }

        String status = SUCCESS;
        String error = "";

        CAEngine engine = CAEngine.getInstance();

        KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(httpReq));
        processor.setCMSEngine(engine);
        processor.init();

        KRAConnectorInfo info = createConnectorInfo(httpReq);

        String url = "https://" + info.getHost() + ":" + info.getPort();
        logger.info("UpdateConnector: Adding KRA connector for " + url);

        try {
            processor.addConnector(info);

        } catch (Exception e) {
            String message = "Unable to add KRA connector for " + url + ": " + e.getMessage();
            logger.error("UpdateConnector: " + message, e);
            sendResponse(httpResp, FAILED, message);
            return;
        }

        UGSubsystem ugSubsystem = engine.getUGSubsystem();

        String uid = "KRA-" + info.getHost() + "-" + info.getPort();
        String fullName = "KRA " + info.getHost() + " " + info.getPort();
        logger.info("UpdateConnector: Adding " + uid + " user");

        Auditor auditor = engine.getAuditor();
        String auditSubjectID = auditSubjectID();
        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;UpdateConnector" +
                "+Resource;;" + uid +
                "+fullname;;" + fullName +
                "+state;;1" +
                "+userType;;agentType+email;;<null>+password;;<null>+phone;;<null>";

        try {
            User user = ugSubsystem.createUser(uid);
            user.setFullName(fullName);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");

            ugSubsystem.addUser(user);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));

        } catch (ConflictingOperationException e) {
            logger.info("UpdateConnector: User " + uid + " already exists");

        } catch (Exception e) {
            String message = "Unable to add " + uid + " user: " + e.getMessage();
            logger.error("UpdateConnector: " + message, e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            sendResponse(httpResp, FAILED, message);
            return;
        }

        String cert = info.getSubsystemCert();
        logger.info("UpdateConnector: Adding cert for " + uid + " user");

        auditParams = "Scope;;certs+Operation;;OP_ADD+source;;UpdateConnector" +
                "+Resource;;" + uid +
                "+cert;;" + cert;

        try {
            byte[] binCert = Utils.base64decode(cert);
            X509CertImpl certImpl = new X509CertImpl(binCert);
            ugSubsystem.addUserCert(uid, certImpl);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));

        } catch (ConflictingOperationException e) {
            logger.info("UpdateConnector: Certificate for " + uid + " already exists: " + e.getMessage(), e);

        } catch (Exception e) {
            String message = "Unable to add cert for " + uid + " user: " + e.getMessage();
            logger.error("UpdateConnector: " + message, e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            sendResponse(httpResp, FAILED, message);
            return;
        }

        String groupName = "Subsystem Group";
        logger.info("UpdateConnector: Adding " + uid + " user into " + groupName);

        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;UpdateConnector" +
                "+Resource;;" + groupName;

        try {
            Group group = ugSubsystem.getGroupFromName(groupName);

            auditParams += "+user;;";
            Enumeration<String> members = group.getMemberNames();
            while (members.hasMoreElements()) {
                auditParams += members.nextElement();
                if (members.hasMoreElements()) {
                    auditParams += ",";
                }
            }

            if (!group.isMember(uid)) {

                auditParams += "," + uid;
                group.addMemberName(uid);
                ugSubsystem.modifyGroup(group);

                auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));

            } else {
                logger.info("UpdateConnector: User " + uid + " already in " + groupName);
            }

        } catch (Exception e) {
            String message = "Unable to add " + uid + " user into " + groupName + ": " + e.getMessage();
            logger.error("UpdateConnector: " + message, e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            sendResponse(httpResp, FAILED, message);
            return;
        }

        sendResponse(httpResp, SUCCESS, null);
    }

    public void sendResponse(HttpServletResponse httpResp, String status, String error) {

        // send success status back to the requestor
        try {
            logger.debug("UpdateConnector: Sending response");
            JSONObject jsonObj = new JSONObject();

            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            if (status.equals(SUCCESS)) {
                responseNode.put("Status", SUCCESS);
            } else {
                responseNode.put("Status", FAILED);
                responseNode.put("Error", error);
            }
            jsonObj.getRootNode().set("Response", responseNode);
            outputResult(httpResp, "application/json", jsonObj.toByteArray());
        } catch (Exception e) {
            logger.error("UpdateConnector: Failed to send the output: " + e.getMessage(), e);
        }
    }

    @Override
    protected void setDefaultTemplates(ServletConfig sc) {
    }

    @Override
    protected void renderTemplate(
            CMSRequest cmsReq, String templateName, ICMSTemplateFiller filler)
            throws IOException {// do nothing
    }

    @Override
    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    /**
     * Retrieves locale based on the request.
     */
    @Override
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                    UserInfo.getUserCountry(lang));
        }
        return locale;
    }
}
