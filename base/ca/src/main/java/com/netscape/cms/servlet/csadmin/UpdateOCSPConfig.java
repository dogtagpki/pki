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
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.json.JSONObject;

@WebServlet(
        name = "caUpdateOCSPConfig",
        urlPatterns = "/ee/ca/updateOCSPConfig",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="ID",            value="caUpdateOCSPConfig"),
                @WebInitParam(name="interface",     value="ee"),
                @WebInitParam(name="AuthMgr",       value="TokenAuth"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="resourceID",    value="certServer.admin.ocsp"),
        }
)
public class UpdateOCSPConfig extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UpdateOCSPConfig.class);

    private static final long serialVersionUID = 42812270761684404L;
    private final static String SUCCESS = "0";
    private final static String FAILED = "1";
    private final static String AUTH_FAILURE = "2";

    public UpdateOCSPConfig() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        logger.debug("UpdateOCSPConfig: initializing...");
        super.init(sc);
        logger.debug("UpdateOCSPConfig: done initializing...");
    }

    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {
        logger.debug("UpdateOCSPConfig: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        logger.debug("UpdateOCSPConfig process: authentication starts");

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        AuthToken authToken = authenticate(cmsReq);
        if (authToken == null) {
            logger.warn("UpdateOCSPConfig process: authToken is null");
            outputError(httpResp, AUTH_FAILURE, "Error: not authenticated",
                        null);
        }

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "modify");
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

        String nickname = "";

        // get nickname
        try {
            nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!CryptoUtil.isInternalToken(tokenname))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
        }

        logger.debug("UpdateOCSPConfig process: nickname=" + nickname);

        String ocsphost = httpReq.getParameter("ocsp_host");
        String ocspport = httpReq.getParameter("ocsp_port");
        String ocspname = ocsphost.replace('.', '-')+"-"+ocspport;
        String publisherPrefix = "ca.publish.publisher.instance.OCSPPublisher-"+ocspname;
        String rulePrefix = "ca.publish.rule.instance.ocsprule-"+ocspname;

        String url = "https://" + ocsphost + ":" + ocspport;
        logger.info("UpdateOCSPConfig: Adding OCSP publisher for " + url);

        try {
            cs.putString("ca.publish.enable", "true");
            cs.putString(publisherPrefix+".host", ocsphost);
            cs.putString(publisherPrefix+".port", ocspport);
            cs.putString(publisherPrefix+".nickName", nickname);
            cs.putString(publisherPrefix+".path", "/ocsp/agent/ocsp/addCRL");
            cs.putString(publisherPrefix+".pluginName", "OCSPPublisher");
            cs.putString(publisherPrefix+".enableClientAuth", "true");
            cs.putString(rulePrefix+".enable", "true");
            cs.putString(rulePrefix+".mapper", "NoMap");
            cs.putString(rulePrefix+".pluginName", "Rule");
            cs.putString(rulePrefix+".publisher", "OCSPPublisher-"+ocspname);
            cs.putString(rulePrefix+".type", "crl");
            cs.commit(false);

        } catch (Exception e) {
            String message = "Unable to add OCSP publisher for " + url + ": " + e.getMessage();
            logger.error("UpdateOCSPConfig: " + message, e);
            sendResponse(httpResp, FAILED, message);
            return;
        }

        UGSubsystem ugSubsystem = engine.getUGSubsystem();

        String uid = "OCSP-" + ocsphost + "-" + ocspport;
        String fullName = "OCSP " + ocsphost + " " + ocspport;
        logger.info("UpdateOCSPConfig: Adding " + uid + " user");

        Auditor auditor = engine.getAuditor();
        String auditSubjectID = auditSubjectID();
        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;UpdateOCSPConfig" +
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
            logger.info("UpdateOCSPConfig: User " + uid + " already exists");

        } catch (Exception e) {
            String message = "Unable to add " + uid + " user: " + e.getMessage();
            logger.error("UpdateOCSPConfig: " + message, e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            sendResponse(httpResp, FAILED, message);
            return;
        }

        String cert = httpReq.getParameter("subsystemCert");
        logger.info("UpdateOCSPConfig: Adding cert for " + uid + " user");

        auditParams = "Scope;;certs+Operation;;OP_ADD+source;;UpdateOCSPConfig" +
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
            logger.info("UpdateOCSPConfig: Certificate for " + uid + " already exists: " + e.getMessage(), e);

        } catch (Exception e) {
            String message = "Unable to add cert for " + uid + " user: " + e.getMessage();
            logger.error("UpdateOCSPConfig: " + message, e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            sendResponse(httpResp, FAILED, message);
            return;
        }

        String groupName = "Subsystem Group";
        logger.info("UpdateOCSPConfig: Adding " + uid + " user into " + groupName);

        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;UpdateOCSPConfig" +
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
                logger.info("UpdateOCSPConfig: User " + uid + " already in " + groupName);
            }

        } catch (Exception e) {
            String message = "Unable to add " + uid + " user into " + groupName + ": " + e.getMessage();
            logger.error("UpdateOCSPConfig: " + message, e);

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
            logger.debug("UpdateOCSPConfig: Sending response");
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
            logger.error("UpdateOCSPConfig: Failed to update OCSP configuration: " + e.getMessage(), e);
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
