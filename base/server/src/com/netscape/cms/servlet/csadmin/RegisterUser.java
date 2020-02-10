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
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.w3c.dom.Node;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.usrgrp.ICertUserLocator;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This servlet creates a TPS user in the CA,
 * and it associates TPS's server certificate to
 * the user. Finally, it addes the user to the
 * administrator group. This procedure will
 * allows TPS to connect to the CA for certificate
 * issuance.
 */
public class RegisterUser extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RegisterUser.class);

    private static final long serialVersionUID = -699307373400031138L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";
    private String mGroupName = null;
    public RegisterUser() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        logger.debug("RegisterUser: initializing...");
        super.init(sc);
        logger.debug("RegisterUser: done initializing...");
        mGroupName = sc.getInitParameter("GroupName");
        logger.debug("RegisterUser: group name " + mGroupName);
    }

    /**
     * Process the HTTP request.
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {

        logger.debug("RegisterUser: Processing request");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMSEngine engine = CMS.getCMSEngine();
        IAuthToken authToken = null;

        try {
            logger.info("RegisterUser: Authenticating request");
            authToken = authenticate(cmsReq);
            logger.debug("RegisterUser: authentication successful");

        } catch (Exception e) {
            logger.error("Unable to authenticate request: " + e.getMessage(), e);
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated", null);
            return;
        }

        if (authToken == null) {
            logger.error("Unable to authenticate request");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        AuthzToken authzToken = null;
        try {
            logger.info("RegisterUser: Authorizing request");
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "modify");
            logger.debug("RegisterUser: Authorization successful");

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
            logger.error("Unable to authorize request");
            outputError(httpResp, "Error: Not authorized");
            return;
        }

        // create user and add certificate
        String uid = httpReq.getParameter("uid");
        String name = httpReq.getParameter("name");
        String certsString = httpReq.getParameter("certificate");

        logger.info("RegisterUser: uid: " + uid);
        logger.info("RegisterUser: name: " + name);
        logger.info("RegisterUser: cert: " + certsString);

        String auditSubjectID = auditSubjectID();
        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;RegisterUser" +
                             "+Resource;;" + uid +
                             "+fullname;;" + name +
                             "+state;;1" +
                             "+userType;;<null>+email;;<null>+password;;<null>+phone;;<null>";

        UGSubsystem ugsys = engine.getUGSubsystem();

        IUser user = null;
        boolean foundByCert = false;
        X509Certificate certs[] = new X509Certificate[1];

        try {
            logger.info("RegisterUser: Searching user by cert");

            byte[] bCert = Utils.base64decode(certsString);
            X509CertImpl cert = new X509CertImpl(bCert);
            certs[0] = cert;

            // test to see if the cert already belongs to a user
            ICertUserLocator cul = ugsys.getCertUserLocator();
            com.netscape.certsrv.usrgrp.Certificates c =
                    new com.netscape.certsrv.usrgrp.Certificates(certs);
            user = cul.locateUser(c);

        } catch (Exception e) {
            logger.warn("Unable to find user: " + e.getMessage());
        }

        if (user == null) {
            logger.info("RegisterUser: Searching user by uid");
            try {
                user = ugsys.getUser(uid);
                logger.debug("RegisterUser: found user " + uid);
            } catch (Exception eee) {
                logger.warn("Unable to find user " + uid);
            }

        } else {
            logger.info("RegisterUser: Found user by cert");
            foundByCert = true;
        }

        try {
            if (user == null) {

                logger.info("RegisterUser: Creating user " + uid);

                user = ugsys.createUser(uid);
                user.setFullName(name);
                user.setState("1");
                user.setUserType("");
                user.setEmail("");
                user.setPhone("");
                user.setPassword("");

                ugsys.addUser(user);
                logger.debug("RegisterUser: created user " + uid);

                audit(new ConfigRoleEvent(
                              auditSubjectID,
                              ILogger.SUCCESS,
                              auditParams));
            }

            // concatenate lines
            certsString = certsString.replace("\r", "").replace("\n", "");

            auditParams = "Scope;;certs+Operation;;OP_ADD+source;;RegisterUser" +
                        "+Resource;;" + uid +
                        "+cert;;" + certsString;

            user.setX509Certificates(certs);

            if (!foundByCert) {
                logger.info("RegisterUser: Adding user certificate");
                ugsys.addUserCert(user);

                audit(new ConfigRoleEvent(
                              auditSubjectID,
                              ILogger.SUCCESS,
                              auditParams));

            } else {
                logger.debug("RegisterUser: No need to add user certificate");
            }

        } catch (Exception e) {
            logger.error("Unable to create user: " + e.getMessage(), e);

            audit(new ConfigRoleEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams));

            outputError(httpResp, "Error: Certificate malformed");
            return;
        }

        logger.info("RegisterUser: Adding user to group " + mGroupName);

        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;RegisterUser" +
                      "+Resource;;" + mGroupName;
        try {
            Enumeration<IGroup> groups = ugsys.findGroups(mGroupName);
            IGroup group = groups.nextElement();

            auditParams += "+user;;";
            Enumeration<String> members = group.getMemberNames();
            while (members.hasMoreElements()) {
                auditParams += members.nextElement();
                if (members.hasMoreElements()) {
                    auditParams += ",";
                }
            }

            if (!group.isMember(user.getUserID())) {
                auditParams += "," + user.getUserID();
                group.addMemberName(user.getUserID());
                ugsys.modifyGroup(group);
                logger.debug("RegisterUser modified group");

                audit(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));
            }

        } catch (Exception e) {
            logger.warn("Unable to add user to group " + mGroupName + ": " + e.getMessage(), e);
            audit(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));
        }

        try {
            logger.debug("RegisterUser: Sending response");
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);

        } catch (Exception e) {
            logger.warn("RegisterUser: Failed to send the XML output: " + e.getMessage(), e);
        }
    }

    protected void setDefaultTemplates(ServletConfig sc) {
    }

    protected void renderTemplate(
            CMSRequest cmsReq, String templateName, ICMSTemplateFiller filler)
            throws IOException {// do nothing
    }

    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    /**
     * Retrieves locale based on the request.
     */
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
