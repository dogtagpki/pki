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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import javax.servlet.*;
import java.security.cert.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.cms.servlet.*;
import com.netscape.cmsutil.xml.*;
import org.w3c.dom.*;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.dom.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import com.netscape.certsrv.connector.*;
import com.netscape.certsrv.ca.*;

/**
 * This servlet creates a TPS user in the CA,
 * and it associates TPS's server certificate to
 * the user. Finally, it addes the user to the
 * administrator group. This procedure will 
 * allows TPS to connect to the CA for certificate
 * issuance.
 */
public class RegisterUser extends CMSServlet {

    private final static String SUCCESS = "0";
    private final static String FAILED = "1";
    private final static String AUTH_FAILURE = "2";
    private String mGroupName = null;

    public RegisterUser() {
        super();
    }

    /**
     * initialize the servlet.
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("RegisterUser: initializing...");
        super.init(sc);
        CMS.debug("RegisterUser: done initializing...");
        mGroupName = sc.getInitParameter("GroupName");
        CMS.debug("RegisterUser: group name " + mGroupName);
    }

    /**
     * Process the HTTP request. 
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("UpdateUpdater: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        IAuthToken authToken = null;
        try {
            authToken = authenticate(cmsReq);
            CMS.debug("RegisterUser authentication successful.");
        } catch (Exception e) {
            CMS.debug("RegisterUser: authentication failed.");
            log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "",
                    e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated");
            return;
        }

        if (authToken == null) {
            CMS.debug("RegisterUser: authentication failed.");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated");
            return;
        }

        AuthzToken authzToken = null;
        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName, 
              "modify");
            CMS.debug("RegisterUser authorization successful.");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            outputError(httpResp, "Error: Not authorized");
            return;
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            outputError(httpResp,
                "Error: Encountered problem during authorization.");
            return;
        }

        if (authzToken == null) {
            outputError(httpResp, "Error: Not authorized");
            return;
        }

        IConfigStore cs = CMS.getConfigStore();

        // create user and add certificate
        String uid = httpReq.getParameter("uid");
        String name = httpReq.getParameter("name");
        String certsString = httpReq.getParameter("certificate");
        CMS.debug("RegisterUser got uid=" + uid);
        CMS.debug("RegisterUser got name=" + name);
        CMS.debug("RegisterUser got certsString=" + certsString);

        IUGSubsystem ugsys = (IUGSubsystem)CMS.getSubsystem(CMS.SUBSYSTEM_UG);

        IUser user = null;
        boolean foundByCert = false;
        X509Certificate certs[] = new X509Certificate[1];
        try {

          byte bCert[] = null;
          X509CertImpl cert = null;
          bCert = (byte[]) (com.netscape.osutil.OSUtil.AtoB(certsString));
          cert = new X509CertImpl(bCert);
          certs[0] = (X509Certificate)cert;

          // test to see if the cert already belongs to a user
          ICertUserLocator cul = ugsys.getCertUserLocator();
          com.netscape.certsrv.usrgrp.Certificates c =
            new com.netscape.certsrv.usrgrp.Certificates(certs);
          user = (IUser) cul.locateUser(c);
        } catch (Exception ec) {
            CMS.debug("RegisterUser: exception thrown: "+ec.toString());
        }
        if (user == null) {
          CMS.debug("RegisterUser NOT found user by cert");
          try { 
            user = ugsys.getUser(uid);
            CMS.debug("RegisterUser found user by uid "+uid);
          } catch (Exception eee) {
          } 
        } else {
          foundByCert = true;
          CMS.debug("RegisterUser found user by cert");
        }
    
        try { 

          if (user == null) {
            // create user only if such user does not exist
            user = ugsys.createUser(uid);
            user.setFullName(name);
            user.setState("1");
            user.setUserType("");
            user.setEmail("");
            user.setPhone("");
            user.setPassword("");
            ugsys.addUser(user);
            CMS.debug("RegisterUser created user " + uid);
          }

          user.setX509Certificates(certs);
          if (!foundByCert) {
            ugsys.addUserCert(user);
            CMS.debug("RegisterUser added user certificate");
          } else
            CMS.debug("RegisterUser no need to add user certificate");
        } catch (Exception eee) {
            CMS.debug("RegisterUser error " + eee.toString());
            outputError(httpResp, "Error: Certificate malformed");
            return;
        }


        // add user to the group
        Enumeration groups = ugsys.findGroups(mGroupName);
        IGroup group = (IGroup)groups.nextElement();
        group.addMemberName(user.getUserID());
        ugsys.modifyGroup(group);
        CMS.debug("RegisterUser modified group");

        // send success status back to the requestor
        try {
            CMS.debug("RegisterUser: Sending response");
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("RegisterUser: Failed to send the XML output");
        }
    }

    protected void setDefaultTemplates(ServletConfig sc) {}

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
