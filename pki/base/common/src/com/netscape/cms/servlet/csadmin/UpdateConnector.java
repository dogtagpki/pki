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


public class UpdateConnector extends CMSServlet {

    private final static String SUCCESS = "0";
    private final static String FAILED = "1";
    private final static String AUTH_FAILURE = "2";

    public UpdateConnector() {
        super();
    }

    /**
     * initialize the servlet.
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("UpdateConnector: initializing...");
        super.init(sc);
        CMS.debug("UpdateConnector: done initializing...");
    }

    /**
     * Process the HTTP request. 
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("UpdateConnector: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        IAuthToken authToken = null;
        try {
            authToken = authenticate(cmsReq);
            CMS.debug("UpdateConnector authentication successful.");
        } catch (Exception e) {
            CMS.debug("UpdateConnector: authentication failed.");
            log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "",
                    e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated");
            return;
        }

        if (authToken == null) {
            CMS.debug("UpdateConnector: authentication failed.");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated");
            return;
        }

        AuthzToken authzToken = null;
        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName, 
              "modify");
            CMS.debug("UpdateConnector authorization successful.");
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

        Enumeration list = httpReq.getParameterNames();
        while (list.hasMoreElements()) {
            String name = (String)list.nextElement();
            String val = httpReq.getParameter(name);
            if (name != null && name.startsWith("ca.connector")) {
                CMS.debug("Adding connector update name=" + name + " val=" + val);
                cs.putString(name, val);
            } else {
                CMS.debug("Skipping connector update name=" + name + " val=" + val);
            }
        }
 
        try { 
            String nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!tokenname.equals("Internal Key Storage Token"))
                nickname = tokenname+":"+nickname;
            cs.putString("ca.connector.KRA.nickName", nickname);
            cs.commit(false);
        } catch (Exception e) {
        }

        // start the connector
        try { 
            ICertificateAuthority ca = (ICertificateAuthority)
                CMS.getSubsystem("ca");
            ICAService caService = (ICAService)ca.getCAService();
            IConnector kraConnector = caService.getConnector(
                cs.getSubStore("ca.connector.KRA"));
            caService.setKRAConnector(kraConnector);
            kraConnector.start();
        } catch (Exception e) {
            CMS.debug("Failed to start connector " + e);
        }

        // send success status back to the requestor
        try {
            CMS.debug("UpdateConnector: Sending response");
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("UpdateConnector: Failed to send the XML output");
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
