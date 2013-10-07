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
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.xml.XMLObject;

public class UpdateOCSPConfig extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 42812270761684404L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

    public UpdateOCSPConfig() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("UpdateOCSPConfig: initializing...");
        super.init(sc);
        CMS.debug("UpdateOCSPConfig: done initializing...");
    }

    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("UpdateOCSPConfig: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMS.debug("UpdateOCSPConfig process: authentication starts");
        IAuthToken authToken = authenticate(cmsReq);
        if (authToken == null) {
            CMS.debug("UpdateOCSPConfig process: authToken is null");
            outputError(httpResp, AUTH_FAILURE, "Error: not authenticated",
                        null);
        }

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "modify");
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
        String nickname = "";

        // get nickname
        try {
            nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token"))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
        }

        CMS.debug("UpdateOCSPConfig process: nickname=" + nickname);

        String ocsphost = httpReq.getParameter("ocsp_host");
        String ocspport = httpReq.getParameter("ocsp_port");
        String ocspname = ocsphost.replace('.', '-')+"-"+ocspport;
        String publisherPrefix = "ca.publish.publisher.instance.OCSPPublisher-"+ocspname;
        String rulePrefix = "ca.publish.rule.instance.ocsprule-"+ocspname;
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
            // insert info
            CMS.debug("UpdateOCSPConfig: Sending response");

            // send success status back to the requestor
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("UpdateOCSPConfig: Failed to update OCSP configuration. Exception: " + e.toString());
            outputError(httpResp, "Error: Failed to update OCSP configuration.");
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
