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

import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.util.Utils;
import org.w3c.dom.Node;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This servlet imports DRM's transport certificate into TKS.
 */
public class ImportTransportCert extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ImportTransportCert.class);

    private static final long serialVersionUID = 7490067757951541235L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

    public ImportTransportCert() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        logger.debug("ImportTransportCert: initializing...");
        super.init(sc);
        logger.debug("ImportTransportCert: done initializing...");
    }

    /**
     * Process the HTTP request.
     */
    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {
        logger.debug("UpdateUpdater: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        TKSEngine engine = TKSEngine.getInstance();
        TKSEngineConfig cs = engine.getConfig();

        IAuthToken authToken = null;
        try {
            authToken = authenticate(cmsReq);
            logger.debug("ImportTransportCert authentication successful.");
        } catch (Exception e) {
            logger.error("ImportTransportCert: authentication failed: " + e.getMessage(), e);
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated", null);
            return;
        }

        if (authToken == null) {
            logger.error("ImportTransportCert: authentication failed.");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        AuthzToken authzToken = null;
        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "modify");
            logger.debug("ImportTransportCert authorization successful.");
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

        String certsString = httpReq.getParameter("certificate");

        try {
            CryptoManager cm = CryptoManager.getInstance();
            logger.debug("ImportTransportCert: Importing certificate");
            org.mozilla.jss.crypto.X509Certificate cert =
                    cm.importCACertPackage(Utils.base64decode(certsString));
            String nickName = cert.getNickname();
            logger.debug("ImportTransportCert: nickname " + nickName);
            cs.putString("tks.drm_transport_cert_nickname", nickName);
            logger.debug("ImportTransportCert: Commiting configuration");
            cs.commit(false);

            // send success status back to the requestor
            logger.debug("ImportTransportCert: Sending response");
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            logger.warn("ImportTransportCert: Failed to send the XML output " + e.getMessage(), e);
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
