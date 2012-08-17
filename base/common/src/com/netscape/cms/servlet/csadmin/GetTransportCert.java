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
import java.security.cert.CertificateEncodingException;
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
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This servlet retrieves the transport certificate from DRM.
 */
public class GetTransportCert extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 2495152202191979339L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

    public GetTransportCert() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("GetTransportCert: initializing...");
        super.init(sc);
        CMS.debug("GetTransportCert: done initializing...");
    }

    /**
     * Process the HTTP request.
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("UpdateUpdater: processing...");

        HttpServletResponse httpResp = cmsReq.getHttpResp();

        IAuthToken authToken = null;
        try {
            authToken = authenticate(cmsReq);
            CMS.debug("GetTransportCert authentication successful.");
        } catch (Exception e) {
            CMS.debug("GetTransportCert: authentication failed.");
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "",
                            e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        if (authToken == null) {
            CMS.debug("GetTransportCert: authentication failed.");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        AuthzToken authzToken = null;
        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "read");
            CMS.debug("GetTransportCert authorization successful.");
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

        IKeyRecoveryAuthority kra =
                (IKeyRecoveryAuthority) mAuthority;
        ITransportKeyUnit tu = kra.getTransportKeyUnit();
        org.mozilla.jss.crypto.X509Certificate transportCert =
                tu.getCertificate();

        String mime64 = "";
        try {
            mime64 = CMS.BtoA(transportCert.getEncoded());
            mime64 = com.netscape.cmsutil.util.Cert.normalizeCertStrAndReq(mime64);
        } catch (CertificateEncodingException eee) {
            CMS.debug("GetTransportCert: Failed to encode certificate");
        }

        // send success status back to the requestor
        try {
            CMS.debug("GetTransportCert: Sending response " + mime64);
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            xmlObj.addItemToContainer(root, "TransportCert", mime64);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("GetTransportCert: Failed to send the XML output " + e);
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
