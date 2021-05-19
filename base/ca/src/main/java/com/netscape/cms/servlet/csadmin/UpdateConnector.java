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
import org.jboss.resteasy.spi.BadRequestException;
import org.w3c.dom.Node;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.xml.XMLObject;

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

        IAuthToken authToken = null;
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
        KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(httpReq));
        KRAConnectorInfo info = createConnectorInfo(httpReq);
        try {
            processor.addConnector(info);
        } catch (BadRequestException | PKIException e) {
            status = FAILED;
            error = e.getMessage();
        }

        // send success status back to the requestor
        try {
            logger.debug("UpdateConnector: Sending response");
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            if (status.equals(SUCCESS)) {
                xmlObj.addItemToContainer(root, "Status", SUCCESS);
            } else {
                xmlObj.addItemToContainer(root, "Status", FAILED);
                xmlObj.addItemToContainer(root, "Error", error);
            }

            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            logger.warn("UpdateConnector: Failed to send the XML output: " + e.getMessage(), e);
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
