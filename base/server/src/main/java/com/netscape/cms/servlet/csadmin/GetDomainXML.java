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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.xml.XMLObject;

public class GetDomainXML extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetDomainXML.class);

    private static final long serialVersionUID = 3079546345000720649L;
    private final static String SUCCESS = "0";
    private final static String FAILED = "1";

    public GetDomainXML() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        logger.debug("GetDomainXML: initializing...");
        super.init(sc);
        logger.debug("GetDomainXML: done initializing...");
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param op 'downloadBIN' - return the binary certificate chain
     * <li>http.param op 'displayIND' - display pretty-print of certificate chain components
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {
        logger.debug("GetDomainXML: processing...");

        HttpServletResponse httpResp = cmsReq.getHttpResp();

        String status = SUCCESS;

        try {
            XMLObject response = new XMLObject();
            Node root = response.createRoot("XMLResponse");

            try {
                SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(cmsReq.getHttpReq()));
                XMLObject xmlObj = processor.getDomainXML();

                // Add new xml object as string to response.
                response.addItemToContainer(root, "DomainInfo", xmlObj.toXMLString());

            } catch (Exception e) {
                logger.warn("Failed to read domain.xml: " + e.getMessage(), e);
                status = FAILED;
            }

            response.addItemToContainer(root, "Status", status);
            byte[] cb = response.toByteArray();
            outputResult(httpResp, "application/xml", cb);

        } catch (Exception e) {
            logger.warn("GetDomainXML: Failed to send the XML output" + e.getMessage(), e);
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
