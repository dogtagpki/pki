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
import java.math.*;
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


public class GetDomainXML extends CMSServlet {

    private final static String SUCCESS = "0";
    private final static String FAILED = "1";

    public GetDomainXML() {
        super();
    }

    /**
     * initialize the servlet.
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("GetDomainXML: initializing...");
        super.init(sc);
        CMS.debug("GetDomainXML: done initializing...");
    }

    /**
     * Process the HTTP request. 
     * <ul>
     * <li>http.param op 'downloadBIN' - return the binary certificate chain
     * <li>http.param op 'displayIND' - display pretty-print of certificate chain components
     * </ul>
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("GetDomainXML: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        String outputString = null;

        String path = CMS.getConfigStore().getString("instanceRoot", "")
                + "/conf/domain.xml";

        CMS.debug("GetDomainXML: got path=" + path);

        try {
            CMS.debug("GetDomainXML: Reading domain.xml...");
            FileInputStream fis = new FileInputStream(path);
            int s = fis.available();

            CMS.debug("GetDomainXML: size " + s);
            byte buf[] = new byte[s];

            fis.read(buf, 0, s);
            fis.close();
            CMS.debug("GetDomainXML: Done Reading domain.xml...");

            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            xmlObj.addItemToContainer(root, "DomainInfo", new String(buf));
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("GetDomainXML: Failed to send the XML output");
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
