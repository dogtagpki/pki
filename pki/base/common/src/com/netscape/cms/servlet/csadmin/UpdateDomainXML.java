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


public class UpdateDomainXML extends CMSServlet {

    private final static String SUCCESS = "0";
    private final static String FAILED = "1";

    public UpdateDomainXML() {
        super();
    }

    /**
     * initialize the servlet.
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("UpdateDomainXML: initializing...");
        super.init(sc);
        CMS.debug("UpdateDomainXML: done initializing...");
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
        CMS.debug("UpdateDomainXML: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMS.debug("UpdateDomainXML process: authentication starts");
        IAuthToken authToken = authenticate(cmsReq);
        if (authToken == null) {
            CMS.debug("UpdateDomainXML process: authToken is null");
            outputError(httpResp, "Error: not authenticated");
        }
        CMS.debug("UpdateDomainXML process: authentication done");

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
            CMS.debug("UpdateDomainXML process: authorization error");
            outputError(httpResp, "Error: Not authorized");
            return;
        }

        String path = CMS.getConfigStore().getString("instanceRoot", "")
                + "/conf/domain.xml";

        CMS.debug("UpdateDomainXML: got path=" + path);

        try {
            // set info into domain.xml
            String list = httpReq.getParameter("list");

            String type = httpReq.getParameter("type");
            String host = httpReq.getParameter("host");
            String name = httpReq.getParameter("name");
            String sport = httpReq.getParameter("sport");
            String domainmgr = httpReq.getParameter("dm");
            String clone = httpReq.getParameter("clone");

            // insert info
            CMS.debug("UpdateDomainXML: Inserting new domain info");
            XMLObject parser = new XMLObject(new FileInputStream(path));
            Node n = parser.getContainer(list);
            Node parent = parser.createContainer(n, type);
            parser.addItemToContainer(parent, "SubsystemName", name);
            parser.addItemToContainer(parent, "Host", host);
            parser.addItemToContainer(parent, "SecurePort", sport);
            parser.addItemToContainer(parent, "DomainManager", domainmgr);
            parser.addItemToContainer(parent, "Clone", clone);

            String countS = "";
            NodeList nlist = n.getChildNodes();
            Node countnode = null;
            for (int i=0; i<nlist.getLength(); i++) {
                Element nn = (Element)nlist.item(i);
                String tagname = nn.getTagName();
                if (tagname.equals("SubsystemCount")) {
                    countnode = nn;
                    NodeList nlist1 = nn.getChildNodes();
                    Node nn1 = nlist1.item(0);
                    countS  = nn1.getNodeValue();
                    break;
                }
            }

            CMS.debug("UpdateDomainXML process: SubsystemCount="+countS);
            int count = 0;
            try {
                count = Integer.parseInt(countS);
                count++;
            } catch (Exception ee) {
            }

            Node nn2 = n.removeChild(countnode);
            parser.addItemToContainer(n, "SubsystemCount", ""+count);

            // recreate domain.xml
            CMS.debug("UpdateDomainXML: Recreating domain.xml");
            byte[] b = parser.toByteArray();
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(b);
            fos.close();

            // send success status back to the requestor
            CMS.debug("UpdateDomainXML: Sending response");
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("UpdateDomainXML: Failed to send the XML output");
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
