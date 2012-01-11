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

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.xml.XMLObject;

public class GetDomainXML extends CMSServlet {

    /**
     *
     */
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
     * 
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("GetDomainXML: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        ServletContext context = cmsReq.getServletContext();

        String status = SUCCESS;
        String basedn = null;
        String secstore = null;

        IConfigStore cs = CMS.getConfigStore();
        try {
            secstore = cs.getString("securitydomain.store");
            basedn = cs.getString("internaldb.basedn");
        } catch (Exception e) {
            CMS.debug("Unable to determine the security domain name or internal basedn. Please run the domaininfo migration script");
        }

        try {
            XMLObject response = new XMLObject();
            Node root = response.createRoot("XMLResponse");

            if ((secstore != null) && (basedn != null) && (secstore.equals("ldap"))) {
                ILdapConnFactory connFactory = null;
                LDAPConnection conn = null;
                try {
                    // get data from ldap
                    String[] entries = {};
                    String filter = "objectclass=pkiSecurityGroup";
                    LDAPSearchConstraints cons = null;
                    String[] attrs = null;
                    String dn = "ou=Security Domain," + basedn;

                    IConfigStore ldapConfig = cs.getSubStore("internaldb");
                    connFactory = CMS.getLdapBoundConnFactory();
                    connFactory.init(ldapConfig);
                    conn = connFactory.getConn();

                    // get the security domain name 
                    String secdomain = (String) conn.read(dn).getAttribute("name").getStringValues().nextElement();

                    XMLObject xmlObj = new XMLObject();
                    Node domainInfo = xmlObj.createRoot("DomainInfo");
                    xmlObj.addItemToContainer(domainInfo, "Name", secdomain);

                    // this should return CAList, KRAList etc. 
                    LDAPSearchResults res = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
                            attrs, true, cons);

                    while (res.hasMoreElements()) {
                        int count = 0;
                        dn = res.next().getDN();
                        String listName = dn.substring(3, dn.indexOf(","));
                        String subType = listName.substring(0, listName.indexOf("List"));
                        Node listNode = xmlObj.createContainer(domainInfo, listName);

                        filter = "objectclass=pkiSubsystem";
                        LDAPSearchResults res2 = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
                                attrs, false, cons);
                        while (res2.hasMoreElements()) {
                            Node node = xmlObj.createContainer(listNode, subType);
                            LDAPEntry entry = res2.next();
                            LDAPAttributeSet entryAttrs = entry.getAttributeSet();
                            Enumeration attrsInSet = entryAttrs.getAttributes();
                            while (attrsInSet.hasMoreElements()) {
                                LDAPAttribute nextAttr = (LDAPAttribute) attrsInSet.nextElement();
                                String attrName = nextAttr.getName();
                                if ((!attrName.equals("cn")) && (!attrName.equals("objectClass"))) {
                                    String attrValue = (String) nextAttr.getStringValues().nextElement();
                                    xmlObj.addItemToContainer(node, securityDomainLDAPtoXML(attrName), attrValue);
                                }
                            }
                            count++;
                        }
                        xmlObj.addItemToContainer(listNode, "SubsystemCount", Integer.toString(count));
                    }

                    // Add new xml object as string to response.
                    response.addItemToContainer(root, "DomainInfo", xmlObj.toXMLString());
                } catch (Exception e) {
                    CMS.debug("GetDomainXML: Failed to read domain.xml from ldap " + e.toString());
                    status = FAILED;
                } finally {
                    if ((conn != null) && (connFactory != null)) {
                        CMS.debug("Releasing ldap connection");
                        connFactory.returnConn(conn);
                    }
                }
            } else {
                // get data from file store

                String path = CMS.getConfigStore().getString("instanceRoot", "")
                        + "/conf/domain.xml";

                CMS.debug("GetDomainXML: got path=" + path);

                try {
                    CMS.debug("GetDomainXML: Reading domain.xml from file ...");
                    FileInputStream fis = new FileInputStream(path);
                    int s = fis.available();

                    CMS.debug("GetDomainXML: size " + s);
                    byte buf[] = new byte[s];

                    fis.read(buf, 0, s);
                    fis.close();
                    CMS.debug("GetDomainXML: Done Reading domain.xml...");

                    response.addItemToContainer(root, "DomainInfo", new String(buf));
                } catch (Exception e) {
                    CMS.debug("Failed to read domain.xml from file" + e.toString());
                    status = FAILED;
                }
            }

            response.addItemToContainer(root, "Status", status);
            byte[] cb = response.toByteArray();
            outputResult(httpResp, "application/xml", cb);

        } catch (Exception e) {
            CMS.debug("GetDomainXML: Failed to send the XML output" + e.toString());
        }
    }

    protected String securityDomainLDAPtoXML(String attribute) {
        if (attribute.equals("host"))
            return "Host";
        else
            return attribute;
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
