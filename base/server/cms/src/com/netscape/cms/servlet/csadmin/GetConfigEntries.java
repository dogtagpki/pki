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
import java.net.InetAddress;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

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
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.xml.XMLObject;

public class GetConfigEntries extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -7418561215631752315L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

    public GetConfigEntries() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        CMS.debug("GetConfigEntries init");
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
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        IAuthToken authToken = null;

        try {
            authToken = authenticate(cmsReq);
        } catch (Exception e) {
            CMS.debug("GetConfigEntries authentication failed");
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "",
                            e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        // Construct an ArgBlock
        IArgBlock args = cmsReq.getHttpParams();

        // Get the operation code
        String op = null;

        op = args.getValueAsString("op", null);
        CMS.debug("GetConfigEntries process: op=" + op);

        XMLObject xmlObj = null;
        try {
            xmlObj = new XMLObject();
        } catch (Exception e) {
            CMS.debug("GetConfigEntries process: Exception: " + e.toString());
            throw new EBaseException(e.toString());
        }

        Node root = xmlObj.createRoot("XMLResponse");
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "read");
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

        if (op != null) {
            IConfigStore config = CMS.getConfigStore();
            String substores = args.getValueAsString("substores", "");
            StringTokenizer t = new StringTokenizer(substores, ",");
            while (t.hasMoreTokens()) {
                String name1 = t.nextToken();
                IConfigStore cs = config.getSubStore(name1);
                Enumeration<String> enum1 = cs.getPropertyNames();

                while (enum1.hasMoreElements()) {
                    String name = name1 + "." + enum1.nextElement();
                    try {
                        String value = config.getString(name);
                        if (value.equals("localhost")) {
                            value = config.getString("machineName", InetAddress.getLocalHost().getHostName());
                        }
                        Node container = xmlObj.createContainer(root, "Config");
                        xmlObj.addItemToContainer(container, "name", name);
                        xmlObj.addItemToContainer(container, "value", value);
                    } catch (Exception ee) {
                        continue;
                    }
                }
            }

            String names = args.getValueAsString("names", "");
            StringTokenizer t1 = new StringTokenizer(names, ",");
            while (t1.hasMoreTokens()) {
                String name = t1.nextToken();
                String value = "";

                try {
                    CMS.debug("Retrieving config name=" + name);
                    value = config.getString(name);
                    CMS.debug("Retrieving config value=" + value);
                    if (value.equals("localhost"))
                        value = config.getString("machineName", InetAddress.getLocalHost().getHostName());
                } catch (Exception ee) {
                    if (name.equals("internaldb.ldapauth.password")) {
                        value = getLDAPPassword();
                    } else if (name.equals("internaldb.replication.password")) {
                        value = getReplicationPassword();
                    } else
                        continue;
                }

                Node container = xmlObj.createContainer(root, "Config");
                xmlObj.addItemToContainer(container, "name", name);
                xmlObj.addItemToContainer(container, "value", value);
            }
        }

        try {
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("Failed to send the XML output");
        }
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

    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    private String getLDAPPassword() {
        IPasswordStore pwdStore = CMS.getPasswordStore();
        return pwdStore.getPassword("internaldb");
    }

    private String getReplicationPassword() {
        IPasswordStore pwdStore = CMS.getPasswordStore();
        return pwdStore.getPassword("replicationdb");
    }

}
