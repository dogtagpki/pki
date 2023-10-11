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
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.util.cert.CertUtil;
import org.w3c.dom.Node;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.xml.XMLObject;

public class GetConfigEntries extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetConfigEntries.class);

    private static final long serialVersionUID = -7418561215631752315L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

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

        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMSEngine engine = getCMSEngine();
        AuthToken authToken = null;

        logger.info("GetConfigEntries: Authenticating request");

        try {
            authToken = authenticate(cmsReq);
        } catch (Exception e) {
            logger.error("GetConfigEntries: Authentication failed: " + e.getMessage(), e);
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()));
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated", null);
            return;
        }

        ArgBlock args = cmsReq.getHttpParams();
        String op = args.getValueAsString("op", null);
        logger.info("GetConfigEntries: Operation: " + op);

        XMLObject xmlObj = null;
        try {
            xmlObj = new XMLObject();
        } catch (Exception e) {
            String message = "Unable to create XMLObject: " + e.getMessage();
            logger.error(message, e);
            throw new EBaseException(message, e);
        }

        Node root = xmlObj.createRoot("XMLResponse");

        logger.info("GetConfigEntries: Authorizing request");
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "read");
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

        if (op != null) {

            logger.info("GetConfigEntries: Processing substores");

            EngineConfig config = engine.getConfig();
            String substores = args.getValueAsString("substores", "");
            StringTokenizer t = new StringTokenizer(substores, ",");

            while (t.hasMoreTokens()) {
                String name1 = t.nextToken();
                ConfigStore cs = config.getSubStore(name1, ConfigStore.class);
                Enumeration<String> enum1 = cs.getPropertyNames();

                while (enum1.hasMoreElements()) {
                    String name = name1 + "." + enum1.nextElement();
                    logger.info("- " + name);

                    String value = config.getString(name, null);
                    if ("localhost".equals(value)) {
                        value = config.getHostname();
                    }

                    Node container = xmlObj.createContainer(root, "Config");
                    xmlObj.addItemToContainer(container, "name", name);
                    xmlObj.addItemToContainer(container, "value", value);
                }
            }

            logger.info("GetConfigEntries: Processing names");

            String names = args.getValueAsString("names", "");
            StringTokenizer t1 = new StringTokenizer(names, ",");

            while (t1.hasMoreTokens()) {
                String name = t1.nextToken();
                logger.info("- " + name);

                String value;
                if (name.equals("internaldb.ldapauth.password")) {
                    value = getLDAPPassword();

                } else if (name.equals("internaldb.replication.password")) {
                    value = getReplicationPassword();

                } else if (name.endsWith(".certreq")) {
                    value = getCSR(name);
                } else {
                    value = config.getString(name, null);
                    if ("localhost".equals(value))
                        value = config.getHostname();
                }

                if (value != null) {
                    Node container = xmlObj.createContainer(root, "Config");
                    xmlObj.addItemToContainer(container, "name", name);
                    xmlObj.addItemToContainer(container, "value", value);
                }
            }
        }

        try {
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);

        } catch (Exception e) {
            logger.warn("Failed to send the XML output: " + e.getMessage(), e);
        }
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

    @Override
    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    private String getLDAPPassword() throws EBaseException {
        CMSEngine engine = getCMSEngine();
        PasswordStore pwdStore = engine.getPasswordStore();
        return pwdStore.getPassword("internaldb", 0);
    }

    private String getReplicationPassword() throws EBaseException {
        CMSEngine engine = getCMSEngine();
        PasswordStore pwdStore = engine.getPasswordStore();
        return pwdStore.getPassword("replicationdb", 0);
    }

    /**
     * @author Marco Fargetta
     * @deprecated <subsystem_name>.<cert_id>,certreq configuration properties will be removed in future versions..
     */
    @Deprecated (since = "11.5.0")
    private String getCSR(String param) throws EBaseException {
        CMSEngine engine = getCMSEngine();
        EngineConfig config = engine.getConfig();
        String csr = null;

        String nickname = config.getString(param.replace(".certreq", ".nickname"), null);
        if (nickname == null || nickname.isEmpty()) {
            return null;
        }
        Path csrConfCertsPath = FileSystems.getDefault().getPath(CMS.getInstanceDir(), "conf", "certs", nickname + ".csr");
        try {
            csr = Files.readString(csrConfCertsPath);
        } catch (IOException e) {
            logger.warn("GetConfigEntries: impossible to access the csr file" + csrConfCertsPath, e);
            return null;
        }
        return CertUtil.unwrapPKCS10(csr, true);
    }
}
