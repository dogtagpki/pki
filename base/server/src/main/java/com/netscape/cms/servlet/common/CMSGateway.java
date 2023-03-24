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
package com.netscape.cms.servlet.common;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.base.ConfigStore;

/**
 * This class is to hold some general method for servlets.
 */
public class CMSGateway {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSGateway.class);

    public final static String PROP_CMSGATEWAY = "cmsgateway";
    private final static String PROP_ENABLE_ADMIN_ENROLL = "enableAdminEnroll";

    public static final String CERT_ATTR =
            "javax.servlet.request.X509Certificate";

    protected CMSEngine engine;

    protected CMSFileLoader mFileLoader = new CMSFileLoader();

    protected boolean mEnableFileServing;
    protected boolean mEnableAdminEnroll = true;
    protected ConfigStore mConfig;

    public CMSGateway() {
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    public void init() throws Exception {

        EngineConfig cs = engine.getConfig();
        mConfig = cs.getSubStore(PROP_CMSGATEWAY, ConfigStore.class);
        mEnableAdminEnroll = mConfig.getBoolean(PROP_ENABLE_ADMIN_ENROLL, false);

        mEnableFileServing = true;
    }

    public Hashtable<String, String> toHashtable(HttpServletRequest req) {
        Hashtable<String, String> httpReqHash = new Hashtable<>();
        Enumeration<String> names = req.getParameterNames();

        while (names.hasMoreElements()) {
            String name = names.nextElement();

            httpReqHash.put(name, req.getParameter(name));
        }

        String ip = req.getRemoteAddr();
        if (ip != null)
            httpReqHash.put("clientHost", ip);
        return httpReqHash;
    }

    public boolean getEnableAdminEnroll() {
        return mEnableAdminEnroll;
    }

    public void setEnableAdminEnroll(boolean enableAdminEnroll)
            throws EBaseException {

        EngineConfig engineConfig = engine.getConfig();

        //!!! Is it thread safe? xxxx
        mEnableAdminEnroll = enableAdminEnroll;
        mConfig.putBoolean(PROP_ENABLE_ADMIN_ENROLL, enableAdminEnroll);
        engineConfig.commit(true);
    }

    public void disableAdminEnroll() throws EBaseException {
        setEnableAdminEnroll(false);

        /* need to do this in web.xml and restart ws
         removeServlet("/ca/adminEnroll", "AdminEnroll");
         initGateway();
         */
    }

    /**
     * construct a authentication credentials to pass into authentication
     * manager.
     */
    public AuthCredentials getAuthCreds(
            AuthManager authMgr, ArgBlock argBlock, X509Certificate clientCert)
            throws EBaseException {
        // get credentials from http parameters.
        if (authMgr == null)
            return null;
        String[] reqCreds = authMgr.getRequiredCreds();
        AuthCredentials creds = new AuthCredentials();

        try {
            if (clientCert != null) {
                clientCert = new org.mozilla.jss.netscape.security.x509.X509CertImpl(clientCert.getEncoded());
            }
        } catch (CertificateException e) {
            throw new EBaseException("Unable to parse client certificate: " + e.getMessage(), e);
        }

        for (int i = 0; i < reqCreds.length; i++) {
            String reqCred = reqCreds[i];

            if (reqCred.equals(AuthManager.CRED_SSL_CLIENT_CERT)) {
                // cert could be null
                creds.set(reqCred, new X509Certificate[] { clientCert });

            } else {
                String value = argBlock.getValueAsString(reqCred);
                creds.set(reqCred, value); // value could be null
            }
        }

        creds.set("clientHost", argBlock.getValueAsString("clientHost"));
        // Inserted by bskim
        creds.setArgBlock(argBlock);
        // Insert end
        return creds;
    }

    protected final static String AUTHMGR_PARAM = "authenticator";

    public AuthToken checkAuthManager(
            HttpServletRequest httpReq, ArgBlock httpParams,
            X509Certificate cert, String authMgrName)
            throws EBaseException {
        ArgBlock httpArgs = httpParams;

        if (httpArgs == null)
            httpArgs = new ArgBlock(toHashtable(httpReq));

        AuthSubsystem authSub = engine.getAuthSubsystem();

        String authMgr_http = httpArgs.getValueAsString(
                AUTHMGR_PARAM, null);

        if (authMgr_http != null) {
            authMgrName = authMgr_http;
        }

        if (authMgrName == null || authMgrName.length() == 0) {
            throw new EBaseException(CMS.getLogMessage("BASE_INTERNAL_ERROR_1",
                        CMS.getLogMessage("CMSGW_AUTH_MAN_EXPECTED")));
        }

        AuthManager authMgr = authSub.getAuthManager(AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

        authMgr = authSub.getAuthManager(authMgrName);
        if (authMgr == null)
            return null;
        AuthCredentials creds =
                getAuthCreds(authMgr, new ArgBlock(toHashtable(httpReq)), cert);
        AuthToken authToken = null;

        try {
            authToken = authMgr.authenticate(creds);
        } catch (EBaseException e) {
            throw e;
        } catch (Exception e) {
            logger.error("CMSGateway: " + e.getMessage(), e);
            // catch all errors from authentication manager.
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_AUTH_ERROR_2",
                        e.toString(), e.getMessage()));
        }
        return authToken;
    }

    public void renderTemplate(
            String templateName,
            HttpServletRequest req,
            HttpServletResponse resp,
            ServletConfig servletConfig,
            CMSFileLoader fileLoader)
            throws EBaseException, IOException {
        CMSTemplate template =
                getTemplate(templateName, req,
                        servletConfig, fileLoader, new Locale[1]);
        ServletOutputStream out = resp.getOutputStream();

        template.renderOutput(out, new CMSTemplateParams(null, null));
    }

    // XXX TBD move this to a utility function too.

    public Locale getLocale(String lang) {
        int dash = lang.indexOf('-');

        return dash == -1 ? new Locale(lang, "") : new Locale(lang.substring(0, dash), lang.substring(dash + 1));
    }

    /**
     * @param req http servlet request
     * @param realpathFile the file to get.
     * @param locale array of at least one to be filled with locale found.
     */
    public File getLangFile(
            HttpServletRequest req, File realpathFile, Locale[] locale)
            throws IOException {
        File file = null;
        String acceptLang = req.getHeader("accept-language");

        if (acceptLang != null && !acceptLang.equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(acceptLang, ",");
            int numLangs = tokenizer.countTokens();

            if (numLangs > 0) {
                // languages are searched in order.
                String parent = realpathFile.getParent();

                if (parent == null) {
                    parent = "." + File.separatorChar;
                }
                String name = realpathFile.getName();

                if (name == null) { // filename should never be null.
                    throw new IOException("file has no name");
                }
                int i;

                for (i = 0; i < numLangs; i++) {
                    String lang = null;
                    String token = tokenizer.nextToken();

                    int semicolon = token.indexOf(';');

                    if (semicolon == -1) {
                        lang = token.trim();
                    } else {
                        if (semicolon < 2)
                            continue; // protocol error.
                        lang = token.substring(0, semicolon).trim();
                    }
                    // if browser locale is the same as default locale,
                    // use the default form. (is this the right thing to do ?)
                    Locale l = getLocale(lang);

                    if (Locale.getDefault().equals(l)) {
                        locale[0] = l;
                        file = realpathFile;
                        break;
                    }

                    String langfilepath =
                            parent + File.separatorChar +
                                    lang + File.separatorChar + name;

                    file = new File(langfilepath);
                    if (file.exists()) {
                        locale[0] = getLocale(lang);
                        break;
                    }
                }
                // if no file for lang was found use default
                if (i == numLangs) {
                    file = realpathFile;
                    locale[0] = Locale.getDefault();
                }
            }
        } else {
            // use default if accept-language is not availabe
            file = realpathFile;
            locale[0] = Locale.getDefault();
        }
        return file;
    }

    /**
     * get a template
     */
    protected CMSTemplate getTemplate(
            String templateName,
            HttpServletRequest httpReq,
            ServletConfig servletConfig,
            CMSFileLoader fileLoader,
            Locale[] locale)
            throws EBaseException, IOException {
        // this converts to system dependent file seperator char.
        if (servletConfig == null) {
            logger.warn("CMSGateway:getTemplate() - servletConfig is null!");
            return null;
        }
        if (servletConfig.getServletContext() == null) {
        }
        if (templateName == null) {
        }
        String realpath =
                servletConfig.getServletContext().getRealPath("/" + templateName);
        File realpathFile = new File(realpath);
        File templateFile =
                getLangFile(httpReq, realpathFile, locale);
        CMSTemplate template =
                //(CMSTemplate)fileLoader.getCMSFile(templateFile);
                (CMSTemplate) fileLoader.getCMSFile(templateFile, httpReq.getCharacterEncoding());

        return template;
    }

    /**
     * Get the If-Modified-Since header and compare it to the millisecond
     * epoch value passed in. If there is no header, or there is a problem
     * parsing the value, or if the file has been modified this will return
     * true, indicating the file has changed.
     *
     * @param lastModified The time value in milliseconds past the epoch to
     *            compare the If-Modified-Since header to.
     */
    public boolean modifiedSince(HttpServletRequest req, long lastModified) {
        long ifModSinceStr;

        try {
            ifModSinceStr = req.getDateHeader("If-Modified-Since");
        } catch (IllegalArgumentException e) {
            return true;
        }

        if (ifModSinceStr < 0) {
            return true;
        }

        if (ifModSinceStr < lastModified) {
            return true; // Data must be resent
        }

        return false; // Data has not been modified
    }

}
