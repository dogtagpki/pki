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
package com.netscape.cms.servlet.base;

import java.io.IOException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * Return some javascript to the request which contains the list of
 * dynamic data in the CMS system.
 * <p>
 * This allows the requestor (browser) to make decisions about what to present in the UI, depending on how CMS is
 * configured
 *
 * @version $Revision$, $Date$
 */
public class DynamicVariablesServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 7246774978153039460L;
    public final static String PROP_ACCESS = "ServletAccess";
    public final static String PROP_AUTHMGR = "AuthMgr";
    public final static String PROP_CLIENTAUTH = "GetClientCert";

    public final static String PROP_AUTHORITY = "authority";
    public final static String PROP_CLONING = "cloning";

    private final static String INFO = "dynamicVariables";

    private static final String PROP_DYNVAR = "dynamicVariables";
    private static final String PROP_CRLURL = "cloneMasterCrlUrl";
    private static final String VAR_SERVERDATE_STRING = "serverdate()";
    private static final Integer VAR_SERVERDATE = Integer.valueOf(1);

    private static final String VAR_SUBSYSTEMNAME_STRING = "subsystemname()";
    private static final Integer VAR_SUBSYSTEMNAME = Integer.valueOf(2);
    private String VAR_SUBSYSTEMNAME_VALUE = null;

    private static final String VAR_HTTP_STRING = "http()";
    private static final Integer VAR_HTTP = Integer.valueOf(3);

    private static final String VAR_AUTHMGRS_STRING = "authmgrs()";
    private static final Integer VAR_AUTHMGRS = Integer.valueOf(4);

    private static final String VAR_CLA_CRL_URL_STRING = "clacrlurl()";
    private static final Integer VAR_CLA_CRL_URL = Integer.valueOf(6);

    private String mAuthMgrCacheString = "";
    private long mAuthMgrCacheTime = 0;
    private final int AUTHMGRCACHE = 10; //number of seconds to cache list of
    // authmanagers for
    private Hashtable<Integer, String> dynvars = null;
    @SuppressWarnings("unused")
    private String mGetClientCert = "false";
    private String mAuthMgr = null;

    @SuppressWarnings("unused")
    private ServletConfig mServletCfg;
    private ServletContext mServletCtx = null;
    private static String mCrlurl = "";
    static {
        IConfigStore config = CMS.getConfigStore().getSubStore(PROP_CLONING);

        try {
            mCrlurl =
                    config.getString(PROP_CRLURL, "");
        } catch (EBaseException e) {
        }
    }

    public DynamicVariablesServlet() {
        super();
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Reads the following variables from the servlet config:
     * <ul>
     * <li><strong>AuthMgr</strong> - the authentication manager to use to authenticate the request
     * <li><strong>GetClientCert</strong> - whether to request client auth for this request
     * <li><strong>authority</strong> - the authority (ca, ra, drm) to return to the client
     * <li><strong>dynamicVariables</strong> - a string of the form:
     * serverdate=serverdate(),subsystemname=subsystemname(), http=http(),authmgrs=authmgrs(),clacrlurl=clacrlurl()
     * </ul>
     * The dynamicVariables string is parsed by splitting on commas.
     * When services, the HTTP request provides a piece of javascript
     * code as follows.
     * <p>
     * Each sub expression "lhs=rhs()" forms a javascript statement of the form <i>lhs=xxx;</i> Where lhs is xxx is the
     * result of 'evaluating' the rhs. The possible values for the rhs() function are:
     * <ul>
     * <li><strong>serverdate()</strong> - the timestamp of the server (used to ensure that the client clock is set
     * correctly)
     * <li><strong>subsystemname()</strong>
     * <li><strong>http()</strong> - "true" or "false" - is this an http connection (as opposed to https)
     * <li>authmgrs() - a comma separated list of authentication managers
     * <li>clacrlurl() - the URL to get the CRL from, in the case of a Clone CA. This is defined in the CMS
     * configuration parameter 'cloning.cloneMasterCrlUrl'
     * </ul>
     *
     * @see javax.servlet.Servlet#init(ServletConfig)
     */

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mAuthMgr = sc.getInitParameter(PROP_AUTHMGR);
        mGetClientCert = sc.getInitParameter(PROP_CLIENTAUTH);
        mServletCfg = sc;

        mServletCtx = sc.getServletContext();

        VAR_SUBSYSTEMNAME_VALUE = sc.getInitParameter(PROP_AUTHORITY);

        try {
            String dynvarconfig = sc.getInitParameter(PROP_DYNVAR);
            StringTokenizer s = new StringTokenizer(dynvarconfig, ",");

            dynvars = new Hashtable<Integer, String>();

            while (s.hasMoreTokens()) {
                String token = s.nextToken();

                int i = token.indexOf('=');
                String varname = token.substring(0, i);
                String varvalue = token.substring(i + 1);

                Integer varcode = null;

                if (varvalue.equalsIgnoreCase(VAR_SERVERDATE_STRING)) {
                    varcode = VAR_SERVERDATE;
                } else if (varvalue.equalsIgnoreCase(VAR_SUBSYSTEMNAME_STRING)) {
                    varcode = VAR_SUBSYSTEMNAME;
                } else if (varvalue.equalsIgnoreCase(VAR_HTTP_STRING)) {
                    varcode = VAR_HTTP;
                } else if (varvalue.equalsIgnoreCase(VAR_AUTHMGRS_STRING)) {
                    varcode = VAR_AUTHMGRS;
                } else if (varvalue.equalsIgnoreCase(VAR_CLA_CRL_URL_STRING)) {
                    varcode = VAR_CLA_CRL_URL;
                } else {
                    throw new ServletException("bad configuration parameter in " + PROP_DYNVAR);
                }
                if (varcode != null) {
                    dynvars.put(varcode, varname);
                }
            }
        } catch (Exception e) {
            dynvars = null;
        }
    }

    public void service(HttpServletRequest httpReq,
            HttpServletResponse httpResp)
            throws ServletException, IOException {
        boolean running_state = CMS.isInRunningState();

        if (!running_state)
            throw new IOException(
                    "CMS server is not ready to serve.");

        if (mAuthMgr != null) {
            try {
                authenticate(httpReq);
            } catch (EBaseException e) {
                mServletCtx.log(CMS.getLogMessage("CMSGW_FILE_NO_ACCESS", e.toString()));
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        }

        httpResp.setContentType("application/x-javascript");
        httpResp.setHeader("Pragma", "no-cache");

        try {
            ServletOutputStream os = httpResp.getOutputStream();

            if (os != null) {
                if (dynvars != null) {
                    Enumeration<Integer> k = dynvars.keys();

                    while (k.hasMoreElements()) {
                        String toBeWritten;
                        Integer varcode = k.nextElement();

                        if (varcode.equals(VAR_SERVERDATE)) {
                            toBeWritten = dynvars.get(varcode) +
                                    "=" +
                                    getServerDate() +
                                    ";\n";

                            os.print(toBeWritten);
                        }

                        if (varcode.equals(VAR_SUBSYSTEMNAME)) {
                            if (getSubsystemName() != null) {
                                toBeWritten = dynvars.get(varcode) +
                                        "=" + "\"" +
                                        getSubsystemName() + "\"" +
                                        ";\n";
                                os.print(toBeWritten);
                            }
                        }

                        if (varcode.equals(VAR_HTTP)) {
                            if (getHttp(httpReq) != null) {
                                toBeWritten = dynvars.get(varcode) +
                                        "=" + "\"" +
                                        getHttp(httpReq) + "\"" +
                                        ";\n";
                                os.print(toBeWritten);
                            }
                        }

                        if (varcode.equals(VAR_CLA_CRL_URL)) {
                            if (getImportCrlUrl() != null) {
                                toBeWritten = dynvars.get(varcode) +
                                        "=" + "\"" +
                                        getImportCrlUrl() + "\"" +
                                        ";\n";
                                os.print(toBeWritten);
                            }
                        }

                        if (varcode.equals(VAR_AUTHMGRS)) {
                            toBeWritten = "";
                            IAuthSubsystem as = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
                            Enumeration<IAuthManager> ame = as.getAuthManagers();

                            Date d = CMS.getCurrentDate();
                            long now = d.getTime();

                            if (now > (mAuthMgrCacheTime + 1000 * AUTHMGRCACHE)) {
                                int i = 0;

                                StringBuffer sb = new StringBuffer();
                                while (ame.hasMoreElements()) {
                                    IAuthManager am = ame.nextElement();
                                    String amName = am.getImplName();

                                    AuthMgrPlugin ap = as.getAuthManagerPluginImpl(amName);

                                    if (ap.isVisible()) {
                                        sb.append("authmanager[");
                                        sb.append(i);
                                        sb.append("]=\"");
                                        sb.append(amName);
                                        sb.append("\";\n");
                                        i++;
                                    }
                                }
                                toBeWritten = sb.toString();
                                mAuthMgrCacheString = toBeWritten;
                                mAuthMgrCacheTime = now;
                            } else {
                                toBeWritten = mAuthMgrCacheString;
                            }
                            if (toBeWritten.length() != 0) {
                                os.print("authmanager = new Array();\n");
                                os.print(toBeWritten);
                            }
                        }

                    }
                }
                os.close();
            }

        } catch (IOException e) {
            throw new ServletException("couldn't get outputstream");
        }
    }

    private String getServerDate() {
        Date d = new Date();
        String now = Long.toString(d.getTime());

        return now;
    }

    private String getSubsystemName() {
        return VAR_SUBSYSTEMNAME_VALUE;
    }

    private String getHttp(HttpServletRequest httpReq) {
        if (httpReq.isSecure())
            return "false";
        else
            return "true";
    }

    private String getImportCrlUrl() {
        return mCrlurl;
    }
}
