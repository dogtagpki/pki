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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.wizard.IWizardPanel;
import com.netscape.cms.servlet.wizard.WizardServlet;
import com.netscape.cmsutil.xml.XMLObject;

public class WizardPanelBase implements IWizardPanel {
    public static String PCERT_PREFIX = "preop.cert.";
    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";

    /**
     * Definition for static variables in CS.cfg
     */
    public static final String CONF_CA_CERT = "ca.signing.cert";
    public static final String CONF_CA_CERTREQ = "ca.signing.certreq";
    public static final String CONF_CA_CERTNICKNAME = "ca.signing.certnickname";

    public static final String PRE_CONF_ADMIN_NAME = "preop.admin.name";
    public static final String PRE_CONF_AGENT_GROUP = "preop.admin.group";

    /**
     * Definition for "preop" static variables in CS.cfg
     * -- "preop" config parameters should not assumed to exist after configuation
     */

    public static final String PRE_CONF_CA_TOKEN = "preop.module.token";
    public static final String PRE_CA_TYPE = "preop.ca.type";
    public static final String PRE_OTHER_CA = "otherca";
    public static final String PRE_ROOT_CA = "rootca";

    private String mName = null;
    private int mPanelNo = 0;
    private String mId = null;

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        mPanelNo = panelno;
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        mPanelNo = panelno;
    }

    /**
     * Cleans up this panel so that isPanelDone() will return false.
     */
    public void cleanUp() throws IOException {
    }

    public String getName() {
        return mName;
    }

    public int getPanelNo() {
        return mPanelNo;
    }

    public void setPanelNo(int num) {
        mPanelNo = num;
    }

    public void setName(String name) {
        mName = name;
    }

    public void setId(String id) {
        mId = id;
    }

    public String getId() {
        return mId;
    }

    public PropertySet getUsage() {
        PropertySet set = null;

        return set;
    }

    /**
     * Should we skip this panel?
     */
    public boolean shouldSkip() {
        return false;
    }

    /**
     * Is this panel done
     */
    public boolean isPanelDone() {
        return false;
    }

    /**
     * Show "Apply" button on frame?
     */
    public boolean showApplyButton() {
        return false;
    }

    /**
     * Is this a subPanel?
     */
    public boolean isSubPanel() {
        return false;
    }

    public boolean isLoopbackPanel() {
        return false;
    }

    /**
     * has subPanels?
     */
    public boolean hasSubPanel() {
        return false;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }

    /**
     * Retrieves locale based on the request.
     */
    public Locale getLocale(HttpServletRequest req) {
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

    public boolean authenticate(String hostname, int port, boolean https,
            String servlet, String uri) throws IOException {
        CMS.debug("WizardPanelBase authenticate start");
        String c = ConfigurationUtils.getHttpResponse(hostname, port, https, servlet, uri, null);
        IConfigStore cs = CMS.getConfigStore();

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug("WizardPanelBase::authenticate() - "
                             + "Exception=" + e.toString());
                    throw new IOException(e.toString());
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase authenticate: status=" + status);

                if (status.equals(SUCCESS)) {
                    String cookie = parser.getValue("Cookie");
                    cs.putString("preop.cookie", cookie);
                    return true;
                } else {
                    return false;
                }
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: authenticate: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return false;
    }

    public String pingCS(String hostname, int port, boolean https,
                          SSLCertificateApprovalCallback certApprovalCallback)
            throws IOException {
        CMS.debug("WizardPanelBase pingCS: started");

        String c = ConfigurationUtils.getHttpResponse(hostname, port, https,
                                    "/ca/admin/ca/getStatus",
                                    null, null, certApprovalCallback);

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;
                String state = null;

                try {
                    parser = new XMLObject(bis);
                    CMS.debug("WizardPanelBase pingCS: got XML parsed");
                    state = parser.getValue("State");

                    if (state != null) {
                        CMS.debug("WizardPanelBase pingCS: state=" + state);
                    }
                } catch (Exception e) {
                    CMS.debug("WizardPanelBase: pingCS: parser failed"
                             + e.toString());
                }

                return state;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: pingCS: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        CMS.debug("WizardPanelBase pingCS: stopped");
        return null;
    }

    public void reloginSecurityDomain(HttpServletResponse response) {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String hostname = cs.getString("securitydomain.host", "");
            int port = cs.getInteger("securitydomain.httpsadminport", -1);
            String cs_hostname = cs.getString("machineName", "");
            int cs_port = cs.getInteger("pkicreate.admin_secure_port", -1);
            int panel = getPanelNo();
            String subsystem = cs.getString("cs.type", "");
            String urlVal =
                    "https://"
                            + cs_hostname + ":" + cs_port + "/" + subsystem.toLowerCase()
                            + "/admin/console/config/wizard?p=" + panel + "&subsystem=" + subsystem;
            String encodedValue = URLEncoder.encode(urlVal, "UTF-8");
            String sdurl = "https://" + hostname + ":" + port + "/ca/admin/ca/securityDomainLogin?url=" + encodedValue;
            response.sendRedirect(sdurl);
        } catch (Exception e) {
            CMS.debug("WizardPanelBase reloginSecurityDomain: Exception=" + e.toString());
        }
    }
}
