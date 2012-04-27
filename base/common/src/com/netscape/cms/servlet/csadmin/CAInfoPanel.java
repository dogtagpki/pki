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
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class CAInfoPanel extends WizardPanelBase {

    public CAInfoPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("CA Information");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("CA Information");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.ca.type", "");
    }

    public boolean shouldSkip() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.subsystem.select", "");
            if (s.equals("clone"))
                return true;
        } catch (Exception e) {
        }
        return false;
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.ca.type", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (Exception e) {
        }

        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("CAInfoPanel: display");

        IConfigStore cs = CMS.getConfigStore();
        String hostname = "";
        String httpport = "";
        String httpsport = "";

        if (isPanelDone()) {
            String type = "sdca";

            try {
                type = cs.getString("preop.ca.type");
            } catch (Exception e) {
                CMS.debug("CAInfoPanel exception: " + e.toString());
                return;
            }

            try {
                hostname = cs.getString("preop.ca.hostname");
            } catch (Exception e) {
            }

            try {
                httpport = cs.getString("preop.ca.httpport");
            } catch (Exception e) {
            }

            try {
                httpsport = cs.getString("preop.ca.httpsport");
            } catch (Exception e) {
            }

            if (type.equals("sdca")) {
                context.put("check_sdca", "checked");
                context.put("check_otherca", "");
            } else if (type.equals("otherca")) {
                context.put("check_sdca", "");
                context.put("check_otherca", "checked");
            }
        } else {
            context.put("check_sdca", "checked");
            context.put("check_otherca", "");
        }

        String cstype = "CA";
        String portType = "SecurePort";

        CMS.debug("CAInfoPanel: Ready to get url");
        Vector<String> v = null;
        try {
            v = ConfigurationUtils.getUrlListFromSecurityDomain(cs, cstype, portType);
        } catch (Exception e) {
            CMS.debug("CAInfoPanel display(): errors in getting URL list from security domain" + e);
            e.printStackTrace();
        }
        if (v == null) {
            v = new Vector<String>();
        }

        v.addElement("External CA");
        StringBuffer list = new StringBuffer();
        int size = v.size();

        for (int i = 0; i < size; i++) {
            if (i == size - 1) {
                list.append(v.elementAt(i));
            } else {
                list.append(v.elementAt(i));
                list.append(",");
            }
        }

        try {
            cs.putString("preop.ca.list", list.toString());
            cs.commit(false);
        } catch (Exception e) {
        }

        context.put("urls", v);

        context.put("sdcaHostname", hostname);
        context.put("sdcaHttpPort", httpport);
        context.put("sdcaHttpsPort", httpsport);
        context.put("title", "CA Information");
        context.put("panel", "admin/console/config/cainfopanel.vm");
        context.put("errorString", "");
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
        IConfigStore config = CMS.getConfigStore();

        try {
            String subsystemselect = config.getString("preop.subsystem.select", "");
            if (subsystemselect.equals("clone"))
                return;

            String select = null;
            String index = request.getParameter("urls");
            String url = "";
            if (index.startsWith("http")) {
                // user may submit url directly
                url = index;
            } else {
                int x = Integer.parseInt(index);
                String list = config.getString("preop.ca.list", "");
                StringTokenizer tokenizer = new StringTokenizer(list, ",");
                int counter = 0;

                while (tokenizer.hasMoreTokens()) {
                    url = tokenizer.nextToken();
                    if (counter == x) {
                        break;
                    }
                    counter++;
                }
            }

            URL urlx = null;

            if (url.equals("External CA")) {
                select = "otherca";
                config.putString("preop.ca.pkcs7", "");
                config.putInteger("preop.ca.certchain.size", 0);
            } else {
                select = "sdca";

                // parse URL (CA1 - https://...)
                url = url.substring(url.indexOf("https"));
                urlx = new URL(url);
            }

            ISubsystem subsystem = CMS.getSubsystem(ICertificateAuthority.ID);

            if (select.equals("sdca")) {
                config.putString("preop.ca.type", "sdca");
                CMS.debug("CAInfoPanel update: this is the CA in the security domain.");
                context.put("check_sdca", "checked");
                sdca(request, context, urlx.getHost(),
                        Integer.toString(urlx.getPort()));
                if (subsystem != null) {
                    config.putString(PCERT_PREFIX + "signing.type", "remote");
                    config.putString(PCERT_PREFIX + "signing.profile",
                            "caInstallCACert");
                }
            } else if (select.equals("otherca")) {
                config.putString("preop.ca.type", "otherca");
                context.put("check_otherca", "checked");
                if (subsystem != null) {
                    config.putString(PCERT_PREFIX + "signing.type", "remote");
                }
                CMS.debug("CAInfoPanel update: this is the other CA.");
            }

            config.commit(false);
        } catch (Exception e) {
            CMS.debug("CAInfoPanel update(): Exception thrown " + e);
            e.printStackTrace();
            context.put("updateStatus", "failure");
        }
        context.put("updateStatus", "success");
    }

    private void sdca(HttpServletRequest request, Context context, String hostname, String httpsPortStr)
            throws IOException, CertificateEncodingException, EBaseException {
        CMS.debug("CAInfoPanel update: this is the CA in the security domain.");
        IConfigStore config = CMS.getConfigStore();

        context.put("sdcaHostname", hostname);
        context.put("sdcaHttpsPort", httpsPortStr);

        if (hostname == null || hostname.length() == 0) {
            context.put("errorString", "Hostname is null");
            throw new IOException("Hostname is null");
        }

        int httpsport = -1;
        try {
            httpsport = Integer.parseInt(httpsPortStr);
        } catch (Exception e) {
            CMS.debug("CAInfoPanel update: Https port is not valid. Exception: " + e.toString());
            throw new IOException("Http Port is not valid.");
        }

        config.putString("preop.ca.hostname", hostname);
        config.putString("preop.ca.httpsport", httpsPortStr);
        ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
        updateCertChainUsingSecureEEPort(config, "ca", hostname,
                                          httpsport, true, context,
                                          certApprovalCallback);
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        /* This should never be called */
        context.put("title", "CA Information");
        context.put("panel", "admin/console/config/cainfopanel.vm");
    }
}
