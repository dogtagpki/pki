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
import java.net.URLEncoder;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.util.CertPrettyPrint;
import netscape.security.x509.X509CertImpl;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.cms.servlet.wizard.WizardServlet;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class DisplayCertChainPanel extends WizardPanelBase {

    public DisplayCertChainPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Display Certificate Chain");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Display Certificate Chain");
        setId(id);
    }

    public boolean isSubPanel() {
        return true;
    }

    public boolean isPanelDone() {
        return true;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        return set;
    }

    public void cleanUp() throws IOException {
    }

    /**
     * Should we skip this panel for the configuration.
     */
    public boolean shouldSkip() {
        CMS.debug("DisplayCertChainPanel: should skip");

        IConfigStore cs = CMS.getConfigStore();
        // if we are root, no need to get the certificate chain.

        try {
            String select = cs.getString("securitydomain.select", "");
            String type = cs.getString("preop.subsystem.select", "");
            String hierarchy = cs.getString("preop.hierarchy.select", "");

            if (getId().equals("hierarchy") && hierarchy.equals("root"))
                return true;

            if (select.equals("new")) {
                return true;
            }

            if (type.equals("new") && getId().equals("clone"))
                return true;

            if (type.equals("clone") && getId().equals("ca"))
                return true;
        } catch (EBaseException e) {
        }

        return false;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        try {
            CMS.debug("DisplayCertChainPanel: display");

            // update session id
            String session_id = request.getParameter("session_id");
            if (session_id != null) {
                CMS.debug("DisplayCertChainPanel setting session id.");
                CMS.setConfigSDSessionId(session_id);
            }

            String type = getId();
            IConfigStore cs = CMS.getConfigStore();
            String certChainConfigName = "preop." + type + ".certchain.size";
            String certchain_size = cs.getString(certChainConfigName, "");
            int size = 0;
            Vector<String> v = new Vector<String>();

            if (!certchain_size.equals("")) {
                size = Integer.parseInt(certchain_size);
                for (int i = 0; i < size; i++) {
                    certChainConfigName = "preop." + type + ".certchain." + i;
                    String c = cs.getString(certChainConfigName, "");
                    byte[] b_c = CryptoUtil.base64Decode(c);
                    CertPrettyPrint pp = new CertPrettyPrint(new X509CertImpl(b_c));

                    v.addElement(pp.toString(Locale.getDefault()));
                }
            }

            if (getId().equals("securitydomain")) {
                context.put("panelid", "securitydomain");
                context.put("panelname", "Security Domain Trust Verification");
            } else {
                context.put("panelid", "other");
                context.put("panelname", "Subsystem Trust Verification");
            }
            context.put("title", "Display Certificate Chain");
            context.put("panel", "admin/console/config/displaycertchainpanel.vm");
            context.put("errorString", "");
            context.put("certchain", v);
        } catch (Exception e) {
            CMS.debug("DisplayCertPanel: Exception thrown: " + e.toString());
            e.printStackTrace();
            context.put("errorString", e.toString());
        }
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

        if (getId().equals("securitydomain")) {
            int panel = getPanelNo() + 1;
            IConfigStore cs = CMS.getConfigStore();
            try {
                String sd_hostname = cs.getString("securitydomain.host", "");
                int sd_port = cs.getInteger("securitydomain.httpsadminport", -1);
                String cs_hostname = cs.getString("machineName", "");
                int cs_port = cs.getInteger("pkicreate.admin_secure_port", -1);
                String subsystem = cs.getString("cs.type", "");
                String urlVal = "https://" + cs_hostname + ":" + cs_port + "/" + subsystem.toLowerCase()
                        + "/admin/console/config/wizard?p=" + panel + "&subsystem=" + subsystem;
                String encodedValue = URLEncoder.encode(urlVal, "UTF-8");
                String sdurl = "https://" + sd_hostname + ":" + sd_port + "/ca/admin/ca/securityDomainLogin?url="
                        + encodedValue;
                response.sendRedirect(sdurl);

                // The user previously specified the CA Security Domain's
                // SSL Admin port in the "Security Domain Panel";
                // now retrieve this specified CA Security Domain's
                // non-SSL EE, SSL Agent, and SSL EE ports:
                String domainXML = ConfigurationUtils.getDomainXML(sd_hostname, sd_port, true);
                ConfigurationUtils.getSecurityDomainPorts(domainXML, sd_hostname, sd_port);
                cs.putString("preop.domainXML", domainXML);
                cs.commit(false);
            } catch (Exception e) {
                CMS.debug("DisplayCertChainPanel Exception=" + e.toString());
                e.printStackTrace();
                context.put("errorString", e.toString());
                context.put("updateStatus", "failure");
                throw new IOException(e);
            }
        }
        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        /* This should never be called */
        context.put("title", "Display Certificate Chain");
        context.put("panel", "admin/console/config/displaycertchainpanel.vm");
    }
}
