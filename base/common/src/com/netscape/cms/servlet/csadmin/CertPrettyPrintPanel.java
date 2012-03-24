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


import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.io.*;
import java.security.*;

import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.cmsutil.crypto.*;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.pkcs11.*;

import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;

import com.netscape.cms.servlet.wizard.*;

public class CertPrettyPrintPanel extends WizardPanelBase {
    private Vector mCerts = null;

    public CertPrettyPrintPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Certificates");
        setId(id);
    }

    public PropertySet getUsage() {
        // expects no input from client
        PropertySet set = new PropertySet();
                                                                                
        return set;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putBoolean("preop.CertPrettyPrintPanel.done", false);
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.CertPrettyPrintPanel.done",
                    false);

            if (s != true) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}

        return false;
    }

    public void getCert(HttpServletRequest req, IConfigStore config,
            Context context, String certTag, Cert cert) {
        CMS.debug("CertPrettyPrintPanel: in getCert()");
        try {
            // String cert = config.getString(CONF_CA_CERT);
            String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
            String certs = config.getString(subsystem + "." + certTag + ".cert");
            byte[] certb = CryptoUtil.base64Decode(certs);

            if (cert != null) {
                CertPrettyPrint pp = new CertPrettyPrint(certb);
                cert.setCertpp(pp.toString(Locale.getDefault()));
                String certf = CryptoUtil.certFormat(certs);

                // String canickname = config.getString(CONF_CA_CERTNICKNAME);
                // context.put("cert", certf);
                // context.put("nickname", nickname);
                cert.setCert(certf);
            }
        } catch (Exception e) {
            CMS.debug("CertPrettyPrintPanel:getCert" + e.toString());
        } // try
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        CMS.debug("CertPrettyPrintPanel: display()");
        context.put("title", "Certificates Pretty Print");

        try {
            mCerts = new Vector();

            IConfigStore config = CMS.getConfigStore();

            String certTags = config.getString("preop.cert.list");
            StringTokenizer st = new StringTokenizer(certTags, ",");

            while (st.hasMoreTokens()) {
                String certTag = st.nextToken();

                try {
                    String subsystem = config.getString(
                            PCERT_PREFIX + certTag + ".subsystem");

                    String nickname = config.getString(
                            subsystem + "." + certTag + ".nickname");
                    String tokenname = config.getString(
                            subsystem + "." + certTag + ".tokenname");
                    Cert c = new Cert(tokenname, nickname, certTag);

                    String type = config.getString(
                            PCERT_PREFIX + certTag + ".type");

                    c.setType(type);
                    getCert(request, config, context, certTag, c);

                    mCerts.addElement(c);
                } catch (Exception e) {
                    CMS.debug(
                            "CertPrettyPrintPanel: display() certTag " + certTag
                            + " Exception caught: " + e.toString());
                }
            }
        } catch (Exception e) {
            CMS.debug(
                    "CertPrettyPrintPanel:display() Exception caught: "
                            + e.toString());
            System.err.println("Exception caught: " + e.toString());

        } // try

        context.put("ppcerts", mCerts);
        context.put("status", "display");
        // context.put("status_token", "None");
        context.put("panel", "admin/console/config/certprettyprintpanel.vm");

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
        CMS.debug("CertPrettyPrintPanel: in update()");
        IConfigStore config = CMS.getConfigStore();
        config.putBoolean("preop.CertPrettyPrintPanel.done", true);
        try {
            config.commit(false);
        } catch (EBaseException e) {
            CMS.debug(
                  "CertPrettyPrintPanel: update() Exception caught at config commit: "
                            + e.toString());
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Certificates Pretty Print");
        context.put("panel", "admin/console/config/certprettyprintpanel.vm");
    }
}
