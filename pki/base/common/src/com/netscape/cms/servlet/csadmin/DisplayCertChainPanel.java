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
import org.xml.sax.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.template.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.ca.*;
import com.netscape.cmsutil.xml.*;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import com.netscape.cmsutil.http.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.asn1.*;
import netscape.security.util.*;
import netscape.security.x509.X509CertImpl;

import com.netscape.cmsutil.crypto.*;
import com.netscape.cms.servlet.wizard.*;

public class DisplayCertChainPanel extends WizardPanelBase {

    public DisplayCertChainPanel() {}

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
            String select = cs.getString("preop.securitydomain.select","");
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
        String certchain_size = "";

        try {
            certchain_size = cs.getString(certChainConfigName, "");
        } catch (Exception e) {}

        int size = 0;
        Vector v = new Vector();

        if (!certchain_size.equals("")) {
            try {
                size = Integer.parseInt(certchain_size);
            } catch (Exception e) {}         
            for (int i = 0; i < size; i++) {
                certChainConfigName = "preop." + type + ".certchain." + i;
                try {
                    String c = cs.getString(certChainConfigName, "");
                    byte[] b_c = CryptoUtil.base64Decode(c);
                    CertPrettyPrint pp = new CertPrettyPrint(
                            new X509CertImpl(b_c));                

                    v.addElement(pp.toString(Locale.getDefault()));
                } catch (Exception e) {}
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
        importCertChain(getId());

        if (getId().equals("securitydomain")) {
            int panel = getPanelNo()+1;
            IConfigStore cs = CMS.getConfigStore();
            try {
                String hostname = cs.getString("preop.securitydomain.host", "");
                int port = cs.getInteger("preop.securitydomain.httpsport", -1);
                String subsystem = cs.getString("cs.type", "");
                String urlVal = "https://"+CMS.getEESSLHost()+":"+CMS.getEESSLPort()+"/"+toLowerCaseSubsystemType(subsystem)+"/admin/console/config/wizard?p="+panel+"&subsystem="+subsystem;
                String encodedValue = URLEncoder.encode(urlVal, "UTF-8");
                String sdurl =  "https://"+hostname+":"+port+"/ca/ee/ca/securityDomainLogin?url="+encodedValue;
                response.sendRedirect(sdurl);
            } catch (Exception ee) {
                CMS.debug("DisplayCertChainPanel Exception="+ee.toString());
            }
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        /* This should never be called */
        context.put("title", "Display Certificate Chain");
        context.put("panel", "admin/console/config/displaycertchainpanel.vm");
    }
}
