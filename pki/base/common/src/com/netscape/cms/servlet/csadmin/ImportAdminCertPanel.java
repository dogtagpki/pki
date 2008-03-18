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
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.cmsutil.crypto.*;
import com.netscape.certsrv.template.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.certdb.*;
import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;

import org.mozilla.jss.asn1.*;
import com.netscape.cms.servlet.wizard.*;

public class ImportAdminCertPanel extends WizardPanelBase {

    public ImportAdminCertPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Import Administrator's Certificate");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Import Administrator's Certificate");
        setId(id);
    }

    public boolean isSubPanel() {
        return true;
    }

    public void cleanUp() throws IOException {
    }

    public boolean isPanelDone() {
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
        CMS.debug("ImportAdminCertPanel: display");
        context.put("errorString", "");
        context.put("title", "Import Administrator's Certificate");
        context.put("panel", "admin/console/config/importadmincertpanel.vm");
        context.put("import", "true");

        IConfigStore cs = CMS.getConfigStore();

        String s = "";
        try {
            s = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        String type = "";
        String subsystemtype = "";

        try {
            type = cs.getString("preop.ca.type", "");
            subsystemtype = cs.getString("cs.type", "");
        } catch (Exception e) {}

        if (s.equals("clone")) {
            context.put("import", "false");
            return;
        }

        try {
            String serialno = cs.getString("preop.admincert.serialno.0");
            
            context.put("serialNumber", serialno);
        } catch (Exception e) {
            context.put("errorString", "Failed to get serial number.");
        }

        context.put("caType", type);

        ISubsystem ca = (ISubsystem) CMS.getSubsystem("ca");

        if (ca == null) {
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }

        String caHost = "";
        String caPort = "";
        String info = "";

        if (ca == null) {
            if (type.equals("otherca")) {
                try {
                    caHost = cs.getString("preop.securitydomain.host", "");
                    caPort = cs.getString("preop.securitydomain.httpsport", "");
                } catch (Exception e) {}
            } else if (type.equals("sdca")) {
                try {
                    caHost = cs.getString("preop.ca.hostname", "");
                    caPort = cs.getString("preop.ca.httpsport", "");
                } catch (Exception e) {}
            }
        }

        String pkcs7 = "";
        try {
            pkcs7 = cs.getString("preop.admincert.pkcs7", "");
        } catch (Exception e) {
        }

        context.put("pkcs7", pkcs7);
        context.put("caHost", caHost);
        context.put("caPort", caPort);
        context.put("info", info);
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
        IConfigStore cs = CMS.getConfigStore();

        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
            context.put("select", select);
        } catch (Exception e) {
        }

        String type = "";
        String subsystemtype = "";

        try {
            type = cs.getString("preop.ca.type", "");
            subsystemtype = cs.getString("cs.type", "");
        } catch (Exception e) {}

        if (select.equals("clone"))
            return;

        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(
                ICertificateAuthority.ID);

        if (ca == null) { 
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }
        context.put("caType", type);

        X509CertImpl certs[] = new X509CertImpl[1];

        if (ca != null) {
            String serialno = null;

            try {
                serialno = cs.getString("preop.admincert.serialno.0");
            } catch (Exception e) {
                CMS.debug(
                        "ImportAdminCertPanel update: Failed to get request id.");
                throw new IOException("Failed to get request id.");
            }

            ICertificateRepository repost = ca.getCertificateRepository();

            try {
                certs[0] = repost.getX509Certificate(
                        new BigInteger(serialno, 16));
            } catch (Exception ee) {}
        } else {
            String dir = null;

            try {
                dir = cs.getString("preop.admincert.b64", ""); 
                CMS.debug("ImportAdminCertPanel update: dir=" + dir);
            } catch (Exception ee) {}

            try {
                BufferedReader reader = new BufferedReader(
                  new FileReader(dir));
                String b64 = "";

                StringBuffer sb = new StringBuffer();
                while (reader.ready()) {
                    sb.append(reader.readLine());
                }
                b64 = sb.toString();
                reader.close();

                b64 = b64.trim();
                b64 = CryptoUtil.stripCertBrackets(b64);
                CMS.debug("ImportAdminCertPanel update: b64=" + b64);
                byte[] b = CryptoUtil.base64Decode(b64);
                certs[0] = new X509CertImpl(b);
            } catch (Exception e) {
                CMS.debug("ImportAdminCertPanel update: " + e.toString());
            }
        }

        try {
            IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);
            String uid = cs.getString("preop.admin.uid");
            IUser user = ug.getUser(uid);
            user.setX509Certificates(certs);
            ug.addUserCert(user);
        } catch (LDAPException e) {
            CMS.debug("ImportAdminCertPanel update: failed to add certificate to the internal database. Exception: "+e.toString());
            if (e.getLDAPResultCode() != LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
                throw new IOException(e.toString());
            }
        } catch (Exception e) {
            CMS.debug(
                    "ImportAdminCertPanel update: failed to add certificate. Exception: "
                            + e.toString());
            throw new IOException(e.toString());
        }

        context.put("errorString", "");
        context.put("info", "");
        context.put("title", "Import Administrator Certificate");
        context.put("panel", "admin/console/config/importadmincertpanel.vm");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        /* This should never be called */
        context.put("title", "Import Administrator Certificate");
        context.put("panel", "admin/console/config/importadmincertpanel.vm");
        context.put("info", "");
    }
}
