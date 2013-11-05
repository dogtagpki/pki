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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.wizard.WizardServlet;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class ImportAdminCertPanel extends WizardPanelBase {

    public ImportAdminCertPanel() {
    }

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

        String type = "";

        try {
            type = cs.getString("preop.ca.type", "");
        } catch (Exception e) {
        }

        try {
            String serialno = cs.getString("preop.admincert.serialno.0");

            context.put("serialNumber", serialno);
        } catch (Exception e) {
            context.put("errorString", "Failed to get serial number.");
        }

        context.put("caType", type);

        ISubsystem ca = CMS.getSubsystem("ca");

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
                    // this is a non-CA system that has elected to have its certificates
                    // signed by a CA outside of the security domain.
                    // in this case, we submitted the cert request for the admin cert to
                    // to security domain host.
                    caHost = cs.getString("securitydomain.host", "");
                    caPort = cs.getString("securitydomain.httpsadminport", "");
                } catch (Exception e) {
                }
            } else if (type.equals("sdca")) {
                try {
                    // this is a non-CA system that submitted its certs to a CA
                    // within the security domain.  In this case, we submitted the cert
                    // request for the admin cert to this CA
                    caHost = cs.getString("preop.ca.hostname", "");
                    caPort = cs.getString("preop.ca.httpsadminport", "");
                } catch (Exception e) {
                }
            }
        } else {
            // for CAs, we always generate our own admin certs
            // send our own connection details
            try {
                caHost = cs.getString("service.machineName", "");
                caPort = cs.getString("pkicreate.admin_secure_port", "");
            } catch (Exception e) {
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

        String type = "";
        String subsystemtype = "";
        String selected_hierarchy = "";

        try {
            type = cs.getString("preop.ca.type", "");
            subsystemtype = cs.getString("cs.type", "");
            selected_hierarchy = cs.getString("preop.hierarchy.select", "");
        } catch (Exception e) {
        }

        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(
                ICertificateAuthority.ID);

        if (ca == null) {
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }
        context.put("caType", type);

        X509CertImpl certs[] = new X509CertImpl[1];

        // REMINDER:  This panel is NOT used by "clones"
        if (ca != null) {
            String serialno = null;

            if (selected_hierarchy.equals("root")) {
                CMS.debug("ImportAdminCertPanel update:  "
                         + "Root CA subsystem - "
                         + "(new Security Domain)");
            } else {
                CMS.debug("ImportAdminCertPanel update:  "
                         + "Subordinate CA subsystem - "
                         + "(new Security Domain)");
            }

            try {
                serialno = cs.getString("preop.admincert.serialno.0");
            } catch (Exception e) {
                CMS.debug(
                        "ImportAdminCertPanel update: Failed to get request id.");
                context.put("updateStatus", "failure");
                throw new IOException("Failed to get request id.");
            }

            ICertificateRepository repost = ca.getCertificateRepository();

            try {
                certs[0] = repost.getX509Certificate(
                        new BigInteger(serialno, 16));
            } catch (Exception ee) {
            }
        } else {
            String dir = null;

            // REMINDER:  This panel is NOT used by "clones"
            if (subsystemtype.equals("CA")) {
                if (selected_hierarchy.equals("root")) {
                    CMS.debug("ImportAdminCertPanel update:  "
                             + "Root CA subsystem - "
                             + "(existing Security Domain)");
                } else {
                    CMS.debug("ImportAdminCertPanel update:  "
                             + "Subordinate CA subsystem - "
                             + "(existing Security Domain)");
                }
            } else {
                CMS.debug("ImportAdminCertPanel update:  "
                         + subsystemtype
                         + " subsystem");
            }

            try {
                dir = cs.getString("preop.admincert.b64", "");
                CMS.debug("ImportAdminCertPanel update: dir=" + dir);
            } catch (Exception ee) {
            }

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

        } catch (ConflictingOperationException e) {
            CMS.debug("ImportAdminCertPanel update: failed to add certificate to the internal database. Exception: "
                    + e.toString());
            // ignore

        } catch (Exception e) {
            CMS.debug(
                    "ImportAdminCertPanel update: failed to add certificate. Exception: "
                            + e.toString());
            context.put("updateStatus", "failure");
            throw new IOException(e.toString());
        }

        context.put("errorString", "");
        context.put("info", "");
        context.put("title", "Import Administrator Certificate");
        context.put("panel", "admin/console/config/importadmincertpanel.vm");
        context.put("updateStatus", "success");
    }

    public boolean shouldSkip() {
        try {
            IConfigStore c = CMS.getConfigStore();
            String s = c.getString("preop.subsystem.select", null);
            if (s != null && s.equals("clone")) {
                return true;
            }
        } catch (EBaseException e) {
        }

        return false;
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
