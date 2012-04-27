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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class AdminPanel extends WizardPanelBase {

    private static final String ADMIN_UID = "admin";

    public AdminPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Administrator");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id) {
        setPanelNo(panelno);
        setName("Administrator");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.admin.email", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.admin.email", "");
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

        Descriptor emailDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Email address for an administrator");

        set.add("admin_email", emailDesc);

        Descriptor pwdDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Administrator's password");

        set.add("pwd", pwdDesc);

        Descriptor pwdAgainDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Administrator's password again");

        set.add("admin_password_again", pwdAgainDesc);
        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("AdminPanel: display");

        IConfigStore cs = CMS.getConfigStore();
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        String type = "";
        String info = "";
        context.put("import", "true");

        try {
            type = cs.getString("preop.ca.type", "");
        } catch (Exception e) {
        }

        if (isPanelDone()) {
            try {
                context.put("admin_email", cs.getString("preop.admin.email"));
                context.put("admin_name", cs.getString("preop.admin.name"));
                context.put("admin_pwd", "");
                context.put("admin_pwd_again", "");
                context.put("admin_uid", cs.getString("preop.admin.uid"));
            } catch (Exception e) {
            }
        } else {
            String def_admin_name = "";
            try {
                def_admin_name = cs.getString("cs.type") + " Administrator of Instance " + cs.getString("instanceId");
            } catch (EBaseException e) {
            }
            context.put("admin_name", def_admin_name);
            context.put("admin_email", "");
            context.put("admin_pwd", "");
            context.put("admin_pwd_again", "");
            context.put("admin_uid", ADMIN_UID);
        }
        ISubsystem ca = CMS.getSubsystem("ca");

        if (ca == null) {
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }
        context.put("caType", type);

        String domainname = "";
        try {
            domainname = cs.getString("securitydomain.name", "");
        } catch (EBaseException e1) {
        }
        context.put("securityDomain", domainname);
        context.put("title", "Administrator");
        context.put("panel", "admin/console/config/adminpanel.vm");
        context.put("errorString", "");
        context.put("info", info);

    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        String pwd = HttpInput.getPassword(request, "__pwd");
        String pwd_again = HttpInput.getPassword(request, "__admin_password_again");
        String email = HttpInput.getEmail(request, "email");
        String name = HttpInput.getName(request, "name");
        String uid = HttpInput.getUID(request, "uid");
        context.put("admin_email", email);
        context.put("admin_name", name);
        context.put("admin_pwd", pwd);
        context.put("admin_pwd_again", pwd_again);
        context.put("import", "true");

        if (name == null || name.equals("")) {
            context.put("updateStatus", "validate-failure");
            throw new IOException("Name is empty");
        }

        if (email == null || email.equals("")) {
            context.put("updateStatus", "validate-failure");
            throw new IOException("Email is empty");
        }

        if (uid == null || uid.equals("")) {
            context.put("updateStatus", "validate-failure");
            throw new IOException("Uid is empty");
        }

        if (!pwd.equals(pwd_again)) {
            context.put("updateStatus", "validate-failure");
            throw new IOException("Password and password again are not the same.");
        }

        if (email == null || email.length() == 0) {
            context.put("updateStatus", "validate-failure");
            throw new IOException("Email address is empty string.");
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request, HttpServletResponse response, Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        context.put("info", "");
        context.put("import", "true");

        String uid = HttpInput.getUID(request, "uid");
        String email = HttpInput.getEmail(request, "email");
        String name = HttpInput.getName(request, "name");
        String pwd = HttpInput.getPassword(request, "__pwd");
        String cert_request_type = HttpInput.getID(request, "cert_request_type");
        String subject = request.getParameter("subject");
        String cert_request = HttpInput.getCertRequest(request, "cert_request");
        String profileId = HttpInput.getID(request, "profileId");

        try {
            String type = config.getString(PRE_CA_TYPE, "");
            String subsystemtype = config.getString("cs.type", "");
            String selected_hierarchy = config.getString("preop.hierarchy.select", "");

            ISubsystem ca = CMS.getSubsystem("ca");

            if (ca == null) {
                context.put("ca", "false");
            } else {
                context.put("ca", "true");
            }
            context.put("caType", type);

            config.putString("preop.admin.uid", uid);
            config.putString("preop.admin.email", email);
            config.putString("preop.admin.name", name);
            ConfigurationUtils.createAdmin(uid, email, name, pwd);

            if (ca != null) {
                if (selected_hierarchy.equals("root")) {
                    CMS.debug("AdminPanel update:  " + "Root CA subsystem");
                } else {
                    CMS.debug("AdminPanel update:  " + "Subordinate CA subsystem");
                }

                ConfigurationUtils.createAdminCertificate(cert_request,
                        cert_request_type, subject);
            } else {
                String ca_hostname = null;
                int ca_port = -1;

                CMS.debug("AdminPanel update:  " + subsystemtype + " subsystem");

                if (type.equals("sdca")) {
                    ca_hostname = config.getString("preop.ca.hostname");
                    ca_port = config.getInteger("preop.ca.httpsport");
                } else {
                    ca_hostname = config.getString("securitydomain.host", "");
                    ca_port = config.getInteger("securitydomain.httpseeport");
                }

                ConfigurationUtils.submitAdminCertRequest(ca_hostname, ca_port,
                        profileId, cert_request_type, cert_request, subject);
            }

            CMS.reinit(IUGSubsystem.ID);
            config.commit(false);
        } catch (Exception e) {
            CMS.debug("AdminPanel update(): Exception thrown " + e);
            e.printStackTrace();
            context.put("updateStatus", "failure");
            throw new IOException("Error when adding admin user" + e);
        }

        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        context.put("title", "Administrator");
        context.put("panel", "admin/console/config/adminpanel.vm");
        ISubsystem ca = CMS.getSubsystem("ca");
        IConfigStore cs = CMS.getConfigStore();
        String type = "";
        String info = "";

        try {
            type = cs.getString("preop.ca.type", "");
        } catch (Exception e) {
        }
        if (ca == null && type.equals("otherca")) {
            info =
                    "Since you do not join the Redhat CA network, the administrator's certificate will not be generated automatically.";
        }
        context.put("info", info);
        context.put("admin_email", request.getParameter("email"));
        context.put("admin_name", request.getParameter("name"));
        context.put("admin_pwd", "");
        context.put("admin_pwd_again", "");
        context.put("admin_uid", request.getParameter("uid"));
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
}
