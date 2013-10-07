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
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class BackupKeyCertPanel extends WizardPanelBase {

    public BackupKeyCertPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Export Keys and Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Export Keys and Certificates");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        /* clean up if necessary */
        try {
            @SuppressWarnings("unused")
            boolean done = cs.getBoolean("preop.backupkeycert.done"); // check for errors
            cs.putBoolean("preop.backupkeycert.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean shouldSkip() {
        IConfigStore cs = CMS.getConfigStore();

        try {
            String s = cs.getString("preop.module.token", "");
            if (s.equals("Internal Key Storage Token"))
                return false;
        } catch (Exception e) {
        }

        return true;
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.backupkeycert.done", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {
        }
        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        /* XXX */

        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Export Keys and Certificates");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            try {
                boolean enable = config.getBoolean("preop.backupkeys.enable");
                if (enable) {
                    context.put("dobackup", "checked");
                    context.put("nobackup", "");
                } else {
                    context.put("dobackup", "");
                    context.put("nobackup", "checked");
                }
            } catch (Exception e) {
            }
        } else {
            context.put("dobackup", "");
            context.put("nobackup", "checked");
        }

        context.put("panel", "admin/console/config/backupkeycertpanel.vm");
        context.put("pwd", "");
        context.put("pwdagain", "");
        context.put("errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response, Context context) throws IOException {
        String select = HttpInput.getID(request, "choice");
        if (select.equals("backupkey")) {
            String pwd = request.getParameter("__pwd");
            String pwdAgain = request.getParameter("__pwdagain");
            if (pwd == null || pwdAgain == null || pwd.equals("") || pwdAgain.equals("")) {
                CMS.debug("BackupKeyCertPanel validate: Password is null");
                context.put("updateStatus", "validate-failure");
                throw new IOException("PK12 password is empty.");
            }

            if (!pwd.equals(pwdAgain)) {
                CMS.debug("BackupKeyCertPanel validate: Password and password again are not the same.");
                context.put("updateStatus", "validate-failure");
                throw new IOException("PK12 password is different from the PK12 password again.");
            }
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();

        try {
            String select = HttpInput.getID(request, "choice");
            String pwd = request.getParameter("__pwd");
            if (select.equals("backupkey")) {
                CMS.debug("BackupKeyCertPanel update: backup");
                config.putBoolean("preop.backupkeys.enable", true);
                ConfigurationUtils.backupKeys(pwd, null);
            } else {
                CMS.debug("BackupKeyCertPanel update: no backup");
                config.putBoolean("preop.backupkeys.enable", false);
            }

            config.putBoolean("preop.backupkeycert.done", true);
                config.commit(false);
        } catch (Exception e) {
            CMS.debug("BackupKeyertPanel: update(): Exception thrown " + e);
            e.printStackTrace();
            context.put("updateStatus", "failure");
            throw new IOException(e);
        }
        context.put("updateStatus", "success");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String select = "";
        try {
            select = HttpInput.getID(request, "choice");
        } catch (Exception e) {
        }

        if (select.equals("backupkey")) {
            context.put("dobackup", "checked");
            context.put("nobackup", "");
        } else {
            context.put("dobackup", "");
            context.put("nobackup", "checked");
        }

        context.put("pwd", "");
        context.put("pwdagain", "");
        context.put("title", "Export Keys and Certificates");
        context.put("panel", "admin/console/config/backupkeycertpanel.vm");
    }
}
