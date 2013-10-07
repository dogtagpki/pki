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

import java.io.File;
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

public class RestoreKeyCertPanel extends WizardPanelBase {

    public RestoreKeyCertPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Import Keys and Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Import Keys and Certificates");
        setId(id);
    }

    /**
     * Should we skip this panel for the configuration.
     */
    public boolean shouldSkip() {
        CMS.debug("RestoreKeyCertPanel: should skip");

        IConfigStore cs = CMS.getConfigStore();
        // if we are root, no need to get the certificate chain.

        try {
            String select = cs.getString("preop.subsystem.select", "");
            if (select.equals("clone")) {
                return false;
            }
        } catch (EBaseException e) {
        }

        return true;
    }

    public boolean isSubPanel() {
        return true;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        /* clean up if necessary */
        try {
            @SuppressWarnings("unused")
            boolean done = cs.getBoolean("preop.restorekeycert.done"); // check for errors
            cs.putBoolean("preop.restorekeycert.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.restorekeycert.done", "");
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
        context.put("title", "Import Keys and Certificates");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {

            try {
                String s = config.getString("preop.pk12.path", "");
                context.put("path", s);
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("path", "");
        }

        context.put("password", "");
        context.put("panel", "admin/console/config/restorekeycertpanel.vm");
        context.put("errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String tokenname = "";
        try {
            tokenname = config.getString("preop.module.token", "");
        } catch (Exception e) {
        }

        if (!tokenname.equals("Internal Key Storage Token"))
            return;

        // Path can be empty. If this case, we just want to
        // get to the next panel. Customer has HSM.
        String s = HttpInput.getString(request, "path");

        if (s != null && !s.equals("")) {
            s = HttpInput.getPassword(request, "__password");
            if (s == null || s.equals("")) {
                CMS.debug("RestoreKeyCertPanel validate: password is empty");
                context.put("updateStatus", "validate-failure");
                throw new IOException("Empty password");
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
            ConfigurationUtils.getConfigEntriesFromMaster();

            String path = HttpInput.getString(request, "path");
            if (path == null || path.equals("")) {
                // skip to next panel
                config.putBoolean("preop.restorekeycert.done", true);
                config.commit(false);
                context.put("updateStatus", "success");
                return;
            }

            String pwd = HttpInput.getPassword(request, "__password");

            String tokenn = config.getString("preop.module.token");
            if (tokenn.equals("Internal Key Storage Token")) {
                String instanceRoot = config.getString("instanceRoot");
                String p12File = instanceRoot + File.separator + "alias" +
                                 File.separator + path;
                ConfigurationUtils.restoreCertsFromP12(p12File, pwd);
            }

            String subsystemtype = config.getString("preop.subsystem.select", "");
            if (subsystemtype.equals("clone")) {
                CMS.debug("RestoreKeyCertPanel: this is the clone subsystem");
                boolean cloneReady = ConfigurationUtils.isCertdbCloned();
                if (!cloneReady) {
                    CMS.debug("RestoreKeyCertPanel update: clone does not have all the certificates.");
                    throw new IOException("Clone is not ready");
                }
            }

            config.putBoolean("preop.restorekeycert.done", true);
            config.commit(false);
        } catch (Exception e) {
            CMS.debug("RestoreKeyCertPanel update: exception thrown:" + e);
            e.printStackTrace();
            context.put("errorString", e.toString());
            context.put("updateStatus", "failure");
            throw new IOException(e);
        }

        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Import Keys and Certificates");
        context.put("password", "");
        context.put("path", "");
        context.put("panel", "admin/console/config/restorekeycertpanel.vm");
    }
}
