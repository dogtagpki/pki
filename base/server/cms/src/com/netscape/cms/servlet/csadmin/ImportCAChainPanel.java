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
import com.netscape.certsrv.property.PropertySet;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class ImportCAChainPanel extends WizardPanelBase {

    public ImportCAChainPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Import CA's Certificate Chain");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Import CA's Certificate Chain");
        setId(id);
    }

    public boolean isSubPanel() {
        return false;
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
        CMS.debug("ImportCACertChain: display");
        context.put("errorString", "");
        context.put("title", "Import CA's Certificate Chain");
        context.put("panel", "admin/console/config/importcachainpanel.vm");
        context.put("import", "true");

        IConfigStore cs = CMS.getConfigStore();
        try {
            context.put("machineName", cs.getString("machineName"));
            context.put("https_port", cs.getString("pkicreate.ee_secure_port"));
            context.put("http_port", cs.getString("pkicreate.unsecure_port"));
        } catch (EBaseException e) {
            CMS.debug("ImportCACertChain:display: Exception: " + e.toString());
            context.put("errorString", "Error loading values for Import CA Certificate Panel");
        }

        ISubsystem ca = CMS.getSubsystem("ca");

        if (ca == null) {
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
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

        context.put("errorString", "");
        context.put("title", "Import CA's Certificate Chain");
        context.put("panel", "admin/console/config/importcachainpanel.vm");
        context.put("updateStatus", "success");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        /* This should never be called */
        IConfigStore cs = CMS.getConfigStore();
        try {
            context.put("machineName", cs.getString("machineName"));
            context.put("https_port", cs.getString("pkicreate.ee_secure_port"));
            context.put("http_port", cs.getString("pkicreate.unsecure_port"));
            context.put("title", "Import CA's Certificate Chain");
            context.put("panel", "admin/console/config/importcachainpanel.vm");
        } catch (EBaseException e) {
        }
    }
}
