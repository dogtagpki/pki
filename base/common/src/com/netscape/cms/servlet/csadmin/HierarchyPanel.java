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

public class HierarchyPanel extends WizardPanelBase {

    public HierarchyPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("PKI Hierarchy");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("PKI Hierarchy");
        setId(id);
    }

    public boolean shouldSkip() {

        // we dont need to ask the hierachy if we are
        // setting up a clone
        try {
            IConfigStore c = CMS.getConfigStore();
            String s = c.getString("preop.subsystem.select",
                    null);
            if (s != null && s.equals("clone")) {
                // mark this panel as done
                c.putString("preop.hierarchy.select", "root");
                c.putString("hierarchy.select", "Clone");
                return true;
            }
        } catch (EBaseException e) {
        }

        return false;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.hierarchy.select", "");
        cs.putString("hierarchy.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.hierarchy.select", "");
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
        context.put("title", "PKI Hierarchy");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            try {
                String s = config.getString("preop.hierarchy.select");

                if (s.equals("root")) {
                    context.put("check_root", "checked");
                } else if (s.equals("join")) {
                    context.put("check_join", "checked");
                }
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("check_root", "checked");
            context.put("check_join", "");
        }

        context.put("panel", "admin/console/config/hierarchypanel.vm");
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
            String cstype = config.getString("preop.subsystem.select", "");
            if (cstype.equals("clone")) {
                context.put("updateStatus", "success");
                return;
            }
        } catch (Exception e) {
        }

        String select = HttpInput.getID(request, "choice");

        if (select == null) {
            CMS.debug("HierarchyPanel: choice not found");
            context.put("updateStatus", "failure");
            throw new IOException("choice not found");
        }

        if (select.equals("root")) {
            config.putString("preop.hierarchy.select", "root");
            config.putString("hierarchy.select", "Root");
            config.putString("preop.ca.type", "sdca");
            try {
                config.commit(false);
            } catch (EBaseException e) {
            }
        } else if (select.equals("join")) {
            config.putString(PCERT_PREFIX + "signing.type", "remote");
            config.putString("preop.hierarchy.select", "join");
            config.putString("hierarchy.select", "Subordinate");
        } else {
            config.putString(PCERT_PREFIX + "signing.type", "remote");
            CMS.debug("HierarchyPanel: invalid choice " + select);
            context.put("updateStatus", "failure");
            throw new IOException("invalid choice " + select);
        }
        context.put("updateStatus", "success");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }
}
