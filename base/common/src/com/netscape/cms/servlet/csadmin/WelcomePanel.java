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

import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;

import com.netscape.cms.servlet.wizard.*;

public class WelcomePanel extends WizardPanelBase {

    public WelcomePanel() {}

    /**
     * Initializes this panel.
     */
    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Welcome");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putBoolean("preop.welcome.done", false);
    }

    public boolean isPanelDone() { 
        IConfigStore cs = CMS.getConfigStore();
        try {
            return cs.getBoolean("preop.welcome.done");
        } catch (EBaseException e) {}
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
        IConfigStore cs = CMS.getConfigStore();
        CMS.debug("WelcomePanel: display()");
        context.put("title", "Welcome");
        try {
            context.put("cstype", cs.getString("cs.type"));
            context.put("wizardname", cs.getString("preop.wizard.name"));
            context.put("panelname", 
                    cs.getString("preop.system.fullname") + " Configuration Wizard");
            context.put("systemname",
                    cs.getString("preop.system.name"));
            context.put("fullsystemname",
                    cs.getString("preop.system.fullname"));
            context.put("productname",
                    cs.getString("preop.product.name"));
            context.put("productversion",
                    cs.getString("preop.product.version"));
        } catch (EBaseException e) {}
        context.put("panel", "admin/console/config/welcomepanel.vm");
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
        try {
            cs.putBoolean("preop.welcome.done", true);
            cs.commit(false);
        } catch (EBaseException e) {}
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {/* This should never be called */}
}
