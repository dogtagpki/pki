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

public class AuthenticatePanel extends WizardPanelBase {

    public AuthenticatePanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Authentication");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Authentication");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.ca.agent.uid", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.ca.agent.uid", "");
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
        context.put("title", "Authentication");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {

            try {
                String s = config.getString("preop.ca.agent.uid", "");
                String type = config.getString("preop.hierarchy.select", "");
                if (type.equals("root"))
                    context.put("uid", "");
                else
                    context.put("uid", s);
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("uid", "");
        }

        context.put("password", "");
        context.put("panel", "admin/console/config/authenticatepanel.vm");
        context.put("errorString", "");
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
        String type = "";
        String catype = "";
        try {
            type = config.getString("preop.hierarchy.select", "");
            catype = config.getString("preop.ca.type", "");
        } catch (Exception e) {
        }

        if (type.equals("root")) {
            CMS.debug("AuthenticatePanel: This is root, no need for authentication");
        } else if (catype.equals("sdca")) {
            CMS.debug("AuthenticatePanel: This is not external CA");
            String uid = HttpInput.getUID(request, "uid");
            if (uid == null) {
                context.put("errorString", "Uid is empty");
                throw new IOException("Uid is empty");
            }
            context.put("uid", uid);
            String pwd = HttpInput.getPassword(request, "__password");
            config.putString("preop.ca.agent.uid", uid);
            config.putString("preop.ca.agent.pwd", pwd);
            String host = "";
            int httpsport = -1;
            try {
                host = config.getString("preop.ca.hostname");
            } catch (Exception e) {
                CMS.debug("AuthenticatePanel update: " + e.toString());
                context.put("errorString", "Missing hostname");
                throw new IOException("Missing hostname");
            }

            try {
                httpsport = config.getInteger("preop.ca.httpsport");
            } catch (Exception e) {
                CMS.debug("AuthenticatePanel update: " + e.toString());
                context.put("errorString", "Missing port");
                throw new IOException("Missing port");
            }

            boolean authenticated = authenticate(host, httpsport, true,
                    "/ca/ee/ca/configSubsystem", "uid=" + uid + "&pwd=" + pwd);

            if (!authenticated) {
                context.put("errorString", "Wrong user id or password");
                throw new IOException("Wrong user id or password");
            }

            try {
                config.commit(false);
            } catch (EBaseException e) {
            }
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("password", "");
        context.put("panel", "admin/console/config/authenticatepanel.vm");
    }
}
