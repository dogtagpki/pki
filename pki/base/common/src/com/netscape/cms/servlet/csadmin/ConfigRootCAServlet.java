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
import javax.servlet.http.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.profile.*;

import java.util.*;


public class ConfigRootCAServlet extends ConfigBaseServlet {

    public boolean isDisplayMode(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String profile = request.getParameter("profile");

        if (profile == null) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isPanelModified() {
        IConfigStore config = CMS.getConfigStore();
      
        String profile = null;

        try {
            profile = config.getString("preop.hierarchy.profile", null);
        } catch (EBaseException e) {}
        if (profile == null || profile.equals("")) {
            return false;
        } else {
            return true;
        }
    }

    public Vector getProfiles() {
        IConfigStore config = CMS.getConfigStore();
        String instancePath = "";

        try {
            instancePath = config.getString("instanceRoot");
        } catch (EBaseException e) {}
        String p[] = { "caCert.profile" };
        Vector profiles = new Vector();

        for (int i = 0; i < p.length; i++) {
            try {
                profiles.addElement(
                        new CertInfoProfile(instancePath + "/conf/" + p[i]));
            } catch (Exception e) {}
        }
        return profiles;
    }

    public void display(HttpServletRequest request,
            HttpServletResponse response, 
            Context context) {
        IConfigStore config = CMS.getConfigStore();
        String profile = null;

        if (isPanelModified()) {
            try {
                profile = config.getString("preop.hierarchy.profile", null);
            } catch (EBaseException e) {}
        }
        if (profile == null) {
            profile = "caCert.profile";
        }
        Vector profiles = getProfiles();

        context.put("status", "display");
        context.put("profiles", profiles);
        context.put("selected_profile_id", profile);
    }

    public void update(HttpServletRequest request,
            HttpServletResponse response, 
            Context context) {
        String profile = request.getParameter("profile");
        IConfigStore config = CMS.getConfigStore();

        config.putString("preop.hierarchy.profile", profile);
        try {
            config.commit(false); 
        } catch (Exception e) {}
        context.put("status", "update");
        context.put("error", "");
        Vector profiles = getProfiles();

        context.put("profiles", profiles);
        context.put("selected_profile_id", profile);
    }
                                                                                
    public Template getTemplate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        Template template = null;

        try {
            template = Velocity.getTemplate(
                    "admin/console/config/config_rootca.vm");
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        }

        return template;
    }
}
