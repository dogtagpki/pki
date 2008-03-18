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
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import java.io.*;


public class ConfigDatabaseServlet extends ConfigBaseServlet {

    private static final String HOST = "localhost";
    private static final String PORT = "389";
    private static final String BASEDN = "o=netscapeCertificateServer";
    private static final String BINDDN = "cn=Directory Manager";
    private static final String DATABASE = "userRoot";

    public boolean isPanelModified() {
        IConfigStore cs = CMS.getConfigStore();
        String modified = "";

        try {
            modified = cs.getString("preop.configDatabase.modified", "");
        } catch (Exception e) {}

        if (modified.equals("true")) {
            return true;
        } else {
            return false;
        }
    }

    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String hostname = null;
        String portStr = null;
        String basedn = null;
        String binddn = null;
        String bindpwd = "";
        String database = null;

        IConfigStore cs = CMS.getConfigStore();

        if (isPanelModified()) {
            try {
                hostname = cs.getString("internaldb.ldapconn.host", "");
                portStr = cs.getString("internaldb.ldapconn.port", "");
                basedn = cs.getString("internaldb.basedn", "");
                binddn = cs.getString("internaldb.ldapauth.bindDN", "");
                database = cs.getString("internaldb.database", "");
            } catch (Exception e) {}
        } else {
            hostname = HOST;
            portStr = PORT;
            basedn = BASEDN;
            binddn = BINDDN;
            database = DATABASE;
        }

        context.put("hostname", hostname);
        context.put("portStr", portStr);
        context.put("basedn", basedn);
        context.put("binddn", binddn);
        context.put("bindpwd", bindpwd);
        context.put("database", database);
        context.put("displayStr", "initial");
        context.put("errorString", "");
    }

    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        IConfigStore cs = CMS.getConfigStore();
        String errorString = "";
        String hostname = request.getParameter("host");

        if (hostname != null && hostname.length() > 0) {
            cs.putString("internaldb.ldapconn.host", hostname);
        } else {
            errorString = "Host is empty string";
        }

        String portStr = request.getParameter("port");

        if (portStr != null && portStr.length() > 0) {
            int port = -1;

            try {
                port = Integer.parseInt(portStr); 
                cs.putInteger("internaldb.ldapconn.port", port);
            } catch (Exception e) {
                errorString = "Port is invalid";
            }
        } else {
            errorString = "Port is empty string";
        }

        String basedn = request.getParameter("basedn");

        if (basedn != null && basedn.length() > 0) {
            cs.putString("internaldb.basedn", basedn);
        } else {
            errorString = "Base DN is empty string";
        }

        String binddn = request.getParameter("binddn");

        if (binddn != null && binddn.length() > 0) {
            cs.putString("internaldb.ldapauth.bindDN", binddn);
        } else {
            errorString = "Bind DN is empty string";
        }

        String database = request.getParameter("database");

        if (database != null && database.length() > 0) {
            cs.putString("internaldb.database", database);
        } else {
            errorString = "Database is empty string";
        }

        String bindpwd = request.getParameter("bindpwd");
        IConfigStore psStore = null;

        if (bindpwd != null && bindpwd.length() > 0) {
            String passwordFile = null;

            try {
                passwordFile = cs.getString("passwordFile");
                psStore = CMS.createFileConfigStore(passwordFile);
            } catch (Exception e) {
                CMS.debug("ConfigDatabaseServlet update: " + e.toString());
                return;
            }
            psStore.putString("internaldb", bindpwd); 
        } else {
            errorString = "Bind password is empty string";
        }

        cs.putString("preop.configDatabase.modified", "true");
        if (errorString.equals("")) {
            try {
                psStore.commit(false);
                cs.commit(false);
            } catch (Exception e) {
                CMS.debug("ConfigDatabaseServlet update: " + e.toString());
            }
        }

        context.put("hostname", hostname);
        context.put("portStr", portStr);
        context.put("basedn", basedn);
        context.put("binddn", binddn);
        context.put("bindpwd", bindpwd);
        context.put("database", database);
        context.put("displayStr", "loaded");
        context.put("errorString", errorString);
    }

    public Template getTemplate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        try {
            return Velocity.getTemplate("admin/console/config/config_db.vm");
        } catch (Exception e) {}
        return null;
    }
}
