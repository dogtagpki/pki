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
import java.util.Random;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class DatabasePanel extends WizardPanelBase {

    private static final String HOST = "localhost";
    private static final String CLONE_HOST = "Enter FQDN here";
    private static final String PORT = "389";
    private static final String BINDDN = "cn=Directory Manager";

    private WizardServlet mServlet = null;

    public DatabasePanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Internal Database");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Internal Database");
        setId(id);
        mServlet = servlet;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putBoolean("preop.Database.done", false);
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.Database.done",
                    false);

            if (s != true) {
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
        Descriptor hostDesc = new Descriptor(IDescriptor.STRING, null, null, "Host name");
        set.add("hostname", hostDesc);

        Descriptor portDesc = new Descriptor(IDescriptor.INTEGER, null, null, "Port");
        set.add("portStr", portDesc);

        Descriptor basednDesc = new Descriptor(IDescriptor.STRING, null, null, "Base DN");
        set.add("basedn", basednDesc);

        Descriptor binddnDesc = new Descriptor(IDescriptor.STRING, null, null, "Bind DN");
        set.add("binddn", binddnDesc);

        Descriptor bindpwdDesc = new Descriptor(IDescriptor.PASSWORD, null, null, "Bind Password");
        set.add("bindpwd", bindpwdDesc);

        Descriptor databaseDesc = new Descriptor(IDescriptor.STRING, null, null, "Database");
        set.add("database", databaseDesc);

        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("DatabasePanel: display()");
        context.put("title", "Internal Database");
        context.put("firsttime", "false");
        IConfigStore cs = CMS.getConfigStore();
        String hostname = null;
        String portStr = null;
        String basedn = null;
        String binddn = null;
        String bindpwd = "";
        String database = null;
        String errorString = "";
        String secure = "false";
        String masterReplicationPort = "";
        String cloneReplicationPort = "";
        String replicationSecurity = "";

        try {
            @SuppressWarnings("unused")
            String s = cs.getString("preop.database.removeData"); // check whether it's first time
        } catch (Exception e) {
            context.put("firsttime", "true");
        }

        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        if (isPanelDone()) {
            try {
                hostname = cs.getString("internaldb.ldapconn.host", "");
                portStr = cs.getString("internaldb.ldapconn.port", "");
                basedn = cs.getString("internaldb.basedn", "");
                binddn = cs.getString("internaldb.ldapauth.bindDN", "");
                database = cs.getString("internaldb.database", "");
                secure = cs.getString("internaldb.ldapconn.secureConn", "");
                replicationSecurity = cs.getString("internaldb.ldapconn.replicationSecurity", "None");
                masterReplicationPort = cs.getString("internaldb.ldapconn.masterReplicationPort", "");
                cloneReplicationPort = cs.getString("internaldb.ldapconn.cloneReplicationPort", "");
                errorString = cs.getString("preop.database.errorString", "");
            } catch (Exception e) {
                CMS.debug("DatabasePanel display: " + e.toString());
            }
        } else if (select.equals("clone")) {
            hostname = CLONE_HOST;
            portStr = PORT;
            try {
                basedn = cs.getString("internaldb.basedn", "");
            } catch (Exception e) {
                CMS.debug("DatabasePanel::display() - "
                         + "Exception=" + e.toString());
                return;
            }
            binddn = BINDDN;
            database = basedn.substring(basedn.lastIndexOf('=') + 1);
            CMS.debug("Clone: database=" + database);
        } else {
            hostname = HOST;
            portStr = PORT;
            String instanceId = "";
            String machineName = "";

            try {
                instanceId = cs.getString("instanceId", "");
                machineName = cs.getString("machineName", "");
            } catch (Exception e) {
                CMS.debug("DatabasePanel display: " + e.toString());
            }
            String suffix = "dc=" + machineName + "-" + instanceId;

            boolean multipleEnable = false;
            try {
                multipleEnable = cs.getBoolean(
                        "internaldb.multipleSuffix.enable", false);
            } catch (Exception e) {
            }

            if (multipleEnable)
                basedn = "ou=" + instanceId + "," + suffix;
            else
                basedn = suffix;
            binddn = BINDDN;
            database = machineName + "-" + instanceId;
        }

        context.put("clone", select);
        context.put("hostname", hostname);
        context.put("portStr", portStr);
        context.put("basedn", basedn);
        context.put("binddn", binddn);
        context.put("bindpwd", bindpwd);
        context.put("database", database);
        context.put("secureConn", (secure.equals("true") ? "on" : "off"));
        context.put("masterReplicationPort", masterReplicationPort);
        context.put("cloneReplicationPort", cloneReplicationPort);
        context.put("replicationSecurity", replicationSecurity);
        context.put("panel", "admin/console/config/databasepanel.vm");
        context.put("errorString", errorString);
    }

    public void initParams(HttpServletRequest request, Context context)
                   throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String select = "";
        try {
            select = config.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }
        context.put("clone", select);
        context.put("hostname", (request.getParameter("host") != null) ? request.getParameter("host") : "");
        context.put("portStr", (request.getParameter("port") != null) ? request.getParameter("port") : "");
        context.put("basedn", (request.getParameter("basedn") != null) ? request.getParameter("basedn") : "");
        context.put("binddn", (request.getParameter("binddn") != null) ? request.getParameter("binddn") : "");
        context.put("bindpwd", (request.getParameter("__bindpwd") != null) ?
                request.getParameter("__bindpwd"): "");
        context.put("database", (request.getParameter("database") != null) ?
                request.getParameter("database") : "");
        context.put("masterReplicationPort", (request.getParameter("masterReplicationPort") != null) ?
                request.getParameter("masterReplicationPort"): "");
        context.put("cloneReplicationPort", (request.getParameter("cloneReplicationPort") != null) ?
                request.getParameter("cloneReplicationPort"): "");
        context.put("replicationSecurity", (request.getParameter("replicationSecurity") != null) ?
                request.getParameter("replicationSecurity"): "None");
    }

    /**
     * Parses and validates the parameters in the request.
     */
    public void parseParameters(HttpServletRequest request,
            HttpServletResponse response, Context context) throws IOException {
        IConfigStore cs = CMS.getConfigStore();

        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        String hostname = HttpInput.getHostname(request, "host");
        if (hostname == null || hostname.length() == 0) {
            throw new IOException("hostname is empty string");
        }
        context.put("hostname", hostname);

        // this validates that port is an integer
        String portStr = HttpInput.getPortNumber(request, "port");
        context.put("portStr", portStr);

        String basedn = HttpInput.getDN(request, "basedn");
        if (basedn == null || basedn.length() == 0) {
            throw new IOException("basedn is empty string");
        }
        context.put("basedn", basedn);

        String binddn = HttpInput.getDN(request, "binddn");
        if (binddn == null || binddn.length() == 0) {
            throw new IOException("binddn is empty string");
        }
        context.put("binddn", binddn);

        String database = HttpInput.getLdapDatabase(request, "database");
        if (database == null || database.length() == 0) {
            throw new IOException("Database is empty string");
        }
        context.put("database", database);

        String bindpwd = HttpInput.getPassword(request, "__bindpwd");
        if (bindpwd == null || bindpwd.length() == 0) {
            throw new IOException("Bind password is empty string");
        }
        context.put("bindpwd", bindpwd);

        String secure = HttpInput.getCheckbox(request, "secureConn");
        context.put("secureConn", secure);

        String masterReplicationPort = HttpInput.getString(request, "masterReplicationPort");
        if (masterReplicationPort != null && masterReplicationPort.length() > 0) {
            try {
                Integer.parseInt(masterReplicationPort); // check for errors
            } catch (NumberFormatException e) {
                throw new IOException("Master replication port is invalid");
            }
        }
        context.put("masterReplicationPort", masterReplicationPort);

        String cloneReplicationPort = HttpInput.getString(request, "cloneReplicationPort");
        if (cloneReplicationPort != null && cloneReplicationPort.length() > 0) {
            try {
                Integer.parseInt(cloneReplicationPort); // check for errors
            } catch (Exception e) {
                throw new IOException("Clone replication port is invalid");
            }
        }
        context.put("cloneReplicationPort", cloneReplicationPort);

        String replicationSecurity = HttpInput.getString(request, "replicationSecurity");
        context.put("replicationSecurity", replicationSecurity);

        if (select.equals("clone")) {
            String masterhost = "";
            String masterport = "";
            String masterbasedn = "";
            String realhostname = "";
            try {
                masterhost = cs.getString("preop.internaldb.master.ldapconn.host", "");
                masterport = cs.getString("preop.internaldb.master.ldapconn.port", "");
                masterbasedn = cs.getString("preop.internaldb.master.basedn", "");
                realhostname = cs.getString("machineName", "");
            } catch (Exception e) {
            }

            if (masterhost.equals(realhostname) && masterport.equals(portStr)) {
                throw new IOException("Master and clone must not share the same internal database");
            }

            if (!masterbasedn.equals(basedn)) {
                throw new IOException("Master and clone should have the same base DN");
            }
        }

        context.put("errorString", "");
        cs.putString("preop.database.errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {

        IConfigStore cs = CMS.getConfigStore();
        context.put("firsttime", "false");
        try {
            @SuppressWarnings("unused")
            String s = cs.getString("preop.database.removeData"); // check whether it's first time
        } catch (Exception e) {
            context.put("firsttime", "true");
        }

        try {
            parseParameters(request, response, context);
        } catch (IOException e) {
            context.put("errorString", e.getMessage());
            cs.putString("preop.database.errorString", e.getMessage());
            context.put("updateStatus", "validate-failure");
            throw e;
        }

        context.put("errorString", "");
        cs.putString("preop.database.errorString", "");
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore cs = CMS.getConfigStore();

        context.put("firsttime", "false");
        try {
            @SuppressWarnings("unused")
            String s = cs.getString("preop.database.removeData"); // check whether it's first time
        } catch (Exception e) {
            context.put("firsttime", "true");
        }

        String hostname1 = "";
        String portStr1 = "";
        String database1 = "";
        String masterPortStr = "";
        String csType = "";
        String select = "";

        try {
            hostname1 = cs.getString("internaldb.ldapconn.host", "");
            portStr1 = cs.getString("internaldb.ldapconn.port", "");
            database1 = cs.getString("internaldb.database", "");
            masterPortStr = cs.getString("preop.internaldb.master.ldapconn.port", "0");
            csType = cs.getString("cs.type");
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        try {
            parseParameters(request, response, context);
        } catch (IOException e) {
            context.put("errorString", e.getMessage());
            cs.putString("preop.database.errorString", e.getMessage());
            context.put("updateStatus", "validate-failure");
            throw e;
        }

        String hostname2 = (String) context.get("hostname");
        String portStr2 = (String) context.get("portStr");
        String database2 = (String) context.get("database");
        String basedn2 = (String) context.get("basedn");
        String binddn = (String) context.get("binddn");
        String secure = (String) context.get("secureConn");
        String masterReplicationPortStr = (String) context.get("masterReplicationPort");
        String cloneReplicationPortStr = (String) context.get("cloneReplicationPort");

        cs.putString("internaldb.ldapconn.host", hostname2);
        cs.putString("internaldb.ldapconn.port", portStr2);
        cs.putString("internaldb.database", database2);
        cs.putString("internaldb.basedn", basedn2);
        cs.putString("internaldb.ldapauth.bindDN", binddn);
        cs.putString("internaldb.ldapconn.secureConn", (secure.equals("on") ? "true" : "false"));

        if (csType.equals("TPS")) {
            cs.putString("tokendb.activityBaseDN", "ou=Activities," + basedn2);
            cs.putString("tokendb.baseDN", "ou=Tokens," + basedn2);
            cs.putString("tokendb.certBaseDN", "ou=Certificates," + basedn2);
            cs.putString("tokendb.userBaseDN", basedn2);
            cs.putString("tokendb.hostport", hostname2 + ":" + portStr2);
        }

        if ((masterReplicationPortStr == null) || (masterReplicationPortStr.length() == 0)) {
            masterReplicationPortStr = masterPortStr;
        }
        cs.putString("internaldb.ldapconn.masterReplicationPort", masterReplicationPortStr);

        int cloneReplicationPort = 0;
        int port = Integer.parseInt(portStr2);
        if ((cloneReplicationPortStr == null) || (cloneReplicationPortStr.length() == 0)) {
            cloneReplicationPortStr = portStr2;
        }
        cloneReplicationPort = Integer.parseInt(cloneReplicationPortStr);
        cs.putString("internaldb.ldapconn.cloneReplicationPort", cloneReplicationPortStr);

        String replicationSecurity = HttpInput.getString(request, "replicationSecurity");
        if ((cloneReplicationPort == port) && (secure.equals("true"))) {
            replicationSecurity = "SSL";
        } else if (replicationSecurity == null) {
            replicationSecurity = "None";
        }
        cs.putString("internaldb.ldapconn.replicationSecurity", replicationSecurity);

        String remove = HttpInput.getID(request, "removeData");
        cs.putString("preop.database.removeData", ((remove != null) && (!remove.equals(""))) ?
                "true" : "false");

        if (isPanelDone() && (remove == null || remove.equals(""))) {
            /* if user submits the same data, they just want to skip
               to the next panel, no database population is required. */
            if (hostname1.equals(hostname2) &&
                    portStr1.equals(portStr2) &&
                    database1.equals(database2)) {
                context.put("updateStatus", "success");
                return;
            }
        }

        mServlet.cleanUpFromPanel(mServlet.getPanelNo(request));

        try {
            /* BZ 430745 create password for replication manager */
            String replicationpwd = Integer.toString(new Random().nextInt());

            IConfigStore psStore = null;
            String passwordFile = null;
            passwordFile = cs.getString("passwordFile");
            psStore = CMS.createFileConfigStore(passwordFile);
            psStore.putString("internaldb", HttpInput.getPassword(request, "__bindpwd"));
            psStore.putString("replicationdb", replicationpwd);
            psStore.commit(false);

            ConfigurationUtils.populateDB();

            cs.putString("preop.internaldb.replicationpwd", replicationpwd);
            cs.putString("preop.database.removeData", "false");

            if (select.equals("clone")) {
                CMS.debug("Start setting up replication.");
                ConfigurationUtils.setupReplication();
            }

            ConfigurationUtils.reInitSubsystem(csType);
            ConfigurationUtils.populateDBManager();
            ConfigurationUtils.populateVLVIndexes();

            cs.putBoolean("preop.Database.done", true);
            cs.commit(false);
        } catch (Exception e) {
            e.printStackTrace();
            CMS.debug("DatabasePanel update: error in populating database " + e.toString());
            context.put("errorString", e.toString());
            cs.putString("preop.database.errorString", e.toString());
            context.put("updateStatus", "failure");
            throw new IOException(e.toString());
        }

        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        try {
            initParams(request, context);
        } catch (IOException e) {
        }
        context.put("title", "Database");
        context.put("panel", "admin/console/config/databasepanel.vm");
    }

}
