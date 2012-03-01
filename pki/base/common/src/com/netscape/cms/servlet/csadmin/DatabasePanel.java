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

import java.util.ArrayList;

import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.ca.*;
import java.io.*;
import java.util.*;
import com.netscape.cmsutil.ldap.*;

import com.netscape.cms.servlet.wizard.*;

public class DatabasePanel extends WizardPanelBase {

    private static final String HOST = "localhost";
    private static final String CLONE_HOST="Enter FQDN here";
    private static final String PORT = "389";
    private static final String BASEDN = "o=netscapeCertificateServer";
    private static final String BINDDN = "cn=Directory Manager";
    private static final String DATABASE = "csRoot";
    private static final String MASTER_AGREEMENT = "masteragreement-";
    private static final String CLONE_AGREEMENT = "cloneagreement-";

    private WizardServlet mServlet = null;

    public DatabasePanel() {}

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
        } catch (EBaseException e) {}

        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
        Descriptor hostDesc = new Descriptor(IDescriptor.STRING, null, null,
                "Host name");

        set.add("hostname", hostDesc);
      
        Descriptor portDesc = new Descriptor(IDescriptor.INTEGER, null, null,
                "Port");

        set.add("portStr", portDesc);

        Descriptor basednDesc = new Descriptor(IDescriptor.STRING, null, null,
                "Base DN");

        set.add("basedn", basednDesc);
 
        Descriptor binddnDesc = new Descriptor(IDescriptor.STRING, null, null,
                "Bind DN");

        set.add("binddn", binddnDesc);

        Descriptor bindpwdDesc = new Descriptor(IDescriptor.PASSWORD, null, null,
                "Bind Password"); 

        set.add("bindpwd", bindpwdDesc);

        Descriptor databaseDesc = new Descriptor(IDescriptor.STRING, null, null,
                "Database");

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
        String cloneStartTLS = "false";
        try {
            String s = cs.getString("preop.database.removeData");
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
            	secure =  cs.getString("internaldb.ldapconn.secureConn", "");
            	cloneStartTLS =  cs.getString("internaldb.ldapconn.cloneStartTLS", "");
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
                CMS.debug( "DatabasePanel::display() - "
                         + "Exception="+e.toString() );
                return;
            }
            binddn = BINDDN;
            database = basedn.substring(basedn.lastIndexOf('=')+1);
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
        context.put("secureConn", (secure.equals("true")? "on":"off"));
        context.put("cloneStartTLS", (cloneStartTLS.equals("true")? "on":"off"));
        context.put("panel", "admin/console/config/databasepanel.vm");
        context.put("errorString", errorString);
    }

    public void initParams(HttpServletRequest request, Context context)
                   throws IOException
    {
        IConfigStore config = CMS.getConfigStore();
        String select = "";
        try {
            select = config.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }
        context.put("clone", select);
        context.put("hostname", request.getParameter("host"));
        context.put("portStr", request.getParameter("port"));
        context.put("basedn", request.getParameter("basedn"));
        context.put("binddn", request.getParameter("binddn"));
        context.put("bindpwd", request.getParameter("__bindpwd"));
        context.put("database", request.getParameter("database"));
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
            String s = cs.getString("preop.database.removeData");
        } catch (Exception e) {
            context.put("firsttime", "true");
        }

        String hostname = HttpInput.getHostname(request, "host");
        context.put("hostname", hostname);

        String portStr = HttpInput.getPortNumber(request, "port");
        context.put("portStr", portStr);

        String basedn = HttpInput.getDN(request, "basedn");
        context.put("basedn", basedn);

        String binddn = HttpInput.getDN(request, "binddn");
        context.put("binddn", binddn);

        String database = HttpInput.getLdapDatabase(request, "database");
        context.put("database", database);

        String bindpwd = HttpInput.getPassword(request, "__bindpwd");
        context.put("bindpwd", bindpwd);

        String secure = HttpInput.getCheckbox(request, "secureConn");
        context.put("secureConn", secure);

        String cloneStartTLS = HttpInput.getCheckbox(request, "cloneStartTLS");
        context.put("cloneStartTLS", cloneStartTLS);

        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        if (select.equals("clone")) {
            String masterhost = "";
            String masterport = "";
            String masterbasedn = "";
            try {
                masterhost = cs.getString("preop.internaldb.master.ldapconn.host", "");
                masterport = cs.getString("preop.internaldb.master.ldapconn.port", "");
                masterbasedn = cs.getString("preop.internaldb.master.basedn", "");
            } catch (Exception e) {
            }

            //get the real host name
            String realhostname = "";
            if (hostname.equals("localhost")) {
                try {
                    realhostname = cs.getString("machineName", "");
                } catch (Exception ee) {
                }
            }
            if (masterhost.equals(realhostname) && masterport.equals(portStr)) {
                context.put("updateStatus", "validate-failure");
                throw new IOException("Master and clone must not share the same internal database");
            }

            if (!masterbasedn.equals(basedn)) {
                context.put("updateStatus", "validate-failure");
                throw new IOException("Master and clone should have the same base DN");
            }
        }

        if (hostname == null || hostname.length() == 0) {
            cs.putString("preop.database.errorString", "Host is empty string");
            context.put("updateStatus", "validate-failure");
            throw new IOException("Host is empty string");
        }

        if (portStr != null && portStr.length() > 0) {
            int port = -1;

            try {
                port = Integer.parseInt(portStr);
            } catch (Exception e) {
                cs.putString("preop.database.errorString", "Port is invalid");
                context.put("updateStatus", "validate-failure");
                throw new IOException("Port is invalid");
            }
        } else {
            cs.putString("preop.database.errorString", "Port is empty string");
            context.put("updateStatus", "validate-failure");
            throw new IOException("Port is empty string");
        }

        if (basedn == null || basedn.length() == 0) {
            cs.putString("preop.database.errorString", "Base DN is empty string");
            context.put("updateStatus", "validate-failure");
            throw new IOException("Base DN is empty string");
        }

        if (binddn == null || binddn.length() == 0) {
            cs.putString("preop.database.errorString", "Bind DN is empty string");
            context.put("updateStatus", "validate-failure");
            throw new IOException("Bind DN is empty string");
        }

        if (database == null || database.length() == 0) {
            cs.putString("preop.database.errorString",
                    "Database is empty string");
            context.put("updateStatus", "validate-failure");
            throw new IOException("Database is empty string");
        }

        if (bindpwd == null || bindpwd.length() == 0) {
            cs.putString("preop.database.errorString",
                    "Bind password is empty string");
            context.put("updateStatus", "validate-failure");
            throw new IOException("Bind password is empty string");
        }

        context.put("errorString", "");
        cs.putString("preop.database.errorString", "");
    }

    private LDAPConnection getLocalLDAPConn(Context context, String secure)
                throws IOException
    {
        IConfigStore cs = CMS.getConfigStore();

        String host = "";
        String port = "";
        String pwd = "";
        String binddn = "";
        String security = "";

        try {
            host = cs.getString("internaldb.ldapconn.host");
            port = cs.getString("internaldb.ldapconn.port");
            binddn = cs.getString("internaldb.ldapauth.bindDN");
            pwd = (String) context.get("bindpwd");    
            security = cs.getString("internaldb.ldapconn.secureConn");
        } catch (Exception e) {
            CMS.debug("DatabasePanel populateDB: " + e.toString());
            throw new IOException(
                    "Failed to retrieve LDAP information from CS.cfg.");
        }

        int p = -1;

        try {
            p = Integer.parseInt(port);
        } catch (Exception e) {
            CMS.debug("DatabasePanel populateDB: " + e.toString());
            throw new IOException("Port is not valid");
        }

        LDAPConnection conn = null;
        if (security.equals("true")) {
          CMS.debug("DatabasePanel populateDB: creating secure (SSL) connection for internal ldap");
          conn = new LDAPConnection(CMS.getLdapJssSSLSocketFactory());
	} else {
          CMS.debug("DatabasePanel populateDB: creating non-secure (non-SSL) connection for internal ldap");
          conn = new LDAPConnection();
	}

        CMS.debug("DatabasePanel connecting to " + host + ":" + p);
        try {
            conn.connect(host, p, binddn, pwd);
        } catch (LDAPException e) {
            CMS.debug("DatabasePanel populateDB: " + e.toString());
            throw new IOException("Failed to connect to the internal database.");
        }

      return conn;
    }

    private boolean deleteDir(File dir) 
    {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i=0; i<children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }
    
        // The directory is now empty so delete it
        return dir.delete();
    } 

    private void cleanupDB(LDAPConnection conn, String baseDN, String database) 
    {
        String[] entries = {};
        String filter = "objectclass=*";
        LDAPSearchConstraints cons = null;
        String[] attrs = null;
        String dn="";
        try {
            CMS.debug("Deleting baseDN: " + baseDN);
            LDAPSearchResults res = conn.search(baseDN, LDAPConnection.SCOPE_BASE, filter,
                attrs, true, cons);
            if (res != null) 
            	deleteEntries(res, conn, baseDN, entries);
        }
        catch (LDAPException e) {}
        
        try {
           dn="cn=mapping tree, cn=config";
           filter = "nsslapd-backend=" + database;
           LDAPSearchResults res = conn.search(dn, LDAPConnection.SCOPE_ONE, filter,
              attrs, true, cons);
          if (res != null) {
              while (res.hasMoreElements()) {
                  dn = res.next().getDN();
                  filter = "objectclass=*";
                  LDAPSearchResults res2 = conn.search(dn, LDAPConnection.SCOPE_BASE, filter,
                      attrs, true, cons);
                  if (res2 != null) 
              	      deleteEntries(res2, conn, dn, entries);
              }
          }
        }
        catch (LDAPException e) {}

        try {
            dn = "cn=" + database + ",cn=ldbm database, cn=plugins, cn=config";
            LDAPSearchResults res = conn.search(dn, LDAPConnection.SCOPE_BASE, filter,
                attrs, true, cons);
            if (res != null) {
                deleteEntries(res, conn, dn, entries);
                String dbdir = getInstanceDir(conn) + "/db/" + database; 
                if (dbdir != null) { 
            	    CMS.debug(" Deleting dbdir " + dbdir);
                    boolean success = deleteDir(new File(dbdir));
                    if (!success) {
                        CMS.debug("Unable to delete database directory " + dbdir);
                    }
                }
            }
        }
        catch (LDAPException e) {}
    }


    private void populateDB(HttpServletRequest request, Context context, String secure) 
        throws IOException {
        IConfigStore cs = CMS.getConfigStore();

        String baseDN = "";
        String database = "";
        String dn = "";

        try {
            baseDN = cs.getString("internaldb.basedn");
            database = cs.getString("internaldb.database", "");
        } catch (Exception e) {
            CMS.debug("DatabasePanel populateDB: " + e.toString());
            throw new IOException(
                    "Failed to retrieve LDAP information from CS.cfg.");
        }

        String remove = HttpInput.getID(request, "removeData");
        LDAPConnection conn = getLocalLDAPConn(context, secure);

        // check that the database and baseDN do not exist

        boolean foundBaseDN = false;
        boolean foundDatabase = false;
        try {
            LDAPEntry entry = conn.read(baseDN);
            if (entry != null) foundBaseDN = true;
        } catch (LDAPException e) {
            switch( e.getLDAPResultCode() ) {
                case LDAPException.NO_SUCH_OBJECT:
                    break;
                default:
                    CMS.debug("DatabasePanel update: LDAPException " + e.toString());
                    throw new IOException("Failed to create the database");
            }
        }

        try {
            dn = "cn=" + database + ",cn=ldbm database, cn=plugins, cn=config";
            LDAPEntry entry = conn.read(dn);
            if (entry != null) foundDatabase = true;
        } catch (LDAPException e) {
            switch( e.getLDAPResultCode() ) {
                case LDAPException.NO_SUCH_OBJECT:
                    break;
                default:
                    CMS.debug("DatabasePanel update: LDAPException " + e.toString());
                    throw new IOException("Failed to create the database");
            }
        }
        try {
            dn = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";
            LDAPEntry entry = conn.read(dn);
            if (entry != null) foundDatabase = true;
        } catch (LDAPException e) {
            switch( e.getLDAPResultCode() ) {
                case LDAPException.NO_SUCH_OBJECT:
                    break;
                default:
                    CMS.debug("DatabasePanel update: LDAPException " + e.toString());
                    throw new IOException("Failed to create the database");
            }
        }

        if (foundDatabase) {
            CMS.debug("DatabasePanel update: This database has already been used.");
            if (remove == null) {
                throw new IOException("This database has already been used. Select the checkbox below to remove all data and reuse this database");
            }
            else {
                CMS.debug("DatabasePanel update: Deleting existing DB and reusing base DN");
                cleanupDB(conn, baseDN, database);
                foundBaseDN = false;
                foundDatabase = false;
            }
        }

        if (foundBaseDN) {
            CMS.debug("DatabasePanel update: This base DN has already been used.");
            if (remove == null) {
                throw new IOException("This base DN ("+baseDN+") has already been used. Select the checkbox below to remove all data and reuse this base DN");
            }
            else {
                CMS.debug("DatabasePanel update: Deleting existing DB and reusing base DN");
                cleanupDB(conn, baseDN, database);
                foundBaseDN = false;
                foundDatabase = false;
            }
        }

        // create database
        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            String oc[] = { "top", "extensibleObject", "nsBackendInstance"};
            attrs.add(new LDAPAttribute("objectClass", oc));
            attrs.add(new LDAPAttribute("cn", database));
            attrs.add(new LDAPAttribute("nsslapd-suffix", baseDN));
            dn = "cn=" + database + ",cn=ldbm database, cn=plugins, cn=config";
            LDAPEntry entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (Exception e) {
            CMS.debug("Warning: database creation error - " + e.toString());
            throw new IOException("Failed to create the database.");
        }

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            String oc2[] = { "top", "extensibleObject", "nsMappingTree"};
            attrs.add(new LDAPAttribute("objectClass", oc2));
            attrs.add(new LDAPAttribute("cn", baseDN));
            attrs.add(new LDAPAttribute("nsslapd-backend", database));
            attrs.add(new LDAPAttribute("nsslapd-state", "Backend"));
            dn = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";
            LDAPEntry entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (Exception e) {
            CMS.debug("Warning: database mapping tree creation error - " + e.toString());
            throw new IOException("Failed to create the database.");
        }

        try {
            // create base dn
            CMS.debug("Creating base DN: " + baseDN);
            String dns3[] = LDAPDN.explodeDN(baseDN, false);
            StringTokenizer st = new StringTokenizer(dns3[0], "=");
            String n = st.nextToken();
            String v = st.nextToken();
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            String oc3[] = { "top", "domain"};
            if (n.equals("o")) {
              oc3[1] = "organization";
            } else if (n.equals("ou")) {
              oc3[1] = "organizationalUnit";
            } 
            attrs.add(new LDAPAttribute("objectClass", oc3));
            attrs.add(new LDAPAttribute(n, v));

            LDAPEntry entry = new LDAPEntry(baseDN, attrs);
            conn.add(entry);
        } catch (Exception e) {
            CMS.debug("Warning: suffix creation error - " + e.toString());
            throw new IOException("Failed to create the base DN: "+baseDN);
        }

        // check to see if the base dn exists
        CMS.debug("DatabasePanel checking existing " + baseDN);

        try {
            LDAPEntry entry = conn.read(baseDN);

            if (entry != null) {
                foundBaseDN = true; 
            }
        } catch (LDAPException e) {}
        boolean createBaseDN = true;

        boolean testing = false;
        try {
            testing = cs.getBoolean("internaldb.multipleSuffix.enable", false);
        } catch (Exception e) {}

        if (!foundBaseDN) {
            if (!testing) {
                context.put("errorString", "Base DN was not found. Please make sure to create the suffix in the internal database.");
                throw new IOException("Base DN not found");
            }

            if (createBaseDN) {
                // only auto create if it is an ou entry
                String dns1[] = LDAPDN.explodeDN(baseDN, false);

                if (dns1 == null) {
                    throw new IOException("Invalid base DN");
                }
                if (!dns1[0].startsWith("ou")) {
                    throw new IOException(
                            "Failed to find base DN, and failed to create non ou entry.");
                }
                String dns2[] = LDAPDN.explodeDN(baseDN, true);
                // support only one level creation - create new entry
                // right under the suffix
                LDAPAttributeSet attrs = new LDAPAttributeSet();
                String oc[] = { "top", "organizationalUnit"};

                attrs.add(new LDAPAttribute("objectClass", oc));
                attrs.add(new LDAPAttribute("ou", dns2[0]));
                LDAPEntry entry = new LDAPEntry(baseDN, attrs);

                try {
                    conn.add(entry);
                    foundBaseDN = true; 
                    CMS.debug("DatabasePanel added " + baseDN);
                } catch (LDAPException e) {
                    throw new IOException("Failed to create " + baseDN);
                }
            }
        }
        if (!foundBaseDN) {
            throw new IOException("Failed to find base DN");
        }

        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        if (select.equals("clone")) {
            // if this is clone, add index before replication
            // don't put in the schema or bad things will happen
            importLDIFS("preop.internaldb.ldif", conn);
            importLDIFS("preop.internaldb.index_ldif", conn);
            importLDIFS("preop.internaldb.manager_ldif", conn);
        } else {
          // data will be replicated from the master to the clone
          // so clone does not need the data
          //

            importLDIFS("preop.internaldb.schema.ldif", conn);
            importLDIFS("preop.internaldb.ldif", conn);
            importLDIFS("preop.internaldb.data_ldif", conn);
            importLDIFS("preop.internaldb.index_ldif", conn);
            importLDIFS("preop.internaldb.manager_ldif", conn);
        }

        try {
            conn.disconnect();
        } catch (LDAPException e) {}
    }

    private void importLDIFS(String param, LDAPConnection conn) throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String v = null;

        CMS.debug("DatabasePanel populateDB param=" + param);
        try {
            v = cs.getString(param);
        } catch (EBaseException e) {  
            CMS.debug("DatabasePanel populateDB: " + e.toString());
            throw new IOException("Cant find ldif files.");
        }
 
        StringTokenizer tokenizer = new StringTokenizer(v, ",");
        String baseDN = null;
        String database = null;

        try {
            baseDN = cs.getString("internaldb.basedn");
        } catch (EBaseException e) {
            throw new IOException("internaldb.basedn is missing.");
        }

        try {
            database = cs.getString("internaldb.database");
            CMS.debug("DatabasePanel update: database=" + database);
        } catch (EBaseException e) {
            CMS.debug(
                    "DatabasePanel update: Failed to get database name. Exception: "
                            + e.toString());
            database = "userRoot";
        }

        String instancePath = null;

        try {
            instancePath = cs.getString("instanceRoot");
        } catch (EBaseException e) {
            throw new IOException("instanceRoot is missing");
        }

        String instanceId = null;

        try {
            instanceId = cs.getString("instanceId"); 
        } catch (EBaseException e) {
            throw new IOException("instanceId is missing");
        }

        String dbuser = null;
        try {
            dbuser = "uid=" + cs.getString("cs.type") + "-" + cs.getString("machineName") + "-"
                    + cs.getString("service.securePort") + ",ou=people," + baseDN;
        } catch (EBaseException e) {
            CMS.debug("Unable to construct dbuser" + e.toString());
            e.printStackTrace();
            throw new IOException("unable to construct dbuser");
        }

        String configDir = instancePath + File.separator + "conf";

        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            int index = token.lastIndexOf("/");
            String name = token;

            if (index != -1) {
                name = token.substring(index + 1);
            }

            CMS.debug("DatabasePanel importLDIFS: ldif file = " + token);
            String filename = configDir + File.separator + name;

            CMS.debug("DatabasePanel importLDIFS: ldif file copy to " + filename);
            PrintStream ps = null;
            BufferedReader in = null;

            try {
                in = new BufferedReader(new FileReader(token));
                ps = new PrintStream(new FileOutputStream(filename, false));
                while (in.ready()) {
                    String s = in.readLine();
                    int n = s.indexOf("{");

                    if (n == -1) {
                        ps.println(s);
                    } else {
                        boolean endOfline = false;

                        while (n != -1) {
                            ps.print(s.substring(0, n));
                            int n1 = s.indexOf("}");
                            String tok = s.substring(n + 1, n1);

                            if (tok.equals("instanceId")) {
                                ps.print(instanceId);
                            } else if (tok.equals("rootSuffix")) {
                                ps.print(baseDN);
                            } else if (tok.equals("database")) {
                                ps.print(database);
                            } else if (tok.equals("dbuser")) {
                                ps.print(dbuser);
                            }
                            if ((s.length() + 1) == n1) {
                                endOfline = true;
                                break;
                            }
                            s = s.substring(n1 + 1);
                            n = s.indexOf("{");
                        }

                        if (!endOfline) {
                            ps.println(s);
                        }
                    } 
                }
                in.close();
                ps.close();
            } catch (Exception e) { 
                CMS.debug("DBSubsystem popuateDB: " + e.toString());
                throw new IOException(
                        "Problem of copying ldif file: " + filename);
            }
            ArrayList<String> errors = new ArrayList<String>();
            LDAPUtil.importLDIF(conn, filename, errors);
            if (! errors.isEmpty()) {
                CMS.debug("DatabasePanel: importLDIFS: LDAP Errors in importing " + filename);
                for (String error: errors) {
                    CMS.debug(error);
                }
            }
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore cs = CMS.getConfigStore();
	boolean hasErr = false;

        boolean firsttime = false;
        context.put("firsttime", "false");
        try {
            @SuppressWarnings("unused")
            String s = cs.getString("preop.database.removeData"); // check whether it's first time
        } catch (Exception e) {
            context.put("firsttime", "true");
            firsttime = true;
        }

        String hostname1 = "";
        String portStr1 = "";
        String database1 = "";
        String basedn1 = "";

        try {
            hostname1 = cs.getString("internaldb.ldapconn.host", "");
            portStr1 = cs.getString("internaldb.ldapconn.port", "");
            database1 = cs.getString("internaldb.database", "");
            basedn1 = cs.getString("internaldb.basedn", "");
        } catch (Exception e) {
        }

        String hostname2 = HttpInput.getHostname(request, "host");
        String portStr2 = HttpInput.getPortNumber(request, "port");
        String database2 = HttpInput.getLdapDatabase(request, "database");
        String basedn2 = HttpInput.getDN(request, "basedn");

        cs.putString("internaldb.ldapconn.host", hostname2);
        cs.putString("internaldb.ldapconn.port", portStr2);
        cs.putString("internaldb.basedn", basedn2);
        String binddn = HttpInput.getDN(request, "binddn");
        cs.putString("internaldb.ldapauth.bindDN", binddn);
        cs.putString("internaldb.database", database2);
        String secure = HttpInput.getCheckbox(request, "secureConn");
        cs.putString("internaldb.ldapconn.secureConn", (secure.equals("on")?"true":"false"));
        String cloneStartTLS = HttpInput.getCheckbox(request, "cloneStartTLS");
        cs.putString("internaldb.ldapconn.cloneStartTLS", (cloneStartTLS.equals("on")?"true":"false"));

        String remove = HttpInput.getID(request, "removeData");
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
            populateDB(request, context, (secure.equals("on")?"true":"false"));
        } catch (IOException e) {
            CMS.debug("DatabasePanel update: populateDB Exception: "+e.toString());
            context.put("updateStatus", "failure");
            throw e;
        } catch (Exception e) {
            CMS.debug("DatabasePanel update: populateDB Exception: "+e.toString());
            context.put("errorString", e.toString());
            cs.putString("preop.database.errorString", e.toString());
            context.put("updateStatus", "failure");
            throw new IOException(e.toString());
        }

        String bindpwd = HttpInput.getPassword(request, "__bindpwd");

        /* BZ 430745 create password for replication manager */
        String replicationpwd = Integer.toString(new Random().nextInt());

        IConfigStore psStore = null;
        String passwordFile = null;

        try {
            passwordFile = cs.getString("passwordFile");
            psStore = CMS.createFileConfigStore(passwordFile);
        } catch (Exception e) {
            CMS.debug("ConfigDatabaseServlet update: " + e.toString());
            context.put("updateStatus", "failure");
            throw new IOException( e.toString() );
        }
        psStore.putString("internaldb", bindpwd);
        psStore.putString("replicationdb", replicationpwd);
        cs.putString("preop.internaldb.replicationpwd" , replicationpwd);
        cs.putString("preop.database.removeData", "false");

        try {
            cs.commit(false);
            psStore.commit(false);
            CMS.reinit(IDBSubsystem.SUB_ID);
            String type = cs.getString("cs.type", "");
            if (type.equals("CA"))
                CMS.reinit(ICertificateAuthority.ID);
            CMS.reinit(IAuthSubsystem.ID);
            CMS.reinit(IAuthzSubsystem.ID);
            CMS.reinit(IUGSubsystem.ID);
        } catch (Exception e) {
            CMS.debug("DatabasePanel update: " + e.toString());
            context.put("errorString", e.toString());
            cs.putString("preop.database.errorString", e.toString());
            context.put("updateStatus", "failure");
            throw new IOException(e.toString());
        }

        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }

        // always populate the index the last
        try {
          CMS.debug("Populating local indexes");
          LDAPConnection conn = getLocalLDAPConn(context, 
                            (secure.equals("on")?"true":"false"));
          importLDIFS("preop.internaldb.post_ldif", conn);

          /* For vlvtask, we need to check if the task has 
             been completed or not.  Presence of nsTaskExitCode means task is complete
           */
          String wait_dn = cs.getString("preop.internaldb.wait_dn", "");
          if (!wait_dn.equals("")) {
            int i = 0;
            LDAPEntry task = null;
            boolean taskComplete = false;
            CMS.debug("Checking wait_dn " + wait_dn);
            do {
              Thread.sleep(1000);
              try {
                task = conn.read(wait_dn, (String[])null);
                if (task != null) {
                   LDAPAttribute attr = task.getAttribute("nsTaskExitCode");
                   if (attr != null) {
                       taskComplete = true;
                       String val = (String) attr.getStringValues().nextElement();
                       if (val.compareTo("0") != 0) {
                           CMS.debug("Error in populating local indexes: nsTaskExitCode=" + val);
                       } 
                   } 
                }
              } catch (LDAPException le) {
                CMS.debug("Still checking wait_dn '" + wait_dn + "' (" + le.toString() + ")");
              } catch (Exception e) {
                CMS.debug("Still checking wait_dn '" + wait_dn + "' (" + e.toString() + ").");
              }
            } while ((!taskComplete) && (i < 20));
            if (i < 20) {
              CMS.debug("Done checking wait_dn " + wait_dn);
            } else {
              CMS.debug("Done checking wait_dn " + wait_dn + " due to timeout.");
            }
          }

          conn.disconnect();
          CMS.debug("Done populating local indexes");
        } catch (Exception e) {
          CMS.debug("Populating index failure - " + e);
        }

        // setup replication after indexes have been created
        if (select.equals("clone")) {
            CMS.debug("Start setting up replication.");
            setupReplication(request, context, (secure.equals("on")?"true":"false"), (cloneStartTLS.equals("on")?"true":"false"));
            CMS.debug("Finish setting up replication.");

            try {
                CMS.reinit(IDBSubsystem.SUB_ID);
                String type = cs.getString("cs.type", "");
                if (type.equals("CA"))
                    CMS.reinit(ICertificateAuthority.ID);
                CMS.reinit(IAuthSubsystem.ID);
                CMS.reinit(IAuthzSubsystem.ID);
                CMS.reinit(IUGSubsystem.ID);
            } catch (Exception e) {
            }
        }


        if (hasErr == false) {
          cs.putBoolean("preop.Database.done", true);
          try {
            cs.commit(false);
          } catch (EBaseException e) { 
            CMS.debug(
                  "DatabasePanel: update() Exception caught at config commit: "
                            + e.toString());
	  }
	}
        context.put("updateStatus", "success");
    }

    private void setupReplication(HttpServletRequest request,
                  Context context, String secure, String cloneStartTLS) throws IOException {
        IConfigStore cs = CMS.getConfigStore();
 
        String cstype = "";
        String machinename = "";
        String instanceId = "";
        try {
            cstype = cs.getString("cs.type");
            cstype = toLowerCaseSubsystemType(cstype);
            machinename = cs.getString("machineName", "");
            instanceId = cs.getString("instanceId", "");
        } catch (Exception e) {
        }


        //setup replication agreement
        String masterAgreementName = "masterAgreement1-"+machinename+"-"+instanceId;
        cs.putString("internaldb.replication.master", masterAgreementName);
        String cloneAgreementName = "cloneAgreement1-"+machinename+"-"+instanceId;
        cs.putString("internaldb.replication.consumer", cloneAgreementName);
 
        try {
            cs.commit(false);
        } catch (Exception e) {
        }

        // get connection to master
        LDAPConnection masterConn = null;
        ILdapConnFactory masterFactory = null;
        try {
            IConfigStore masterCfg = cs.getSubStore("preop.internaldb.master");
            masterFactory = CMS.getLdapBoundConnFactory();
            masterFactory.init(masterCfg);
            masterConn = masterFactory.getConn();
        } catch (Exception e) {
            CMS.debug("Failed to set up connection to master:" + e.toString());
            e.printStackTrace();
            throw new IOException("Failed to set up replication: No connection to master");
        }

        // get connection to replica
        LDAPConnection replicaConn = null;
        ILdapConnFactory replicaFactory = null;
        try {
            IConfigStore replicaCfg = cs.getSubStore("internaldb");
            replicaFactory = CMS.getLdapBoundConnFactory();
            replicaFactory.init(replicaCfg);
            replicaConn = replicaFactory.getConn();
        } catch (Exception e) {
            CMS.debug("Failed to set up connection to replica:" + e.toString());
            e.printStackTrace();
            throw new IOException("Failed to set up replication: No connection to replica");
        }

        String master_hostname = "";
        int master_port = -1;
        String master_replicationpwd = "";
        String replica_hostname = "";
        int replica_port = -1;
        String replica_replicationpwd = "";

        try {
            master_hostname = cs.getString("preop.internaldb.master.ldapconn.host", "");
            master_port = cs.getInteger("preop.internaldb.master.ldapconn.port", -1);
            master_replicationpwd = cs.getString("preop.internaldb.master.replication.password", "");
            replica_hostname = cs.getString("internaldb.ldapconn.host", "");
            replica_port = cs.getInteger("internaldb.ldapconn.port", -1);
            replica_replicationpwd = cs.getString("preop.internaldb.replicationpwd", "");
        } catch (Exception e) {
        }

        String basedn = "";
        try {
            basedn = cs.getString("internaldb.basedn");
        } catch (Exception e) {
        }

        try {
            String suffix = cs.getString("internaldb.basedn", "");

            String replicadn = "cn=replica,cn=\""+suffix+"\",cn=mapping tree,cn=config";
            CMS.debug("DatabasePanel setupReplication: replicadn="+replicadn);

            String masterBindUser = "Replication Manager " + masterAgreementName;
            String cloneBindUser = "Replication Manager " + cloneAgreementName;

            createReplicationManager(masterConn, masterBindUser, master_replicationpwd);
            createReplicationManager(replicaConn, cloneBindUser, replica_replicationpwd);

            String dir1 = getInstanceDir(masterConn);
            createChangeLog(masterConn, dir1 + "/changelogs");

            String dir2 = getInstanceDir(replicaConn);
            createChangeLog(replicaConn, dir2 + "/changelogs");

            int replicaId = cs.getInteger("dbs.beginReplicaNumber", 1);

            replicaId = enableReplication(replicadn, masterConn, masterBindUser, basedn, replicaId);
            replicaId = enableReplication(replicadn, replicaConn, cloneBindUser, basedn, replicaId);
            cs.putString("dbs.beginReplicaNumber", Integer.toString(replicaId));

            CMS.debug("DatabasePanel setupReplication: Finished enabling replication");
 
            createReplicationAgreement(replicadn, masterConn, masterAgreementName,
                    replica_hostname, replica_port, replica_replicationpwd, basedn, cloneBindUser, secure,
                    cloneStartTLS);

            createReplicationAgreement(replicadn, replicaConn, cloneAgreementName,
                    master_hostname, master_port, master_replicationpwd, basedn, masterBindUser, secure,
                    cloneStartTLS);

            // initialize consumer
            initializeConsumer(replicadn, masterConn, masterAgreementName);

            while (!replicationDone(replicadn, masterConn, masterAgreementName)) {
                CMS.debug("DatabasePanel setupReplication: Waiting for replication to complete");
                Thread.sleep(1000);
            }

            String status = replicationStatus(replicadn, masterConn, masterAgreementName);
            if (!status.startsWith("0 ")) {
                CMS.debug("DatabasePanel setupReplication: consumer initialization failed. " +
                    status);
                throw new IOException("consumer initialization failed. " + status);
            } 

            // remove master ldap password from password.conf (if present)
            String passwordFile = cs.getString("passwordFile");
            IConfigStore psStore = CMS.createFileConfigStore(passwordFile);
            psStore.remove("master_internaldb");
            psStore.commit(false);

        } catch (Exception e) {
            CMS.debug("DatabasePanel setupReplication: "+e.toString());
            throw new IOException("Failed to setup the replication for cloning.");
        }
    }

    /**
     * If validiate() returns false, this method will be called.
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

    private boolean isAgreementExist(String replicadn, LDAPConnection conn,
      String name) {
        String dn = "cn="+name+","+replicadn;
        String filter = "(cn="+name+")";
        String[] attrs = {"cn"};
        try {
            LDAPSearchResults results = conn.search(dn, LDAPv3.SCOPE_SUB,
              filter, attrs, false);
            while (results.hasMoreElements())
                return true; 
        } catch (LDAPException e) {
            return false;
        }

        return false;
    }

    private void createReplicationManager(LDAPConnection conn, String bindUser, String pwd)
      throws LDAPException {
        LDAPAttributeSet attrs = null;
        LDAPEntry entry = null;
        String dn = "cn=" + bindUser + ",ou=csusers,cn=config";
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "person"));
            attrs.add(new LDAPAttribute("userpassword", pwd));
            attrs.add(new LDAPAttribute("cn", bindUser));
            attrs.add(new LDAPAttribute("sn", "manager"));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("DatabasePanel createReplicationManager: Replication Manager has already used");
                try {
                    conn.delete(dn);
                    conn.add(entry);
                } catch (LDAPException ee) {
                    CMS.debug("DatabasePanel createReplicationManager: "+ee.toString());
                }
                return;
            } else {
                CMS.debug("DatabasePanel createReplicationManager: Failed to create replication manager. Exception: "+e.toString());
                throw e;
            }
        }

        CMS.debug("DatabasePanel createReplicationManager: Successfully created Replication Manager");
    }

    private void createChangeLog(LDAPConnection conn, String dir)
      throws LDAPException {
        LDAPAttributeSet attrs = null;
        LDAPEntry entry = null;
        String dn = "cn=changelog5,cn=config";
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "extensibleObject"));
            attrs.add(new LDAPAttribute("cn", "changelog5"));
            attrs.add(new LDAPAttribute("nsslapd-changelogdir", dir));
            entry = new LDAPEntry("cn=changelog5,cn=config", attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("DatabasePanel createChangeLog: Changelog entry has already used");
/* leave it, dont delete it because it will have operation error
                try {
                    conn.delete(dn);
                    conn.add(entry);
                } catch (LDAPException ee) {
                    CMS.debug("DatabasePanel createChangeLog: "+ee.toString());
                }
*/
                return;
            } else {
                CMS.debug("DatabasePanel createChangeLog: Failed to create changelog entry. Exception: "+e.toString());
                throw e;
            }
        }

        CMS.debug("DatabasePanel createChangeLog: Successfully create change log entry");
    }

    private int enableReplication(String replicadn, LDAPConnection conn, String bindUser, String basedn, int id)
      throws LDAPException {
        CMS.debug("DatabasePanel enableReplication: replicadn: "+replicadn);
        LDAPAttributeSet attrs = null;
        LDAPEntry entry = null;
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "nsDS5Replica"));
            attrs.add(new LDAPAttribute("objectclass", "extensibleobject"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", basedn));
            attrs.add(new LDAPAttribute("nsDS5ReplicaType", "3"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN",
                    "cn=" + bindUser + ",ou=csusers,cn=config"));
            attrs.add(new LDAPAttribute("cn", "replica"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaId", Integer.toString(id)));
            attrs.add(new LDAPAttribute("nsds5flags", "1"));
            entry = new LDAPEntry(replicadn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                /* BZ 470918 -we cant just add the new dn.  We need to do a replace instead 
                 * until the DS code is fixed */
                CMS.debug("DatabasePanel enableReplication: "+replicadn+" has already been used");
                
                try {
                    entry = conn.read(replicadn);
                    LDAPAttribute attr = entry.getAttribute("nsDS5ReplicaBindDN");
                    attr.addValue("cn=" + bindUser + ",ou=csusers,cn=config");
                    LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);
                    conn.modify(replicadn, mod);
                } catch (LDAPException ee) {
                    CMS.debug("DatabasePanel enableReplication: Failed to modify " 
                        +replicadn+" entry. Exception: "+e.toString());
                }
                return id;
            } else {
                CMS.debug("DatabasePanel enableReplication: Failed to create "+replicadn+" entry. Exception: "+e.toString());
                return id;
            }
        }

        CMS.debug("DatabasePanel enableReplication: Successfully create "+replicadn+" entry.");
        return id + 1;
    }

    private void createReplicationAgreement(String replicadn, 
      LDAPConnection conn, String name, String replicahost, int replicaport, 
      String replicapwd, String basedn, String bindUser, String secure, String cloneStartTLS) throws LDAPException {
        String dn = "cn="+name+","+replicadn;
        CMS.debug("DatabasePanel createReplicationAgreement: dn: "+dn);
        LDAPEntry entry = null;
        LDAPAttributeSet attrs = null;
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass",
              "nsds5replicationagreement"));
            attrs.add(new LDAPAttribute("cn", name));
            attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", basedn));
            attrs.add(new LDAPAttribute("nsDS5ReplicaHost", replicahost));
            attrs.add(new LDAPAttribute("nsDS5ReplicaPort", ""+replicaport));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN",
                    "cn=" + bindUser + ",ou=csusers,cn=config"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindMethod", "Simple"));
            attrs.add(new LDAPAttribute("nsds5replicacredentials", replicapwd));

            if (secure.equals("true")) {
                attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", "SSL"));
            } else if (cloneStartTLS.equals("true")) {
                attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", "TLS"));
            }

            CMS.debug("About to set description attr to " + name);
            attrs.add(new LDAPAttribute("description",name));

            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("DatabasePanel createReplicationAgreement: "+dn+" has already used");
                try {
                    conn.delete(dn);
                } catch (LDAPException ee) {
                    CMS.debug("DatabasePanel createReplicationAgreement: "+ee.toString());
                    throw ee;
                }

                try {
                    conn.add(entry);
                } catch (LDAPException ee) {
                    CMS.debug("DatabasePanel createReplicationAgreement: "+ee.toString());
                    throw ee;
                }
            } else {
                CMS.debug("DatabasePanel createReplicationAgreement: Failed to create "+dn+" entry. Exception: "+e.toString());
                throw e;
            }
        }

        CMS.debug("DatabasePanel createReplicationAgreement: Successfully create replication agreement "+name);
    }

    private void initializeConsumer(String replicadn, LDAPConnection conn, 
      String name) {
        String dn = "cn="+name+","+replicadn;
        CMS.debug("DatabasePanel initializeConsumer: initializeConsumer dn: "+dn);
        CMS.debug("DatabasePanel initializeConsumer: initializeConsumer host: "+conn.getHost() + " port: " + conn.getPort());
        try {
            LDAPAttribute attr = new LDAPAttribute("nsds5beginreplicarefresh",
              "start");
            LDAPModification mod = new LDAPModification(
              LDAPModification.REPLACE, attr);
            CMS.debug("DatabasePanel initializeConsumer: start modifying");
            conn.modify(dn, mod);
            CMS.debug("DatabasePanel initializeConsumer: Finish modification.");
        } catch (LDAPException e) {
            CMS.debug("DatabasePanel initializeConsumer: Failed to modify "+dn+" entry. Exception: "+e.toString());
            return;
        } catch (Exception e) {
            CMS.debug("DatabasePanel initializeConsumer: exception " + e);
        }

        try {
            CMS.debug("DatabasePanel initializeConsumer: thread sleeping for 5 seconds.");
            Thread.sleep(5000);
            CMS.debug("DatabasePanel initializeConsumer: finish sleeping.");
        } catch (InterruptedException ee) {
            CMS.debug("DatabasePanel initializeConsumer: exception: "+ee.toString());
        }

        CMS.debug("DatabasePanel initializeConsumer: Successfully initialize consumer");
    }

    private boolean replicationDone(String replicadn, LDAPConnection conn, String name) 
      throws IOException {
        String dn = "cn="+name+","+replicadn;
        String filter = "(objectclass=*)";
        String[] attrs = {"nsds5beginreplicarefresh"};

        CMS.debug("DatabasePanel replicationDone: dn: "+dn);
        try {
            LDAPSearchResults results = conn.search(dn, LDAPConnection.SCOPE_BASE, filter,
              attrs, true);

            int count = results.getCount();
            if (count < 1) {
                throw new IOException("Replication entry not found");
            } 
           
            LDAPEntry entry = results.next();
            LDAPAttribute refresh = entry.getAttribute("nsds5beginreplicarefresh");
            if (refresh == null) {
                return true;
            } 
            return false;
        } catch (Exception e) {
            CMS.debug("DatabasePanel replicationDone: exception " + e);
            throw new IOException("Exception in replicationDone: " + e);
        }
    }

    private String replicationStatus(String replicadn, LDAPConnection conn, String name) 
      throws IOException {
        String dn = "cn="+name+","+replicadn;
        String filter = "(objectclass=*)";
        String[] attrs = {"nsds5replicalastinitstatus"};
        String status = null;

        CMS.debug("DatabasePanel replicationStatus: dn: "+dn);
        try {
            LDAPSearchResults results = conn.search(dn, LDAPConnection.SCOPE_BASE, filter,
              attrs, false);

            int count = results.getCount();
            if (count < 1) {
                throw new IOException("Replication entry not found");
            } 

            LDAPEntry entry = results.next();
            LDAPAttribute attr = entry.getAttribute("nsds5replicalastinitstatus");
            if (attr != null) {
                Enumeration valsInAttr = attr.getStringValues();
                if (valsInAttr.hasMoreElements()) {
                    return  (String)valsInAttr.nextElement();
                } else {
                    throw new IOException("No value returned for nsds5replicalastinitstatus");
                }
            } else {
                throw new IOException("nsDS5ReplicaLastInitStatus is null.");
            }
        } catch (Exception e) {
            CMS.debug("DatabasePanel replicationStatus: exception " + e);
            throw new IOException("Exception in replicationStatus: " + e);
        }
    }

    private String getInstanceDir(LDAPConnection conn) {
        String instancedir="";
        try {
            String filter = "(objectclass=*)";
            String[] attrs = {"nsslapd-directory"};
            LDAPSearchResults results = conn.search("cn=config,cn=ldbm database,cn=plugins,cn=config", LDAPv3.SCOPE_SUB,
              filter, attrs, false);

            while (results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                String dn = entry.getDN();
                CMS.debug("DatabasePanel getInstanceDir: DN for storing nsslapd-directory: "+dn);
                LDAPAttributeSet entryAttrs = entry.getAttributeSet();
                Enumeration attrsInSet = entryAttrs.getAttributes();
                while (attrsInSet.hasMoreElements()) {
                    LDAPAttribute nextAttr = (LDAPAttribute)attrsInSet.nextElement();
                    String attrName = nextAttr.getName();
                    CMS.debug("DatabasePanel getInstanceDir: attribute name: "+attrName);
                    Enumeration valsInAttr = nextAttr.getStringValues();
                    while ( valsInAttr.hasMoreElements() ) {
                        String nextValue = (String)valsInAttr.nextElement();
                        if (attrName.equalsIgnoreCase("nsslapd-directory")) {
                            CMS.debug("DatabasePanel getInstanceDir: instanceDir="+nextValue);
                            return nextValue.substring(0,nextValue.lastIndexOf("/db"));
                        }
                    }
                }
            }
        } catch (LDAPException e) {
            CMS.debug("DatabasePanel getInstanceDir: Error in retrieving the instance directory. Exception: "+e.toString());
        }

        return instancedir;
    }
}
