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
// (C) 2008 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

import com.netscape.cmsutil.xml.*;
import com.netscape.cmscore.base.*;
import com.netscape.cmscore.ldapconn.*;
import com.netscape.cmsutil.ldap.*;
import netscape.ldap.*;
import java.io.*; 
import java.util.*;
import org.w3c.dom.*;
import java.util.ArrayList;

public class MigrateSecurityDomain {

    private static LDAPConnection getLDAPConn(FileConfigStore cs, String passwd)
            throws IOException
    {

        String host = "";
        String port = "";
        String binddn = "";
        String security = "";

        try {
            host = cs.getString("internaldb.ldapconn.host");
            port = cs.getString("internaldb.ldapconn.port");
            binddn = cs.getString("internaldb.ldapauth.bindDN");
            security = cs.getString("internaldb.ldapconn.secureConn");
        } catch (Exception e) {
            System.out.println("MigrateSecurityDomain: getLDAPConnection" + e.toString());
            throw new IOException(
                    "Failed to retrieve LDAP information from CS.cfg.");
        }

        int p = -1;

        try {
            p = Integer.parseInt(port);
        } catch (Exception e) {
            System.out.println("MigrateSecurityDomain getLDAPConn: " + e.toString());
            throw new IOException("Port is not valid");
        }

        LDAPConnection conn = null;
        if (security.equals("true")) {
          System.out.println("MigrateSecurityDomain getLDAPConn: creating secure (SSL) connection for internal ldap");
          conn = new LDAPConnection(new LdapJssSSLSocketFactory());
        } else {
          System.out.println("MigrateSecurityDomain getLDAPConn: creating non-secure (non-SSL) connection for internal ldap");
          conn = new LDAPConnection();
        }

        System.out.println("MigrateSecurityDomain connecting to " + host + ":" + p);
        try {
            conn.connect(host, p, binddn, passwd);
        } catch (LDAPException e) {
            System.out.println("MigrateSecurityDomain getLDAPConn: " + e.toString());
            throw new IOException("Failed to connect to the internal database.");
        }

      return conn;
    }


    public static void main(String args[]) throws Exception
    {
        if (args.length != 2) {
             System.out.println("Usage: MigrateSecurityDomain <instance root path> <directory manager password>");
             System.exit(0);
        }

        String instRoot = args[0];
        String dmPass = args[1];

        XMLObject parser = null;
        // get the security domain data from the domain.xml file
        try {
            String path = instRoot + "/conf/domain.xml";
            System.out.println("MigrateSecurityDomain: Reading domain.xml from file ...");
            parser = new XMLObject(new FileInputStream(path));

        }
        catch (Exception e) {
            System.out.println("MigrateSecurityDomain: Unable to get domain info from domain.xml file");
            System.out.println(e.toString());
            System.exit(1);
        }

        try {
            String configFile = instRoot + "/conf/CS.cfg";
            FileConfigStore cs = new FileConfigStore(configFile);
            
            LDAPConnection conn = null;
            conn = MigrateSecurityDomain.getLDAPConn(cs, dmPass);
            if (conn == null) {
                System.out.println("MigrateSecurityDomain: Failed to connect to internal database");
                System.exit(1);
            } 

            // add new schema elements
            String importFile = "./schema-add.ldif";
            ArrayList<String> errors = new ArrayList<String>();
            try {
                LDAPUtil.importLDIF(conn, importFile, errors);
                if (! errors.isEmpty()) {
                    System.out.println("MigrateSecurityDomain: Errors in adding new schema elements:");
                    for (String error: errors) {
                        System.out.println(error);
                    }
                }
            } catch (Exception e) {
               System.out.println("MigrateSecurityDomain: Error in adding new schema elements");
               System.exit(1);
            }
            // create the containers
            String basedn = cs.getString("internaldb.basedn");
            String secdomain = parser.getValue("Name");

            try {
                String dn = "ou=Security Domain," + basedn;
                System.out.println("MigrateSecurityDomain: creating ldap entry : " + dn);

                LDAPEntry entry = null;
                LDAPAttributeSet attrs = null;
                attrs = new LDAPAttributeSet();
                attrs.add(new LDAPAttribute("objectclass", "top"));
                attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
                attrs.add(new LDAPAttribute("name",  secdomain));
                attrs.add(new LDAPAttribute("ou", "Security Domain"));
                entry = new LDAPEntry(dn, attrs);
                conn.add(entry);
            } catch (LDAPException e) {
                if (e.getLDAPResultCode() != 68) {
                    System.out.println("Unable to create security domain" + e.toString());
                    System.exit(1);
                }
            }

            // create list containers
            String clist[] = {"CAList", "OCSPList", "KRAList", "RAList", "TKSList", "TPSList"};
            for (int i=0; i< 6; i++) {
                LDAPEntry entry = null;
                LDAPAttributeSet attrs = null;
                String dn = "cn=" + clist[i] + ",ou=Security Domain," + basedn;
                attrs = new LDAPAttributeSet();
                attrs.add(new LDAPAttribute("objectclass", "top"));
                attrs.add(new LDAPAttribute("objectclass", "pkiSecurityGroup"));
                attrs.add(new LDAPAttribute("cn", clist[i]));
                entry = new LDAPEntry(dn, attrs);
                try {
                    conn.add(entry);
                } catch (LDAPException e) {
                    if (e.getLDAPResultCode() != 68) {
                        System.out.println("Unable to create security domain list entry " + dn +": "+ e.toString());
                        System.exit(1);
                    }
                }
            }

            // create system entries 
            String tlist[] = {"CA", "OCSP", "KRA", "RA", "TKS", "TPS"};
            Document doc = parser.getDocument();
            for (int j=0; j<6; j++) {
                String type = tlist[j];
                NodeList nodeList = doc.getElementsByTagName(type);
                int len = nodeList.getLength();
                for (int i = 0; i < len; i++) {
                    Vector v_clone = parser.getValuesFromContainer(nodeList.item(i), "Clone");
                    Vector v_name = parser.getValuesFromContainer(nodeList.item(i), "SubsystemName");
                    Vector v_host = parser.getValuesFromContainer(nodeList.item(i), "Host");
                    Vector v_port = parser.getValuesFromContainer(nodeList.item(i), "SecurePort");

                    String cn = (String)v_host.elementAt(0) + ":" + (String)v_port.elementAt(0);
                    String dn = "cn=" + cn + ",cn=" + type +"List,ou=Security Domain," + basedn;
                    LDAPEntry entry = null;
                    LDAPAttributeSet attrs = null;
                    attrs = new LDAPAttributeSet();
                    attrs.add(new LDAPAttribute("objectclass", "top"));
                    attrs.add(new LDAPAttribute("objectclass", "pkiSubsystem"));
                    attrs.add(new LDAPAttribute("Host", (String)v_host.elementAt(0)));
                    attrs.add(new LDAPAttribute("SecurePort", (String)v_port.elementAt(0)));
                    attrs.add(new LDAPAttribute("Clone", (String)v_clone.elementAt(0)));
                    attrs.add(new LDAPAttribute("SubsystemName", (String)v_name.elementAt(0)));
                    attrs.add(new LDAPAttribute("cn", cn));
                    attrs.add(new LDAPAttribute("DomainManager", "true"));
                    // Since the initial port separation feature didn't occur
                    // until an RHCS 7.3 errata, simply store the "SecurePort"
                    // value for BOTH the "SecureAgentPort" and the
                    // "SecureAdminPort", and DON'T store any values for the
                    // "UnSecurePort"
                    attrs.add(new LDAPAttribute("SecureAgentPort", (String)v_port.elementAt(0)));
                    attrs.add(new LDAPAttribute("SecureAdminPort", (String)v_port.elementAt(0)));
                    entry = new LDAPEntry(dn, attrs);

                    try {
                        conn.add(entry);
                    }
                    catch (LDAPException e) {
                        if (e.getLDAPResultCode() != 68) {
                            System.out.println("Unable to create entry " + dn +": "+ e.toString());
                        }
                    }
                }
            }
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);
            System.out.println("MigrateSecurityDomain: Domain successfully migrated.");
        } catch (Exception e) {
            System.out.println("MigrateSecurityDomain: Migration failed. " + e.toString());
        }
        System.exit(0);
    }

}
