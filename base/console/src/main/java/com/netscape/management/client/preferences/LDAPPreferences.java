/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.preferences;

import java.io.*;
import netscape.ldap.*;
import com.netscape.management.client.util.*;

/**
 * A type of Preferences object that allows values
 * to be persistantly stored in an LDAP data source.
 *
 * @author  ahakim@netscape.com
 * @see Preferences
 */
public class LDAPPreferences extends Preferences {
    private static String _attribute = "nsPreference";
    private LDAPConnection _ldc;
    private String _dn;
    private String _group;

    public LDAPPreferences(LDAPConnection ldc, String group, String dn) {
        _ldc = ldc;
        _group = group;
        _dn = createPreferenceEntry(_ldc, group, dn);
    }

    public LDAPPreferences(String host, int port, String username,
            String password, String group, String dn) throws LDAPException {
        LDAPConnection ldc = new LDAPConnection();
        ldc.connect(host, port);
        ldc.authenticate(username, password);
        _ldc = ldc;
        _group = group;
        _dn = createPreferenceEntry(_ldc, group, dn);
    }

    public String toString() {
        return _group + ":" + super.toString();
    }

    public String getDN() {
        return _dn;
    }

    public void setDN(String dn) {
        _dn = dn;
    }

    protected InputStream getInputStream() {
        return new LDAPInputStream(_ldc, _dn, _attribute);
    }

    protected OutputStream getOutputStream() {
        return new LDAPOutputStream(_ldc, _dn, _attribute);
    }

    public void clear() {
        super.clear();
    }

    public void delete() {
        try {
            OutputStream out = getOutputStream();
            ((LDAPOutputStream) out).delete();
        } catch (LDAPException e) {
            Debug.println("Cannot delete preferences: " + e);
        }
    }

    static public String createPreferenceEntry(LDAPConnection ldc,
            String entry, String dn) {
        String newDN = "cn=" + entry + "," + dn;
        LDAPSearchResults searchResults = null;
        try {
            // TODO: minor optimization: set search attrs to "dn", from rweltman
            // FYI: read() calls search()
            searchResults =
                    ldc.search(newDN, LDAPConnection.SCOPE_SUB, "(objectclass=*)",
                    null, false);
        } catch (LDAPException e) {
            Debug.println("Cannot find: " + newDN);
            Debug.println("Creating: " + newDN);
            if (searchResults == null)
                try {
                    LDAPAttribute attr1 = new LDAPAttribute("cn", entry);
                    LDAPAttribute attr2 =
                            new LDAPAttribute("objectclass", "top");
                    LDAPAttribute attr3 =
                            new LDAPAttribute("objectclass", "nsAdminConsoleUser");
                    LDAPAttributeSet attrs = new LDAPAttributeSet();
                    attrs.add(attr1);
                    attrs.add(attr2);
                    attrs.add(attr3);
                    ldc.add(new LDAPEntry(newDN, attrs));
                } catch (LDAPException exception) {
                    Debug.println("Cannot create: " + newDN);
                }
        }
        return newDN;
    }

    public static void main(String argv[]) {
        try {
            String dn = "ou=UserPreferences, ou=Netscape SuiteSpot, o=NetscapeRoot";
            Preferences p =
                    new LDAPPreferences("localhost", 389, "cn=Directory Manager",
                    "adminadmin", "testgroup", dn);
            int i = p.getInt("integer", 0);
            Debug.println("read: " + i);
            boolean b = p.getBoolean("boolean");
            Debug.println("read: " + b);
            String s = p.getString("string", "A long string of a's...");
            Debug.println("read: " + s);

            p.set("integer", ++i);
            p.set("boolean", !b);
            p.set("string", s + "a");
            p.save();

            // uncomment to test clear functionality
            //p.clear();
            //System.out.println("clear");
        } catch (LDAPException e) {
            Debug.println("Unable to connect to ldap host");
        }

        System.exit(0);
    }
}
