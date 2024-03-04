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

import java.util.*;
import netscape.ldap.*;
import com.netscape.management.client.util.*;

/**
 * A PreferenceManager that reads and writes preference
 * data from an LDAP data source.
 *
 * @author  ahakim@netscape.com
 * @see PreferenceManager
 */
public class LDAPPreferenceManager extends PreferenceManager {
    private Hashtable _prefTable = new Hashtable();
    private LDAPConnection _ldc;
    private String _baseName;

    public LDAPPreferenceManager(LDAPConnection ldc, String dn,
            String product, String version) {
        super(product, version);
        _ldc = ldc;
        dn = LDAPUtil.createEntry(ldc, product, dn);
        _baseName = LDAPUtil.createEntry(ldc, version, dn);
    }

    public String getBaseName() {
        return _baseName;
    }

    public String[] getPreferencesList() {
        String filter = "(objectclass=*)";
        String[] attrs = { "nsPreference" };
        LDAPSearchResults results = null;
        Vector v = new Vector();

        try {
            results = _ldc.search(_baseName, LDAPConnection.SCOPE_ONE ,
                    filter, attrs, false);
            while (results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                String nextDN = entry.getDN();
                // nextDN should be this format: cn=xxxx,....
                StringTokenizer st = new StringTokenizer(nextDN, "=,");
                if (st.hasMoreTokens()) {
                    String cn = st.nextToken(); // discard cn=
                    String group = st.nextToken(); // discard cn=
                    if (group != null)
                        v.addElement(group);
                }
            }
        } catch (LDAPException e) {
            int errCode = e.getLDAPResultCode();
            System.err.println("LDAPException: return code:" + errCode);
        }

        String s[] = new String[v.size()];
        v.copyInto(s);
        return s;
    }

    public Preferences getPreferences(String group) {
        Preferences p = (Preferences)_prefTable.get(group);
        if (p == null) {
            p = new LDAPPreferences(_ldc, group, _baseName);
            _prefTable.put(group, p);
        }
        return p;
    }

    public boolean isPreferencesDirty() {
        Enumeration e = _prefTable.elements();
        while (e.hasMoreElements()) {
            Preferences p = (Preferences) e.nextElement();
            if (p.isDirty())
                return true;
        }
        return false;
    }

    public void savePreferences() {
        Enumeration e = _prefTable.elements();
        while (e.hasMoreElements()) {
            Preferences p = (Preferences) e.nextElement();
            p.save();
        }
    }
}
