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
package com.netscape.cmscore.dbs;


import java.util.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;


/**
 * A class represents ann attribute mapper that maps
 * a Java String object into LDAP attribute,
 * and vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$ 
 */
public class StringVectorMapper implements IDBAttrMapper {

    private String mLdapName = null;
    private Vector v = new Vector();

    /**
     * Constructs string vector mapper.
     */
    public StringVectorMapper(String ldapName) {
        mLdapName = ldapName;
        v.addElement(mLdapName);
    }

    /**
     * Retrieves a list of supported ldap attributes.
     */
    public Enumeration getSupportedLDAPAttributeNames() {
        return v.elements();
    }

    /**
     * Maps attribute value to ldap attributes.
     */
    public void mapObjectToLDAPAttributeSet(IDBObj parent, 
        String name, Object obj, LDAPAttributeSet attrs) 
        throws EBaseException {
        Vector v = (Vector) obj;
        int s = v.size();

        if (s == 0) {
            return;
        }
        String m[] = new String[s];

        for (int i = 0; i < s; i++) {
            m[i] = (String) v.elementAt(i);
        }
        attrs.add(new LDAPAttribute(mLdapName, m));
    }

    /**
     * Maps LDAP attributes into object, and put the object
     * into 'parent'.
     */
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs, 
        String name, IDBObj parent) throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(mLdapName);

        if (attr == null)
            return;
        Enumeration e = attr.getStringValues();
        Vector v = new Vector();

        while (e.hasMoreElements()) {
            v.addElement((String) e.nextElement());
        }
        if (v.size() == 0)
            return;
        String m[] = new String[v.size()];

        v.copyInto(m);
        parent.set(name, m);
    }

    /**
     * Maps search filters into LDAP search filter.
     */
    public String mapSearchFilter(String name, String op, 
        String value) throws EBaseException {
        return mLdapName + op + value;
    }
}
