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

import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;

/**
 * A class represents ann attribute mapper that maps
 * a Java String object into LDAP attribute,
 * and vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class StringMapper implements IDBAttrMapper {

    private String mLdapName = null;
    private Vector<String> v = new Vector<String>();

    /**
     * Constructs string mapper.
     */
    public StringMapper(String ldapName) {
        mLdapName = ldapName;
        v.addElement(mLdapName);
    }

    /**
     * Retrieves a list of supported ldap attributes.
     */
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return v.elements();
    }

    /**
     * Maps attribute value to ldap attributes.
     */
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs)
            throws EBaseException {
        attrs.add(new LDAPAttribute(mLdapName, (String) obj));
    }

    /**
     * Maps LDAP attributes into object, and put the object
     * into 'parent'.
     */
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(mLdapName);

        if (attr == null) {
            return;
        }
        try {
            parent.set(name, attr.getStringValues().nextElement());
        } catch (NoSuchElementException e) {
            // attribute present, but without value
        }
    }

    /**
     * Maps search filters into LDAP search filter.
     */
    public String mapSearchFilter(String name, String op,
            String value) throws EBaseException {
        return mLdapName + op + value;
    }
}
