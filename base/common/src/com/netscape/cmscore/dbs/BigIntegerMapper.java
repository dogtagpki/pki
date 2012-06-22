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

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;

/**
 * A class represents ann attribute mapper that maps
 * a Java BigInteger object into LDAP attribute,
 * and vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class BigIntegerMapper implements IDBAttrMapper {

    private String mLdapName = null;
    private Vector<String> v = new Vector<String>();

    /**
     * Constructs BigInteger mapper.
     */
    public BigIntegerMapper(String ldapName) {
        mLdapName = ldapName;
        v.addElement(mLdapName);
    }

    /**
     * Returns a list of supported ldap attribute names.
     */
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return v.elements();
    }

    /**
     * Maps object into ldap attribute set.
     */
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs)
            throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        attrs.add(new LDAPAttribute(mLdapName,
                BigIntegerToDB((BigInteger) obj)));
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
        parent.set(name, BigIntegerFromDB(
                (String) attr.getStringValues().nextElement()));
    }

    /**
     * Maps search filters into LDAP search filter.
     */
    public String mapSearchFilter(String name, String op,
            String value) throws EBaseException {
        String v = null;

        try {
            if (value.startsWith("0x") || value.startsWith("0X")) {
                v = BigIntegerToDB(new
                            BigInteger(value.substring(2), 16));
            } else {
                v = BigIntegerToDB(new BigInteger(value));
            }
        } catch (NumberFormatException e) {
            v = value;
        }
        return mLdapName + op + v;
    }

    public static String BigIntegerToDB(BigInteger i) {
        int len = i.toString().length();
        String ret = null;

        if (len < 10) {
            ret = "0" + Integer.toString(len) + i.toString();
        } else {
            ret = Integer.toString(len) + i.toString();
        }
        return ret;
    }

    public static BigInteger BigIntegerFromDB(String i) {
        String s = i.substring(2);

        // possibly check length
        return new BigInteger(s);
    }
}
