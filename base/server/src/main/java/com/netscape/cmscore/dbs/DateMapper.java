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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A class represents ann attribute mapper that maps
 * a Java Date object into LDAP attribute,
 * and vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class DateMapper extends DBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DateMapper.class);

    private String mLdapName = null;
    private Vector<String> v = new Vector<>();
    private static SimpleDateFormat formatter = new
            SimpleDateFormat("yyyyMMddHHmmss'Z'");

    /**
     * Constructs date mapper.
     */
    public DateMapper(String ldapName) {
        mLdapName = ldapName;
        v.addElement(mLdapName);
    }

    /**
     * Retrieves a list of ldap attribute names.
     */
    @Override
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return v.elements();
    }

    /**
     * Maps object to ldap attribute set.
     */
    @Override
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs)
            throws EBaseException {

        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }

        logger.debug("DateMapper: Mapping " + name + " to " + mLdapName);

        Date value = (Date) obj;
        logger.debug("DateMapper: - value: " + value);

        String dbValue = dateToDB(value);
        logger.debug("DateMapper: - database value: " + dbValue);

        attrs.add(new LDAPAttribute(mLdapName, dbValue));
    }

    /**
     * Maps LDAP attributes into object, and put the object
     * into 'parent'.
     */
    @Override
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(mLdapName);

        if (attr == null)
            return;

        logger.debug("DateMapper: Mapping " + mLdapName + " to " + name);

        String dbValue = attr.getStringValues().nextElement();
        logger.debug("DateMapper: - database value: " + dbValue);

        Date value = dateFromDB(dbValue);
        logger.debug("DateMapper: - value: " + value);

        parent.set(name, value);
    }

    /**
     * Maps search filters into LDAP search filter.
     */
    @Override
    public String mapSearchFilter(String name, String op,
            String value) throws EBaseException {
        String val = null;

        try {
            val = dateToDB(new Date(Long.parseLong(value)));
        } catch (NumberFormatException e) {
            val = value;
        }
        return mLdapName + op + val;
    }

    public synchronized static String dateToDB(Date date) {
        return formatter.format(date);
    }

    public synchronized static Date dateFromDB(String dbDate) {
        try {
            return formatter.parse(dbDate);
        } catch (ParseException e) {
        }
        return null;
    }
}
