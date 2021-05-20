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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A class represents ann attribute mapper that maps
 * a Java object into LDAP attribute,
 * and vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class ObjectStreamMapper extends DBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ObjectStreamMapper.class);
    private String mLdapName = null;
    private Vector<String> v = new Vector<>();

    /**
     * Constructs object stream mapper.
     */
    public ObjectStreamMapper(String ldapName) {
        mLdapName = ldapName;
        v.addElement(mLdapName);
    }

    /**
     * Retrieves a list of supported ldap attributes.
     */
    @Override
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return v.elements();
    }

    /**
     * Maps object to ldap attribute set.
     */
    @Override
    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs)
            throws EBaseException {

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(bos);

            os.writeObject(obj);
            byte[] data = bos.toByteArray();

            logger.debug("ObjectStreamMapper: Mapping " + name + " to " + mLdapName);
            attrs.add(new LDAPAttribute(mLdapName, data));

        } catch (IOException e) {

            /*LogDoc
             *
             * @phase Maps object to ldap attribute set
             * @message ObjectStreamMapper: <exception thrown>
             */
            logger.error(CMS.getLogMessage("CMSCORE_DBS_OBJECTSTREAM_MAPPER_ERROR", e.toString()), e);
            throw new EDBException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name), e);
        }
    }

    /**
     * Maps LDAP attributes into object, and put the object
     * into 'parent'.
     */
    @Override
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException {
        try {
            LDAPAttribute attr = attrs.getAttribute(mLdapName);

            if (attr == null) {
                return;
            }
            ByteArrayInputStream bis = new ByteArrayInputStream(
                    attr.getByteValues().nextElement());
            ObjectInputStream is = new ObjectInputStream(bis);

            parent.set(name, is.readObject());
        } catch (IOException e) {
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_DESERIALIZE_FAILED", name));
        } catch (ClassNotFoundException e) {
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_DESERIALIZE_FAILED", name));
        }
    }

    /**
     * Maps search filters into LDAP search filter.
     */
    @Override
    public String mapSearchFilter(String name, String op,
            String value) throws EBaseException {
        return mLdapName + op + value;
    }
}
