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

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class represents ann attribute mapper that maps
 * a Java object into LDAP attribute,
 * and vice versa.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class ObjectStreamMapper implements IDBAttrMapper {

    private String mLdapName = null;
    private Vector<String> v = new Vector<String>();
    private ILogger mLogger = CMS.getLogger();

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
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return v.elements();
    }

    /**
     * Maps object to ldap attribute set.
     */
    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs)
            throws EBaseException {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(bos);

            os.writeObject(obj);
            byte data[] = bos.toByteArray();
            if (data == null) {
                CMS.debug("ObjectStreamMapper:mapObjectToLDAPAttributeSet " +
                        name + " size=0");
            } else {
                CMS.debug("ObjectStreamMapper:mapObjectToLDAPAttributeSet " +
                        name + " size=" + data.length);
            }
            attrs.add(new LDAPAttribute(mLdapName, data));
        } catch (IOException e) {

            /*LogDoc
             *
             * @phase Maps object to ldap attribute set
             * @message ObjectStreamMapper: <exception thrown>
             */
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_DBS_OBJECTSTREAM_MAPPER_ERROR",
                            e.toString()));
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
    }

    /**
     * Maps LDAP attributes into object, and put the object
     * into 'parent'.
     */
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException {
        try {
            LDAPAttribute attr = attrs.getAttribute(mLdapName);

            if (attr == null) {
                return;
            }
            ByteArrayInputStream bis = new ByteArrayInputStream(
                    (byte[]) attr.getByteValues().nextElement());
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
    public String mapSearchFilter(String name, String op,
            String value) throws EBaseException {
        return mLdapName + op + value;
    }
}
