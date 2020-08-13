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
package com.netscape.cmscore.request;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.BigIntegerMapper;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A mapper between an request id object and
 * its LDAP attribute representation
 * <P>
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
public class RequestIdMapper implements IDBAttrMapper {

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_ID);
    }

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    public void mapObjectToLDAPAttributeSet(
            IDBObj parent,
            String name,
            Object obj,
            LDAPAttributeSet attrs)
            throws EBaseException {

        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }

        RequestId rid = (RequestId) obj;
        String v = BigIntegerMapper.BigIntegerToDB(new BigInteger(rid.toString()));
        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_ID, v));
    }

    public void mapLDAPAttributeSetToObject(
            LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {

        LDAPAttribute attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_ID);

        if (attr == null) {
            throw new EBaseException("schema violation");
        }

        String value = attr.getStringValues().nextElement();
        parent.set(name, new RequestId(BigIntegerMapper.BigIntegerFromDB(value).toString()));
    }

    public String mapSearchFilter(String name, String op, String value) throws EBaseException {
        String v;

        try {
            v = BigIntegerMapper.BigIntegerToDB(new BigInteger(value));
        } catch (NumberFormatException e) {
            v = value;
        }

        return Schema.LDAP_ATTR_REQUEST_ID + op + v;
    }
}
