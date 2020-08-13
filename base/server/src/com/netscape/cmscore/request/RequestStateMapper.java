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

import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A mapper between an request state object and
 * its LDAP attribute representation
 * <P>
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
public class RequestStateMapper implements IDBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestStateMapper.class);

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_STATE);
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

        RequestStatus rs = (RequestStatus) obj;
        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_STATE, rs.toString()));
    }

    public void mapLDAPAttributeSetToObject(
            LDAPAttributeSet attrs,
            String name,
            IDBObj parent)
            throws EBaseException {

        LDAPAttribute attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_STATE);

        if (attr == null) {
            throw new EBaseException("schema violation");
        }

        String value = attr.getStringValues().nextElement();
        parent.set(name, RequestStatus.fromString(value));
    }

    public String mapSearchFilter(String name, String op, String value) {
        return Schema.LDAP_ATTR_REQUEST_STATE + op + value;
    }
}
