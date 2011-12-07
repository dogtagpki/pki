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
package com.netscape.certsrv.request;

import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;

/**
 * A request record is the stored version of a request. It has a set of
 * attributes that are mapped into LDAP attributes for actual directory
 * operations.
 * <p>
 * 
 * @version $Revision$ $Date$
 */
public interface IRequestRecord extends IDBObj {
    //
    // The names of the attributes stored in this record
    //

    // RequestId - identifies the record
    public final static String ATTR_REQUEST_ID = "requestId";

    // RequestStatus - indicates the current state
    public final static String ATTR_REQUEST_STATE = "requestState";

    // CreateTime - indicates the current state
    public final static String ATTR_CREATE_TIME = "requestCreateTime";

    // ModifyTime - indicates the current state
    public final static String ATTR_MODIFY_TIME = "requestModifyTime";

    // SourceId - indicates the current state
    public final static String ATTR_SOURCE_ID = "requestSourceId";

    // SourceId - indicates the current state
    public final static String ATTR_REQUEST_OWNER = "requestOwner";

    public final static String ATTR_REQUEST_TYPE = "requestType";

    // Placeholder for ExtAttr data. this attribute is not in LDAP, but
    // is used to trigger the ExtAttrDynMapper during conversion between LDAP
    // and the RequestRecord.
    public final static String ATTR_EXT_DATA = "requestExtData";

    /**
     * Gets the request id.
     * 
     * @return request id
     */
    public RequestId getRequestId();

    /**
     * Gets attribute names of the request.
     * 
     * @return list of attribute names
     */
    public Enumeration getAttrNames();

    /**
     * Gets the request attribute value by the name.
     * 
     * @param name attribute name
     * @return attribute value
     */
    public Object get(String name);

    /**
     * Sets new attribute for the request.
     * 
     * @param name attribute name
     * @param o attribute value
     */
    public void set(String name, Object o);

    /**
     * Removes attribute from the request.
     * 
     * @param name attribute name
     */
    public void delete(String name) throws EBaseException;

    /**
     * Gets attribute list of the request.
     * 
     * @return attribute list
     */
    public Enumeration getElements();

    // IDBObj.getSerializableAttrNames
    // public Enumeration getSerializableAttrNames();

}
