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
package com.netscape.certsrv.dbs;

import java.util.Enumeration;

import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.base.EBaseException;

/**
 * An interface represents an attribute mapper. A mapper has knowledge on how to
 * convert a db attribute into zero or more LDAP attribute, and vice versa.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IDBAttrMapper {

    /**
     * Retrieves a list of LDAP attributes that are used in the mapper. By
     * having this, the framework can provide search on selective attributes.
     * 
     * @return a list of supported attribute names
     */
    public Enumeration getSupportedLDAPAttributeNames();

    /**
     * Maps object attribute into LDAP attributes.
     * 
     * @param parent parent object where the object comes from
     * @param name name of db attribute
     * @param obj object itself
     * @param attrs LDAP attribute set where the result should be stored
     * @exception EBaseException failed to map object
     */
    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs) throws EBaseException;

    /**
     * Maps LDAP attributes into object, and puts the object into 'parent'.
     * 
     * @param attrs LDAP attribute set
     * @param name name of db attribute to be processed
     * @param parent parent object where the object should be added
     * @exception EBaseException failed to map object
     */
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException;

    /**
     * Maps search filters into LDAP search filter.
     * 
     * @param name name of db attribute
     * @param op filte operation (i.e. "=", ">=")
     * @param value attribute value
     * @exception EBaseException failed to map filter
     */
    public String mapSearchFilter(String name, String op, String value)
            throws EBaseException;
}
