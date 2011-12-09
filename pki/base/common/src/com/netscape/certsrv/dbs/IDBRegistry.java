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


import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
 

/**
 * A class represents a registry where all the
 * schema (object classes and attribute) information 
 * is stored.
 *
 * Attribute mappers can be registered with this
 * registry.
 *
 * Given the schema information stored, this registry
 * has knowledge to convert a Java object into a
 * LDAPAttributeSet or vice versa.
 *
 * @version $Revision$, $Date$ 
 */
public interface IDBRegistry extends ISubsystem {

    /**
     * Registers object class.
     *
     * @param className java class to create for the object classes
     * @param ldapNames a list of LDAP object classes
     * @exception EDBException failed to register
     */
    public void registerObjectClass(String className, String ldapNames[])
        throws EDBException;

    /**
     * See if an object class is registered.
     *
     * @param className java class to create
     * @return true if object class is registered already
     */
    public boolean isObjectClassRegistered(String className);

    /**
     * Registers attribute mapper.
     *
     * @param ufName LDAP attribute name
     * @param mapper mapper to invoke for the attribute
     * @exception EDBException failed to register
     */
    public void registerAttribute(String ufName, IDBAttrMapper mapper) 
        throws EDBException;

    /**
     * See if an attribute is registered.
     *
     * @param ufName attribute name
     * @return true if attribute is registered already
     */
    public boolean isAttributeRegistered(String ufName);

    /**
     * Registers a dynamic attribute mapper.
     * @param mapper The dynamic mapper to register
     */
    public void registerDynamicMapper(IDBDynAttrMapper mapper);

    /**
     * Creates LDAP-based search filters with help of
     * registered mappers.
     * Parses filter from filter string specified in RFC1558.
     * <pre>
     * <filter> ::= '(' <filtercomp> ')'
     * <filtercomp> ::= <and> | <or> | <not> | <item>
     * <and> ::= '&' <filterlist>
     * <or> ::= '|' <filterlist>
     * <not> ::= '!' <filter>
     * <filterlist> ::= <filter> | <filter> <filterlist>
     * <item> ::= <simple> | <present> | <substring>
     * <simple> ::= <attr> <filtertype> <value>
     * <filtertype> ::= <equal> | <approx> | <greater> | <less>
     * <equal> ::= '='
     * <approx> ::= '~='
     * <greater> ::= '>='
     * <less> ::= '<='
     * <present> ::= <attr> '=*'
     * <substring> ::= <attr> '=' <initial> <any> <final>
     * <initial> ::= NULL | <value>
     * <any> ::= '*' <starval>
     * <starval> ::= NULL | <value> '*' <starval>
     * <final> ::= NULL | <value>
     * </pre>
     *
     * @param filter CMS-based filter
     * @return LDAP-based filter string
     * @exception EBaseException failed to convert filter
     */
    public String getFilter(String filter) throws EBaseException;

    /**
     * Creates LDAP-based search filters with help of
     * registered mappers.
     *
     * @param filter CMS-based filter
     * @param c filter converter
     * @return LDAP-based filter string
     * @exception EBaseException failed to convert filter
     */
    public String getFilter(String filter, IFilterConverter c) 
        throws EBaseException;

    /**
     * Maps object into LDAP attribute set.
     *
     * @param parent object's parent
     * @param name name of the object
     * @param obj object to be mapped
     * @param attrs LDAP attribute set
     * @exception EBaseException failed to map object
     */
    public void mapObject(IDBObj parent, String name, Object obj, 
        LDAPAttributeSet attrs) throws EBaseException;

    /**
     * Retrieves a list of LDAP attributes that are associated
     * with the given attributes.
     *
     * @param attrs attributes
     * @return LDAP-based attributes
     * @exception EBaseException failed to map attributes
     */
    public String[] getLDAPAttributes(String attrs[]) 
        throws EBaseException;

    /**
     * Creates attribute set from object.
     *
     * @param obj database object
     * @return LDAP attribute set
     * @exception EBaseException failed to create set
     */
    public LDAPAttributeSet createLDAPAttributeSet(IDBObj obj) 
        throws EBaseException;

    /**
     * Creates object from attribute set.
     *
     * @param attrs LDAP attribute set
     * @return database object
     * @exception EBaseException failed to create object
     */
    public IDBObj createObject(LDAPAttributeSet attrs)
        throws EBaseException;
}
