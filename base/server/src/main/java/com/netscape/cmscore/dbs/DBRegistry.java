package com.netscape.cmscore.dbs;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.dbs.FilterConverter;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.DBDynAttrMapper;

import netscape.ldap.LDAPAttributeSet;

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
 */
public class DBRegistry {

    /**
     * Registers object class.
     *
     * @param className java class to create for the object classes
     * @param ldapNames a list of LDAP object classes
     * @exception DBException failed to register
     */
    public void registerObjectClass(
            String className,
            String[] ldapNames
            ) throws DBException {
    }

    /**
     * See if an object class is registered.
     *
     * @param className java class to create
     * @return true if object class is registered already
     */
    public boolean isObjectClassRegistered(String className) {
        return false;
    }

    /**
     * Registers attribute mapper.
     *
     * @param ufName LDAP attribute name
     * @param mapper mapper to invoke for the attribute
     * @exception DBException failed to register
     */
    public void registerAttribute(String ufName, DBAttrMapper mapper) throws DBException {
    }

    /**
     * See if an attribute is registered.
     *
     * @param ufName attribute name
     * @return true if attribute is registered already
     */
    public boolean isAttributeRegistered(String ufName) {
        return false;
    }

    /**
     * Registers a dynamic attribute mapper.
     *
     * @param mapper The dynamic mapper to register
     */
    public void registerDynamicMapper(DBDynAttrMapper mapper) {
    }

    /**
     * Creates LDAP-based search filters with help of
     * registered mappers.
     * Parses filter from filter string specified in RFC1558.
     *
     * <pre>{@Code
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
     * }</pre>
     *
     * @param filter CMS-based filter
     * @return LDAP-based filter string
     * @exception EBaseException failed to convert filter
     */
    public String getFilter(String filter) throws EBaseException {
        return null;
    }

    /**
     * Creates LDAP-based search filters with help of
     * registered mappers.
     *
     * @param filter CMS-based filter
     * @param c filter converter
     * @return LDAP-based filter string
     * @exception EBaseException failed to convert filter
     */
    public String getFilter(String filter, FilterConverter c) throws EBaseException {
        return null;
    }

    /**
     * Maps object into LDAP attribute set.
     *
     * @param parent object's parent
     * @param name name of the object
     * @param obj object to be mapped
     * @param attrs LDAP attribute set
     * @exception EBaseException failed to map object
     */
    public void mapObject(IDBObj parent, String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
    }

    /**
     * Retrieves a list of LDAP attributes that are associated
     * with the given attributes.
     *
     * @param attrs attributes
     * @return LDAP-based attributes
     * @exception EBaseException failed to map attributes
     */
    public String[] getLDAPAttributes(String[] attrs) throws EBaseException {
        return new String[0];
    }

    /**
     * Creates attribute set from object.
     *
     * @param obj database object
     * @return LDAP attribute set
     * @exception EBaseException failed to create set
     */
    public LDAPAttributeSet createLDAPAttributeSet(IDBObj obj) throws EBaseException {
        return null;
    }

    /**
     * Creates object from attribute set.
     *
     * @param attrs LDAP attribute set
     * @return database object
     * @exception EBaseException failed to create object
     */
    public IDBObj createObject(LDAPAttributeSet attrs) throws EBaseException {
        return null;
    }

    public String getId() {
        return null;
    }

    public void setId(String id) throws EBaseException {
    }

    public void init(ConfigStore config) throws EBaseException {
    }

    public void startup() throws EBaseException {
    }

    public void shutdown() {
    }

    public ConfigStore getConfigStore() {
        return null;
    }
}
