package com.netscape.cmscore.request;

import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;

import netscape.ldap.LDAPAttributeSet;

/**
 * A class representing a dynamic attribute mapper.
 * A dynamic mapper has knowledge on how to convert a set of dynamically
 * assigned db attribute into zero or more dynamically assigned LDAP
 * attributes, and vice versa.
 */
public class DBDynAttrMapper extends DBAttrMapper {

    /**
     * Returns true if the LDAP attribute can be mapped by this
     * dynamic mapper.
     *
     * @param attrName LDAP attribute name to check
     * @return a list of supported attribute names
     */
    public boolean supportsLDAPAttributeName(String attrName) {
        return false;
    }

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return null;
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name, Object obj, LDAPAttributeSet attrs)
            throws EBaseException {
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs, String name, IDBObj parent) throws EBaseException {
    }

    public String mapSearchFilter(String name, String op, String value) throws EBaseException {
        return null;
    }
}
