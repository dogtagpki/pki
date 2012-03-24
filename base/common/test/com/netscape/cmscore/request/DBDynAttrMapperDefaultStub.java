package com.netscape.cmscore.request;

import java.util.Enumeration;

import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBDynAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;

/**
 * Default testing stub for the IRequest interface.
 */
public class DBDynAttrMapperDefaultStub implements IDBDynAttrMapper {
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
