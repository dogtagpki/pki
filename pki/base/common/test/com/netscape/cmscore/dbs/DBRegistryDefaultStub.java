package com.netscape.cmscore.dbs;

import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBDynAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IFilterConverter;

/**
 * A default stub ojbect for tests to extend.
 */
public class DBRegistryDefaultStub implements IDBRegistry {

    public void registerObjectClass(String className, String ldapNames[]) throws EDBException {
    }

    public boolean isObjectClassRegistered(String className) {
        return false;
    }

    public void registerAttribute(String ufName, IDBAttrMapper mapper) throws EDBException {
    }

    public boolean isAttributeRegistered(String ufName) {
        return false;
    }

    public void registerDynamicMapper(IDBDynAttrMapper mapper) {
    }

    public String getFilter(String filter) throws EBaseException {
        return null;
    }

    public String getFilter(String filter, IFilterConverter c) throws EBaseException {
        return null;
    }

    public void mapObject(IDBObj parent, String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
    }

    public String[] getLDAPAttributes(String attrs[]) throws EBaseException {
        return new String[0];
    }

    public LDAPAttributeSet createLDAPAttributeSet(IDBObj obj) throws EBaseException {
        return null;
    }

    public IDBObj createObject(LDAPAttributeSet attrs) throws EBaseException {
        return null;
    }

    public String getId() {
        return null;
    }

    public void setId(String id) throws EBaseException {
    }

    public void init(ISubsystem owner, IConfigStore config) throws EBaseException {
    }

    public void startup() throws EBaseException {
    }

    public void shutdown() {
    }

    public IConfigStore getConfigStore() {
        return null;
    }
}
