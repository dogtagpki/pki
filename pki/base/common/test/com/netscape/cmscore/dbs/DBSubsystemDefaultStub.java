package com.netscape.cmscore.dbs;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSubsystem;
import netscape.ldap.LDAPConnection;

import java.math.BigInteger;

/**
 * A default stub ojbect for tests to extend.
 */
public class DBSubsystemDefaultStub implements IDBSubsystem {


    public String getBaseDN() {
        return null;
    }

    public IDBRegistry getRegistry() {
        return null;
    }

    public IDBSSession createSession() throws EDBException {
        return null;
    }

    public boolean enableSerialNumberRecovery() {
        return false;
    }

    public void setNextSerialConfig(BigInteger serial) throws EBaseException {
    }

    public BigInteger getNextSerialConfig() {
        return null;
    }

    public void setMaxSerialConfig(String serial) throws EBaseException {
    }

    public String getMinSerialConfig() {
        return null;
    }

    public String getMaxSerialConfig() {
        return null;
    }

    public String getMinRequestConfig() {
        return null;
    }

    public String getMaxRequestConfig() {
        return null;
    }

    public void returnConn(LDAPConnection conn) {
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
