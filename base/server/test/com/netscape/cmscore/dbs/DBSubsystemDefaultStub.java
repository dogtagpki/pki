package com.netscape.cmscore.dbs;

import java.math.BigInteger;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSubsystem;

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

    public IDBSSession createSession() {
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

    @Override
    public void setMaxSerialConfig(int repo, String serial)
            throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public void setMinSerialConfig(int repo, String serial)
            throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public void setNextMaxSerialConfig(int repo, String serial)
            throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public void setNextMinSerialConfig(int repo, String serial)
            throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public String getMinSerialConfig(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getMaxSerialConfig(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getNextMaxSerialConfig(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getNextMinSerialConfig(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getLowWaterMarkConfig(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getIncrementConfig(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getNextRange(int repo) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean hasRangeConflict(int repo) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean getEnableSerialMgmt() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void setEnableSerialMgmt(boolean value) throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public IConfigStore getDBConfigStore() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getEntryAttribute(String dn, String attrName,
                                    String defaultValue, String errorValue) {
        // TODO Auto-generated method stub
        return null;
    }
}
