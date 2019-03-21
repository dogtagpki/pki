package com.netscape.cmscore.app;

import java.util.Date;
import java.util.Enumeration;

import com.netscape.certsrv.apps.ICMSEngine;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;

/**
 * Default engine stub for testing.
 */
public class CMSEngineDefaultStub implements ICMSEngine {
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

    public void reinit(String id) throws EBaseException {
    }

    public int getCSState() {
        return 0;
    }

    public void setCSState(int mode) {
    }

    public Date getCurrentDate() {
        return null;
    }

    public Enumeration<String> getSubsystemNames() {
        return null;
    }

    public Enumeration<ISubsystem> getSubsystems() {
        return null;
    }

    public void setSubsystemEnabled(String id, boolean enabled) {
    };

    public ISubsystem getSubsystem(String name) {
        return null;
    }

    public void debug(byte data[]) {
    }

    public void debug(String msg) {
    }

    public void debug(int level, String msg) {
    }

    public void debug(Throwable e) {
    }

    public boolean debugOn() {
        return false;
    }

    public void debugStackTrace() {
    }

    public void disableRequests() {
    }

    public void terminateRequests() {
    }

    public boolean areRequestsDisabled() {
        return false;
    }

    public IConfigStore createFileConfigStore(String path) throws EBaseException {
        return null;
    }

    @Override
    public void sleepOneMinute() {
    }

    @Override
    public boolean isExcludedLdapAttrsEnabled() {
        return true;
    }

    @Override
    public boolean isExcludedLdapAttr(String key) {
        return false;
    }
}
