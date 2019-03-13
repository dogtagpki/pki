package com.netscape.cmscore.app;

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import com.netscape.certsrv.apps.ICMSEngine;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
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

    public void traceHashKey(String type, String key) {
    }

    public void traceHashKey(String type, String key, String val) {
    }

    public void traceHashKey(String type, String key, String val, String def) {
    }

    public String getUserMessage(Locale locale, String msgID) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p[]) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p1) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p1, String p2) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p1, String p2, String p3) {
        return null;
    }

    public String getLogMessage(String msgID, Object p[]) {
        return null;
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

    public IArgBlock createArgBlock() {
        return null;
    }

    @Override
    public IArgBlock createArgBlock(String realm,
            Hashtable<String, String> httpReq) {
        return null;
    }

    @Override
    public IArgBlock createArgBlock(Hashtable<String, String> httpReq) {
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
