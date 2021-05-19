package com.netscape.cmscore.dbs;

import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.request.RequestRecord;

/**
 * Default stub for RequestRecord tests.
 */
public class RequestRecordDefaultStub extends RequestRecord {

    @Override
    public RequestId getRequestId() {
        return null;
    }

    @Override
    public Enumeration<String> getAttrNames() {
        return null;
    }

    @Override
    public Object get(String name) {
        return null;
    }

    @Override
    public void set(String name, Object o) {
    }

    @Override
    public void delete(String name) throws EBaseException {
    }

    @Override
    public Enumeration<String> getElements() {
        return null;
    }

    @Override
    public Enumeration<String> getSerializableAttrNames() {
        return null;
    }
}
