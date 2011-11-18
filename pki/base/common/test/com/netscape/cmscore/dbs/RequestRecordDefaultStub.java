package com.netscape.cmscore.dbs;

import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.RequestId;

/**
 * Default stub for RequestRecord tests.
 */
public class RequestRecordDefaultStub implements IRequestRecord, IDBObj {
    /**
     *
     */
    private static final long serialVersionUID = 3486144284074519531L;

    public RequestId getRequestId() {
        return null;
    }

    public Enumeration<String> getAttrNames() {
        return null;
    }

    public Object get(String name) {
        return null;
    }

    public void set(String name, Object o) {
    }

    public void delete(String name) throws EBaseException {
    }

    public Enumeration<String> getElements() {
        return null;
    }

    public Enumeration<String> getSerializableAttrNames() {
        return null;
    }
}
