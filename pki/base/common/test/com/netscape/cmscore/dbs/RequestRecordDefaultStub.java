package com.netscape.cmscore.dbs;

import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;

import java.util.Enumeration;

/**
 * Default stub for RequestRecord tests.
 */
public class RequestRecordDefaultStub implements IRequestRecord, IDBObj {
    public RequestId getRequestId() {
        return null;
    }

    public Enumeration getAttrNames() {
        return null;
    }

    public Object get(String name) {
        return null;
    }

    public void set(String name, Object o) {
    }

    public void delete(String name) throws EBaseException {
    }

    public Enumeration getElements() {
        return null;
    }

    public Enumeration getSerializableAttrNames() {
        return null;
    }
}
