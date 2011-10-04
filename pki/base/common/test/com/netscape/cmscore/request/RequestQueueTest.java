package com.netscape.cmscore.request;

import junit.framework.Test;
import junit.framework.TestSuite;
import com.netscape.cmscore.test.CMSBaseTestCase;
import com.netscape.certsrv.base.EBaseException;

import java.util.Enumeration;
import java.util.Arrays;
import java.util.Collections;

public class RequestQueueTest extends CMSBaseTestCase {
    RequestStub request;
    RequestQueue queue;

    public RequestQueueTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        request = new RequestStub();
        try {
            queue = new RequestQueue("", 1, null, null, null, null);
        } catch (EBaseException e) {
            e.printStackTrace();
        }
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(RequestQueueTest.class);
    }

    public void testAddRequest() throws EBaseException {
        assertFalse(request.getExtDataKeysCalled);
        queue.addRequest(request);
        assertTrue(request.getExtDataKeysCalled);
    }

    class RequestStub extends RequestDefaultStub {
        String[] keys = new String[] {"key1", "key2"};
        boolean getExtDataKeysCalled = false;

        public Enumeration getExtDataKeys() {
            getExtDataKeysCalled = true;
            return Collections.enumeration(Arrays.asList(keys));
        }

        public boolean isSimpleExtDataValue(String key) {
            return true;
        }

        public String getExtDataInString(String key) {
            return "";
        }
    }
}
