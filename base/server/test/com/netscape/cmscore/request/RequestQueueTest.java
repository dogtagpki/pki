package com.netscape.cmscore.request;

import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.test.CMSBaseTestCase;

import junit.framework.Test;
import junit.framework.TestSuite;

public class RequestQueueTest extends CMSBaseTestCase {
    RequestStub request;
    RequestRepository requestRepository;
    RequestQueue queue;

    public RequestQueueTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() throws Exception {

        request = new RequestStub();

        requestRepository = new RequestRepository(dbSubsystem, null);

        queue = new RequestQueue(
                dbSubsystem,
                requestRepository,
                null,
                null,
                null,
                null);
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(RequestQueueTest.class);
    }

    public void testAddRequest() throws EBaseException {
        assertFalse(request.getExtDataKeysCalled);
        requestRepository.addRequest(request);
        assertTrue(request.getExtDataKeysCalled);
    }

    static class RequestStub extends RequestDefaultStub {
        private static final long serialVersionUID = -9058189963961484835L;

        String[] keys = new String[] { "key1", "key2" };
        boolean getExtDataKeysCalled = false;

        public Enumeration<String> getExtDataKeys() {
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
