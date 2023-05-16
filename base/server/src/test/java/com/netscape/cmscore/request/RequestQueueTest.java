package com.netscape.cmscore.request;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.test.CMSBaseTestHelper;

public class RequestQueueTest {
    static RequestStub request;
    static RequestRepository requestRepository;
    static RequestQueue queue;

    @BeforeAll
    public static void cmsTestSetUp() throws Exception {

        request = new RequestStub();
        CMSBaseTestHelper.setUp();
        requestRepository = new RequestRepository(null, CMSBaseTestHelper.getDbSubsystem(), null);
        requestRepository.init(null);

        queue = new RequestQueue(
                CMSBaseTestHelper.getDbSubsystem(),
                requestRepository,
                null,
                null,
                null,
                null);
    }

    @Test
    public void testAddRequest() throws EBaseException {
        assertFalse(request.getExtDataKeysCalled);
        requestRepository.addRequest(request);
        assertTrue(request.getExtDataKeysCalled);
    }

    static class RequestStub extends RequestDefaultStub {

        String[] keys = new String[] { "key1", "key2" };
        boolean getExtDataKeysCalled = false;

        @Override
        public Enumeration<String> getExtDataKeys() {
            getExtDataKeysCalled = true;
            return Collections.enumeration(Arrays.asList(keys));
        }

        @Override
        public boolean isSimpleExtDataValue(String key) {
            return true;
        }

        @Override
        public String getExtDataInString(String key) {
            return "";
        }
    }
}
