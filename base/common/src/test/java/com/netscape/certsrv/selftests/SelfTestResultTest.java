package com.netscape.certsrv.selftests;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SelfTestResultTest {

    private static SelfTestResult before = new SelfTestResult();

    @Before
    public void setUpBefore() {
        before.setID("selftest1");
        before.setStatus("PASSED");
        before.setOutput(null);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SelfTestResult afterJSON = JSONSerializer.fromJSON(json, SelfTestResult.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
