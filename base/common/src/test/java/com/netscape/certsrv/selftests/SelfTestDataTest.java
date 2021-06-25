package com.netscape.certsrv.selftests;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SelfTestDataTest {

    private static SelfTestData before = new SelfTestData();

    @Before
    public void setUpBefore() {
        before.setID("selftest1");
        before.setEnabledOnDemand(true);
        before.setCriticalOnDemand(false);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SelfTestData afterJSON = JSONSerializer.fromJSON(json, SelfTestData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
