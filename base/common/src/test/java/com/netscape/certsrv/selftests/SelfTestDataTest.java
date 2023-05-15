package com.netscape.certsrv.selftests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SelfTestDataTest {

    private static SelfTestData before = new SelfTestData();

    @BeforeAll
    public static void setUpBefore() {
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
        assertEquals(before, afterJSON);
    }

}
