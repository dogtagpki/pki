package com.netscape.certsrv.selftests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class SelfTestDataTest {

    public static Logger logger = LoggerFactory.getLogger(SelfTestDataTest.class);

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
        logger.debug("JSON (before): " + json);

        SelfTestData afterJSON = JSONSerializer.fromJSON(json, SelfTestData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
