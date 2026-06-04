package com.netscape.certsrv.selftests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class SelfTestResultTest {

    public static Logger logger = LoggerFactory.getLogger(SelfTestResultTest.class);

    private static SelfTestResult before = new SelfTestResult();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("selftest1");
        before.setStatus("PASSED");
        before.setOutput(null);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        SelfTestResult afterJSON = JSONSerializer.fromJSON(json, SelfTestResult.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
