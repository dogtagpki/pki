package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyInfoTest {

    public static Logger logger = LoggerFactory.getLogger(KeyInfoTest.class);

    private static KeyInfo before = new KeyInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setClientKeyID("key");
        before.setStatus("active");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        KeyInfo afterJSON = JSONSerializer.fromJSON(json, KeyInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
