package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyDataTest {

    public static Logger logger = LoggerFactory.getLogger(KeyDataTest.class);

    private static KeyData before = new KeyData();

    @BeforeAll
    public static void setUpBefore() {
        before.setAlgorithm("AES");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        KeyData afterJSON = JSONSerializer.fromJSON(json, KeyData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
