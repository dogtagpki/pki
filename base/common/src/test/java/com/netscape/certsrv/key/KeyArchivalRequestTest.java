package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyArchivalRequestTest {

    public static Logger logger = LoggerFactory.getLogger(KeyArchivalRequestTest.class);

    private static KeyArchivalRequest before = new KeyArchivalRequest();

    @BeforeAll
    public static void setUpBefore() {
        before.setClientKeyId("vek 12345");
        before.setDataType(KeyParameters.SYMMETRIC_KEY_TYPE);
        before.setWrappedPrivateData("XXXXABCDEFXXX");
        before.setKeyAlgorithm(KeyParameters.AES_ALGORITHM);
        before.setRealm("ipa-vault");
        before.setKeySize(128);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        KeyArchivalRequest afterJSON = JSONSerializer.fromJSON(json, KeyArchivalRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
