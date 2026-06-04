package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class SymKeyGenerationRequestTest {

    public static Logger logger = LoggerFactory.getLogger(SymKeyGenerationRequestTest.class);

    private static SymKeyGenerationRequest before = new SymKeyGenerationRequest();

    @BeforeAll
    public static void setUpBefore() {
        before.setClientKeyId("vek 12345");
        before.setKeyAlgorithm(KeyParameters.AES_ALGORITHM);
        before.setKeySize(128);
        before.addUsage(SymKeyGenerationRequest.DECRYPT_USAGE);
        before.addUsage(SymKeyGenerationRequest.ENCRYPT_USAGE);
        before.addUsage(SymKeyGenerationRequest.SIGN_USAGE);
        before.setRealm("ipa");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        SymKeyGenerationRequest afterJSON =
                JSONSerializer.fromJSON(json, SymKeyGenerationRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
