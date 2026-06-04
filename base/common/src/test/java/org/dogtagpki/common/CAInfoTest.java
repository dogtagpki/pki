package org.dogtagpki.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;


public class CAInfoTest {

    public static Logger logger = LoggerFactory.getLogger(CAInfoTest.class);

    private static CAInfo before = new CAInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setArchivalMechanism(CAInfo.KEYWRAP_MECHANISM);
        before.setEncryptAlgorithm(CAInfo.ENCRYPT_MECHANISM);
        before.setKeyWrapAlgorithm(CAInfo.KEYWRAP_MECHANISM);
        before.setRsaPublicKeyWrapAlgorithm(CAInfo.RSA_PUBLIC_KEY_WRAP);
        before.setCaRsaPublicKeyWrapAlgorithm(CAInfo.RSA_PUBLIC_KEY_WRAP);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CAInfo afterJSON = JSONSerializer.fromJSON(json, CAInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }
}
