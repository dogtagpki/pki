package org.dogtagpki.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class KRAInfoTest {

    public static Logger logger = LoggerFactory.getLogger(KRAInfoTest.class);

    private static KRAInfo before = new KRAInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setArchivalMechanism("encrypt");
        before.setRecoveryMechanism("keywrap");
        before.setEncryptAlgorithm("AES/CBC/Pad");
        before.setWrapAlgorithm("AES KeyWrap/Padding");
        before.setRsaPublicKeyWrapAlgorithm("RSA");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        KRAInfo afterJSON = JSONSerializer.fromJSON(json, KRAInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
