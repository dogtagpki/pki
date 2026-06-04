package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class AsymKeyGenerationRequestTest {

    public static Logger logger = LoggerFactory.getLogger(AsymKeyGenerationRequestTest.class);

    private static AsymKeyGenerationRequest before = new AsymKeyGenerationRequest();

    @BeforeAll
    public static void setUpBefore() {
        before.setKeyAlgorithm(KeyParameters.RSA_ALGORITHM);
        before.setKeySize(1024);
        before.setClientKeyId("vek12345");
        List<String> usages = new ArrayList<>();
        usages.add(AsymKeyGenerationRequest.ENCRYPT);
        usages.add(AsymKeyGenerationRequest.DECRYPT);
        before.setUsages(usages);
        before.setRealm("ipa-vault");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        AsymKeyGenerationRequest afterJSON = JSONSerializer.fromJSON(json, AsymKeyGenerationRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
