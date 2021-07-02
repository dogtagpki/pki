package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SymKeyGenerationRequestTest {

    private static SymKeyGenerationRequest before = new SymKeyGenerationRequest();

    @Before
    public void setUpBefore() {
        before.setClientKeyId("vek 12345");
        before.setKeyAlgorithm(KeyRequestResource.AES_ALGORITHM);
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
        System.out.println("JSON (before): " + json);

        SymKeyGenerationRequest afterJSON =
                JSONSerializer.fromJSON(json, SymKeyGenerationRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
