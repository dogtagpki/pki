package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AsymKeyGenerationRequestTest {

    private static AsymKeyGenerationRequest before = new AsymKeyGenerationRequest();

    @BeforeAll
    public static void setUpBefore() {
        before.setKeyAlgorithm(KeyRequestResource.RSA_ALGORITHM);
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
        System.out.println("JSON (before): " + json);

        AsymKeyGenerationRequest afterJSON = JSONSerializer.fromJSON(json, AsymKeyGenerationRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
