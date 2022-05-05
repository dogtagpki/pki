package com.netscape.certsrv.key;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;


public class KeyArchivalRequestTest {

    private static KeyArchivalRequest before = new KeyArchivalRequest();

    @Before
    public void setUpBefore() {
        before.setClientKeyId("vek 12345");
        before.setDataType(KeyRequestResource.SYMMETRIC_KEY_TYPE);
        before.setWrappedPrivateData("XXXXABCDEFXXX");
        before.setKeyAlgorithm(KeyRequestResource.AES_ALGORITHM);
        before.setRealm("ipa-vault");
        before.setKeySize(128);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyArchivalRequest afterJSON = JSONSerializer.fromJSON(json, KeyArchivalRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
