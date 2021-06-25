package com.netscape.certsrv.key;

import org.junit.Assert;
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
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        KeyArchivalRequest afterXML = KeyArchivalRequest.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyArchivalRequest afterJSON = JSONSerializer.fromJSON(json, KeyArchivalRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
