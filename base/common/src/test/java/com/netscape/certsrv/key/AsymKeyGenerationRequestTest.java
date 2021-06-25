package com.netscape.certsrv.key;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AsymKeyGenerationRequestTest {

    private static AsymKeyGenerationRequest before = new AsymKeyGenerationRequest();

    @Before
    public void setUpBefore() {
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
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        AsymKeyGenerationRequest afterXML = AsymKeyGenerationRequest.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AsymKeyGenerationRequest afterJSON = JSONSerializer.fromJSON(json, AsymKeyGenerationRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
