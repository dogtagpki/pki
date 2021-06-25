package org.dogtagpki.common;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KRAInfoTest {

    private static KRAInfo before = new KRAInfo();

    @Before
    public void setUpBefore() {
        before.setArchivalMechanism("encrypt");
        before.setRecoveryMechanism("keywrap");
        before.setEncryptAlgorithm("AES/CBC/Pad");
        before.setWrapAlgorithm("AES KeyWrap/Padding");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        KRAInfo afterXML = KRAInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KRAInfo afterJSON = JSONSerializer.fromJSON(json, KRAInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
