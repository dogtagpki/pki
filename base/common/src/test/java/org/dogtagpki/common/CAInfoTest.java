package org.dogtagpki.common;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;


public class CAInfoTest {

    private static CAInfo before = new CAInfo();

    @Before
    public void setUpBefore() {
        before.setArchivalMechanism(CAInfo.KEYWRAP_MECHANISM);
        before.setEncryptAlgorithm(CAInfo.ENCRYPT_MECHANISM);
        before.setKeyWrapAlgorithm(CAInfo.KEYWRAP_MECHANISM);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CAInfo afterXML = CAInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CAInfo afterJSON = JSONSerializer.fromJSON(json, CAInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }
}
