package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyTest {

    private static Key before = new Key();

    @Before
    public void setUpBefore() {
       before.setAlgorithm("AES");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        Key afterXML = Key.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Key afterJSON = JSONSerializer.fromJSON(json, Key.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
