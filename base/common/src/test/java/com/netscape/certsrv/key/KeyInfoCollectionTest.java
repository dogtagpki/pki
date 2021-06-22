package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class KeyInfoCollectionTest {

    private static KeyInfoCollection before = new KeyInfoCollection();
    private static KeyInfo key1 = new KeyInfo();
    private static KeyInfo key2 = new KeyInfo();

    @Before
    public void setUpBefore() {
        key1.setClientKeyID("key1");
        key1.setStatus("active");
        before.addEntry(key1);

        key2.setClientKeyID("key2");
        key2.setStatus("active");
        before.addEntry(key2);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyInfoCollection afterJSON = KeyInfoCollection.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
