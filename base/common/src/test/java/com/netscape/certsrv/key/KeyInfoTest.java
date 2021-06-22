package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class KeyInfoTest {

    private static KeyInfo before = new KeyInfo();

    @Before
    public void setUpBefore() {
        before.setClientKeyID("key");
        before.setStatus("active");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyInfo afterJSON = KeyInfo.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
