package com.netscape.certsrv.key;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;


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

        KeyInfo afterJSON = JSONSerializer.fromJSON(json, KeyInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
