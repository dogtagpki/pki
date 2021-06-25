package com.netscape.certsrv.dbs.keydb;

import org.junit.Assert;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyIdTest {

    private static KeyId before = new KeyId("0x6");

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyId afterJSON = JSONSerializer.fromJSON(json, KeyId.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
