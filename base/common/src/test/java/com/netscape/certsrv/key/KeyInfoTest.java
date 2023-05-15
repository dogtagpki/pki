package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyInfoTest {

    private static KeyInfo before = new KeyInfo();

    @BeforeAll
    public static void setUpBefore() {
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
