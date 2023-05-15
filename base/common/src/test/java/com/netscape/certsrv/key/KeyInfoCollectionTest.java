package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyInfoCollectionTest {

    private static KeyInfoCollection before = new KeyInfoCollection();
    private static KeyInfo key1 = new KeyInfo();
    private static KeyInfo key2 = new KeyInfo();

    @BeforeAll
    public static void setUpBefore() {
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

        KeyInfoCollection afterJSON = JSONSerializer.fromJSON(json, KeyInfoCollection.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
