package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class KeyInfoCollectionTest {

    public static Logger logger = LoggerFactory.getLogger(KeyInfoCollectionTest.class);

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
        logger.debug("JSON (before): " + json);

        KeyInfoCollection afterJSON = JSONSerializer.fromJSON(json, KeyInfoCollection.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
