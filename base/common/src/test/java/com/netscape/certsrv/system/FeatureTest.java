package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class FeatureTest {

    public static Logger logger = LoggerFactory.getLogger(FeatureTest.class);

    private static Feature before = new Feature();

    @BeforeAll
    public static void setUpBefore() {
        before.setId("authority");
        before.setEnabled(true);
        before.setDescription("Subordinate CA Feature");
        before.setVersion("1.0");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        Feature afterJSON = JSONSerializer.fromJSON(json, Feature.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
