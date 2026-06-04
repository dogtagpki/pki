package org.dogtagpki.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class InfoTest {

    public static Logger logger = LoggerFactory.getLogger(InfoTest.class);

    private static Info before = new Info();

    @BeforeAll
    public static void setUpBefore() {
        before.setName("PKI");
        before.setVersion("10.8.0");
        before.setBanner(
                "WARNING!\n" +
                "Access to this service is restricted to those individuals with " +
                "specific permissions.");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        Info afterJSON = JSONSerializer.fromJSON(json, Info.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
