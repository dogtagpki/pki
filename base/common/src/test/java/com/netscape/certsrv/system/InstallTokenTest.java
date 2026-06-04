package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class InstallTokenTest {

    public static Logger logger = LoggerFactory.getLogger(InstallTokenTest.class);

    private static InstallToken before = new InstallToken();

    @BeforeAll
    public static void setUpBefore() {
        before.setToken("foo");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        InstallToken afterJSON = JSONSerializer.fromJSON(json, InstallToken.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
