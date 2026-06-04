package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class TPSConnectorDataTest {

    public static Logger logger = LoggerFactory.getLogger(TPSConnectorDataTest.class);

    private static TPSConnectorData before = new TPSConnectorData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("tps0");
        before.setUserID("user1");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        TPSConnectorData afterJSON = JSONSerializer.fromJSON(json, TPSConnectorData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
