package com.netscape.certsrv.request;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class RequestIdTest {

    public static Logger logger = LoggerFactory.getLogger(RequestIdTest.class);

    private static RequestId before = new RequestId("1");

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        RequestId afterJSON = JSONSerializer.fromJSON(json, RequestId.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
