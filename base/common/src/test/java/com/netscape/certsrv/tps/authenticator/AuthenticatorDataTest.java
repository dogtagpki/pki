package com.netscape.certsrv.tps.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class AuthenticatorDataTest {

    public static Logger logger = LoggerFactory.getLogger(AuthenticatorDataTest.class);

    private static AuthenticatorData before = new AuthenticatorData();
    private static Map<String, String> properties = new LinkedHashMap<>();


    @BeforeAll
    public static void setUpBefore() {
        before.setID("authenticator1");
        before.setStatus("ENABLED");

        properties.put("param1", "value1");
        properties.put("param2", "value2");
        before.setProperties(properties);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        AuthenticatorData afterJSON = JSONSerializer.fromJSON(json, AuthenticatorData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
