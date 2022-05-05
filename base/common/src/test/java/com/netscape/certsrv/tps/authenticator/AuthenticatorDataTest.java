package com.netscape.certsrv.tps.authenticator;

import static org.junit.Assert.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

public class AuthenticatorDataTest {

    private static AuthenticatorData before = new AuthenticatorData();
    private static Map<String, String> properties = new LinkedHashMap<>();


    @Before
    public void setUpBefore() {
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
        System.out.println("JSON (before): " + json);

        AuthenticatorData afterJSON = AuthenticatorData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
