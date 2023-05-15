package com.netscape.certsrv.tps.connector;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ConnectorDataTest {

    private static ConnectorData before = new ConnectorData();
    private static Map<String, String> properties = new LinkedHashMap<>();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("connector1");
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

        ConnectorData afterJSON = JSONSerializer.fromJSON(json, ConnectorData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
