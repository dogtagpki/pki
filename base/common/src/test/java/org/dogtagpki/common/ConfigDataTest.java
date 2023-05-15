package org.dogtagpki.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ConfigDataTest {

    private static ConfigData before = new ConfigData();
    private static Map<String, String> properties = new TreeMap<>();

    @BeforeAll
    public static void setUpBefore() {
        properties.put("param1", "value1");
        properties.put("param2", "value2");

        before.setProperties(properties);
        before.setStatus("ENABLED");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ConfigData afterJSON = JSONSerializer.fromJSON(json, ConfigData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
