package com.netscape.certsrv.tps.profile;

import static org.junit.Assert.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileMappingDataTest {

    private static ProfileMappingData before = new ProfileMappingData();
    private static Map<String, String> properties = new LinkedHashMap<>();


    @Before
    public void setUpBefore() {
        before.setID("profileMapping1");
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

        ProfileMappingData afterJSON = JSONSerializer.fromJSON(json, ProfileMappingData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
