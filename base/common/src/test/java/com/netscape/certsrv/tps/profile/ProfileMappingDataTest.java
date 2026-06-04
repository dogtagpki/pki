package com.netscape.certsrv.tps.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileMappingDataTest {

    public static Logger logger = LoggerFactory.getLogger(ProfileMappingDataTest.class);

    private static ProfileMappingData before = new ProfileMappingData();
    private static Map<String, String> properties = new LinkedHashMap<>();


    @BeforeAll
    public static void setUpBefore() {
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
        logger.debug("JSON (before): " + json);

        ProfileMappingData afterJSON = JSONSerializer.fromJSON(json, ProfileMappingData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
