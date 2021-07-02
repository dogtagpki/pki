package com.netscape.certsrv.tps.profile;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileDataTest {

    private static ProfileData before = new ProfileData();
    private static Map<String, String> properties = new LinkedHashMap<>();

    @Before
    public void setUpBefore() {
        before.setID("profile1");
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

        ProfileData afterJSON = JSONSerializer.fromJSON(json, ProfileData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
