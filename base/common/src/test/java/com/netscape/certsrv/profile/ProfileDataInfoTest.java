package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileDataInfoTest {

    private static ProfileDataInfo before = new ProfileDataInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setProfileDescription("foo");
        before.setProfileId("bar");
        before.setProfileName("lorem");
        before.setProfileURL("https://www.example.com");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileDataInfo afterXML = ProfileDataInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileDataInfo afterJSON = JSONSerializer.fromJSON(json, ProfileDataInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
